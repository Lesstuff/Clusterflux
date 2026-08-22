use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{
    admin_request_proof_from_token_digest, CredentialKind, Digest, TenantId, UserId,
};

use crate::CoordinatorError;

use super::{CoordinatorResponse, CoordinatorService, CoordinatorServiceError};

const ADMIN_REQUEST_MAX_CLOCK_SKEW_SECONDS: u64 = 300;

impl CoordinatorService {
    pub(super) fn handle_admin_status(
        &mut self,
        tenant: String,
        actor_user: String,
        admin_proof: Digest,
        admin_nonce: String,
        issued_at_epoch_seconds: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.verify_admin_request(
            "admin_status",
            &tenant,
            &actor_user,
            &tenant,
            &admin_proof,
            &admin_nonce,
            issued_at_epoch_seconds,
        )?;
        let tenant = TenantId::new(tenant);
        let actor = UserId::new(actor_user);
        Ok(CoordinatorResponse::AdminStatus {
            suspended: self.coordinator.tenant_suspended(&tenant),
            tenant,
            actor,
            safe_default: "read_only".to_owned(),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_suspend_tenant(
        &mut self,
        tenant: String,
        actor_user: String,
        target_tenant: String,
        admin_proof: Digest,
        admin_nonce: String,
        issued_at_epoch_seconds: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.verify_admin_request(
            "suspend_tenant",
            &tenant,
            &actor_user,
            &target_tenant,
            &admin_proof,
            &admin_nonce,
            issued_at_epoch_seconds,
        )?;
        let actor_tenant = TenantId::new(tenant);
        let actor = UserId::new(actor_user);
        let target_tenant = TenantId::new(target_tenant);
        self.coordinator.upsert_tenant(actor_tenant.clone());
        self.coordinator.upsert_user(
            actor_tenant,
            actor.clone(),
            CredentialKind::CliDeviceSession,
        );
        let policy = self
            .coordinator
            .suspend_tenant(target_tenant.clone(), actor.clone());
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::TenantSuspended {
            tenant: target_tenant,
            actor,
            policy,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_admin_request(
        &mut self,
        operation: &str,
        tenant: &str,
        actor_user: &str,
        target_tenant: &str,
        admin_proof: &Digest,
        admin_nonce: &str,
        issued_at_epoch_seconds: u64,
    ) -> Result<(), CoordinatorServiceError> {
        let expected = self.admin_token_digest.as_ref().ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "self-hosted admin credential is not configured".to_owned(),
            )
        })?;
        if admin_nonce.trim().is_empty() || admin_nonce.len() > 256 {
            return Err(CoordinatorError::Unauthorized(
                "admin request nonce is missing or invalid".to_owned(),
            )
            .into());
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .unwrap_or_default();
        if now.abs_diff(issued_at_epoch_seconds) > ADMIN_REQUEST_MAX_CLOCK_SKEW_SECONDS {
            return Err(CoordinatorError::Unauthorized(
                "admin request timestamp is outside the allowed 300-second window".to_owned(),
            )
            .into());
        }
        let expected_proof = admin_request_proof_from_token_digest(
            expected,
            operation,
            tenant,
            actor_user,
            target_tenant,
            admin_nonce,
            issued_at_epoch_seconds,
        );
        if admin_proof != &expected_proof {
            return Err(CoordinatorError::Unauthorized(
                "admin request proof is invalid".to_owned(),
            )
            .into());
        }
        match self.replay_registry.admit_admin(
            admin_nonce.to_owned(),
            issued_at_epoch_seconds,
            now,
            ADMIN_REQUEST_MAX_CLOCK_SKEW_SECONDS,
            super::MAX_REPLAY_NONCES_PER_AUTHORITY,
        ) {
            Ok(()) => {}
            Err(super::ReplayAdmissionError::Duplicate) => {
                return Err(CoordinatorError::Unauthorized(
                    "admin request nonce was already used".to_owned(),
                )
                .into());
            }
            Err(super::ReplayAdmissionError::Capacity) => {
                return Err(CoordinatorError::Unauthorized(
                    "admin request replay window is full; retry after the bounded signature window advances"
                        .to_owned(),
                )
                .into());
            }
        }
        Ok(())
    }
}
