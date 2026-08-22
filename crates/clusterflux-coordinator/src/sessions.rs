use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{Actor, AuthContext, CredentialKind, Digest, ProjectId, TenantId, UserId};

use crate::{CliSessionRecord, Coordinator, CoordinatorError, CredentialRecord};

impl Coordinator {
    pub fn issue_cli_session(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        user: UserId,
        session_secret: &str,
        expires_at_epoch_seconds: Option<u64>,
    ) -> CliSessionRecord {
        self.upsert_tenant(tenant.clone());
        self.upsert_user(
            tenant.clone(),
            user.clone(),
            CredentialKind::CliDeviceSession,
        );
        let session_digest = Digest::sha256(session_secret);
        let record = CliSessionRecord {
            session_digest: session_digest.clone(),
            tenant: tenant.clone(),
            project: project.clone(),
            user: user.clone(),
            credential_kind: CredentialKind::CliDeviceSession,
            expires_at_epoch_seconds,
            revoked: false,
        };
        self.durable
            .cli_sessions
            .insert(session_digest.clone(), record.clone());
        let credential_subject = format!("cli-session:{}", session_digest.as_str());
        self.durable.credentials.insert(
            credential_subject.clone(),
            CredentialRecord {
                subject: credential_subject,
                tenant,
                project: Some(project),
                kind: CredentialKind::CliDeviceSession,
                public_key_fingerprint: None,
            },
        );
        record
    }

    pub fn authenticate_cli_session(
        &self,
        session_secret: &str,
    ) -> Result<AuthContext, CoordinatorError> {
        self.authenticate_cli_session_at_with_tenant_policy(
            session_secret,
            unix_timestamp_seconds(),
            true,
        )
    }

    pub fn authenticate_cli_session_for_status(
        &self,
        session_secret: &str,
    ) -> Result<AuthContext, CoordinatorError> {
        self.authenticate_cli_session_at_with_tenant_policy(
            session_secret,
            unix_timestamp_seconds(),
            false,
        )
    }

    pub fn authenticate_cli_session_at(
        &self,
        session_secret: &str,
        now_epoch_seconds: u64,
    ) -> Result<AuthContext, CoordinatorError> {
        self.authenticate_cli_session_at_with_tenant_policy(session_secret, now_epoch_seconds, true)
    }

    fn authenticate_cli_session_at_with_tenant_policy(
        &self,
        session_secret: &str,
        now_epoch_seconds: u64,
        require_active_tenant: bool,
    ) -> Result<AuthContext, CoordinatorError> {
        if session_secret.trim().is_empty() {
            return Err(CoordinatorError::Unauthorized(
                "CLI session credential is missing".to_owned(),
            ));
        }
        let session_digest = Digest::sha256(session_secret);
        let record = self
            .durable
            .cli_sessions
            .get(&session_digest)
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "CLI session credential is not recognized".to_owned(),
                )
            })?;
        if record.revoked {
            return Err(CoordinatorError::Unauthorized(
                "CLI session credential has been revoked".to_owned(),
            ));
        }
        if record
            .expires_at_epoch_seconds
            .is_some_and(|expires_at| expires_at <= now_epoch_seconds)
        {
            return Err(CoordinatorError::Unauthorized(
                "CLI session credential has expired; run clusterflux login --browser again"
                    .to_owned(),
            ));
        }
        if record.credential_kind != CredentialKind::CliDeviceSession {
            return Err(CoordinatorError::Unauthorized(
                "credential is not a CLI session".to_owned(),
            ));
        }
        if require_active_tenant {
            self.ensure_tenant_active(&record.tenant)?;
        }
        Ok(AuthContext {
            tenant: record.tenant.clone(),
            project: record.project.clone(),
            actor: Actor::User(record.user.clone()),
        })
    }

    pub fn revoke_cli_session(
        &mut self,
        session_secret: &str,
    ) -> Result<CliSessionRecord, CoordinatorError> {
        self.authenticate_cli_session(session_secret)?;
        let session_digest = Digest::sha256(session_secret);
        let record = self
            .durable
            .cli_sessions
            .get_mut(&session_digest)
            .expect("authenticated session must exist");
        record.revoked = true;
        Ok(record.clone())
    }
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::InMemoryDurableStore;

    use super::*;

    #[test]
    fn repeated_logins_for_one_user_create_distinct_session_credentials() {
        let store = InMemoryDurableStore::default();
        let mut coordinator = Coordinator::boot(&store, 1);
        let tenant = TenantId::from("tenant");
        let user = UserId::from("user");

        coordinator.issue_cli_session(
            tenant.clone(),
            ProjectId::from("project-one"),
            user.clone(),
            "session-one",
            None,
        );
        coordinator.issue_cli_session(
            tenant,
            ProjectId::from("project-two"),
            user,
            "session-two",
            None,
        );

        let subjects = coordinator
            .durable
            .credentials
            .values()
            .map(|credential| credential.subject.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(coordinator.durable.cli_sessions.len(), 2);
        assert_eq!(subjects.len(), 2);
        assert!(subjects
            .iter()
            .all(|subject| subject.starts_with("cli-session:sha256:")));
    }
}
