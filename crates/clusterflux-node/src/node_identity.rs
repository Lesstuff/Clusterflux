use std::path::{Path, PathBuf};

use clusterflux_core::{
    generate_ed25519_private_key, node_ed25519_public_key_from_private_key,
    sign_node_assignment_request, sign_node_request, signed_request_payload_digest,
    AssignmentAuthority, NodeId,
};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::coordinator_session::CoordinatorSession;
use crate::daemon::Args;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct StoredNodeCredential {
    kind: String,
    node: String,
    private_key: String,
    public_key: String,
    credential_scope: String,
}

pub(crate) fn establish_node_identity(
    session: &mut CoordinatorSession,
    args: &Args,
    node_private_key: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let derived_public_key =
        node_ed25519_public_key_from_private_key(node_private_key).map_err(invalid_key_error)?;
    let public_key = args
        .public_key
        .clone()
        .unwrap_or(derived_public_key.clone());
    if public_key != derived_public_key {
        return Err(
            "node --public-key must match CLUSTERFLUX_NODE_PRIVATE_KEY or the stored local node credential"
                .into(),
        );
    }
    if let Some(grant) = &args.enrollment_grant {
        let response = session.request(CoordinatorRequest::ExchangeNodeEnrollmentGrant {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            node: args.node.clone(),
            public_key,
            enrollment_grant: grant.clone(),
        })?;
        match response {
            response @ CoordinatorResponse::NodeEnrollmentExchanged { .. } => {
                Ok(serde_json::to_value(response)?)
            }
            _ => Err("coordinator returned an unexpected enrollment-exchange response".into()),
        }
    } else {
        Ok(json!({
            "type": "node_identity_reused",
            "node": &args.node,
            "credential_source": "stored_project_node_identity",
            "subsequent_authentication": "signed_node_requests",
        }))
    }
}

pub(crate) fn validate_node_identity_configuration(
    args: &Args,
    node_private_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let derived_public_key =
        node_ed25519_public_key_from_private_key(node_private_key).map_err(invalid_key_error)?;
    if args
        .public_key
        .as_ref()
        .is_some_and(|public_key| public_key != &derived_public_key)
    {
        return Err(
            "node --public-key must match CLUSTERFLUX_NODE_PRIVATE_KEY or the stored local node credential"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn node_private_key_for_runtime(
    project_root: Option<&Path>,
    node: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    match std::env::var("CLUSTERFLUX_NODE_PRIVATE_KEY") {
        Ok(private_key) => {
            node_ed25519_public_key_from_private_key(&private_key).map_err(invalid_key_error)?;
            return Ok(private_key);
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err("CLUSTERFLUX_NODE_PRIVATE_KEY must contain valid Unicode".into());
        }
    }
    let current_directory;
    let project_root = match project_root {
        Some(project_root) => project_root,
        None => {
            current_directory = std::env::current_dir()?;
            &current_directory
        }
    };
    load_or_create_local_node_credential(project_root, node)
}

pub(crate) fn load_or_create_local_node_credential(
    project: &Path,
    node: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let file = local_node_credential_file(project, node);
    if credential_file_exists_without_symlink(&file)? {
        let bytes = std::fs::read(&file)?;
        let credential: StoredNodeCredential = serde_json::from_slice(&bytes)?;
        if credential.node != node {
            return Err(format!(
                "stored node credential {} belongs to node `{}` instead of `{}`",
                file.display(),
                credential.node,
                node
            )
            .into());
        }
        let public_key = node_ed25519_public_key_from_private_key(&credential.private_key)
            .map_err(invalid_key_error)?;
        if public_key != credential.public_key {
            return Err(format!(
                "stored node credential {} has a public key that does not match its private key",
                file.display()
            )
            .into());
        }
        return Ok(credential.private_key);
    }

    let private_key = generate_ed25519_private_key().map_err(invalid_key_error)?;
    let public_key =
        node_ed25519_public_key_from_private_key(&private_key).map_err(invalid_key_error)?;
    let credential = StoredNodeCredential {
        kind: "clusterflux_node_credential".to_owned(),
        node: node.to_owned(),
        private_key: private_key.clone(),
        public_key,
        credential_scope: "local_project_node_identity".to_owned(),
    };
    persist_node_credential(&file, &credential)?;
    Ok(private_key)
}

fn credential_file_exists_without_symlink(file: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    match std::fs::symlink_metadata(file) {
        Ok(metadata) if metadata.file_type().is_symlink() => Err(format!(
            "refusing to read node credential through symbolic link {}",
            file.display()
        )
        .into()),
        Ok(metadata) if !metadata.is_file() => Err(format!(
            "node credential path {} is not a regular file",
            file.display()
        )
        .into()),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn persist_node_credential(
    file: &Path,
    credential: &StoredNodeCredential,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;

    let parent = file
        .parent()
        .ok_or_else(|| format!("node credential path {} has no parent", file.display()))?;
    std::fs::create_dir_all(parent)?;
    if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
        return Err(format!(
            "refusing to store node credential through symbolic-link directory {}",
            parent.display()
        )
        .into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    temporary.write_all(&serde_json::to_vec_pretty(credential)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(file).map_err(|error| {
        format!(
            "refusing to overwrite node credential {}: {}",
            file.display(),
            error.error
        )
    })?;
    Ok(())
}

pub(crate) fn local_node_credential_file(project: &Path, node: &str) -> PathBuf {
    let digest = clusterflux_core::Digest::sha256(node);
    let file_stem = digest.as_str().trim_start_matches("sha256:");
    project
        .join(".clusterflux-state")
        .join("nodes")
        .join(format!("{file_stem}.json"))
}

pub(crate) fn node_nonce(prefix: &str) -> String {
    format!("{prefix}-{}-{}", unix_timestamp_nanos(), std::process::id())
}

pub(crate) fn unix_timestamp_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub(crate) fn signed_node_request(
    args: &Args,
    node_private_key: &str,
    request_kind: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorRequest, Box<dyn std::error::Error>> {
    let payload_digest = signed_request_payload_digest(&serde_json::to_value(&request)?);
    let node_signature = sign_node_request(
        node_private_key,
        &NodeId::from(args.node.as_str()),
        request_kind,
        &payload_digest,
        node_nonce(request_kind),
        unix_timestamp_seconds(),
    )
    .map_err(invalid_key_error)?;
    Ok(CoordinatorRequest::SignedNode {
        node: args.node.clone(),
        node_signature,
        request: Box::new(request),
    })
}

pub(crate) fn signed_node_assignment_request(
    args: &Args,
    node_private_key: &str,
    authority: &AssignmentAuthority,
    request_kind: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorRequest, Box<dyn std::error::Error>> {
    let payload_digest = signed_request_payload_digest(&serde_json::to_value(&request)?);
    let node_signature = sign_node_assignment_request(
        node_private_key,
        &NodeId::from(args.node.as_str()),
        request_kind,
        &payload_digest,
        node_nonce(request_kind),
        unix_timestamp_seconds(),
        authority.clone(),
    )
    .map_err(invalid_key_error)?;
    Ok(CoordinatorRequest::SignedNode {
        node: args.node.clone(),
        node_signature,
        request: Box::new(request),
    })
}

fn invalid_key_error(error: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, error)
}

pub(crate) fn unix_timestamp_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0)
}
