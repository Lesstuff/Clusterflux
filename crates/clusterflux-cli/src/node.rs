use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clusterflux_core::{
    generate_ed25519_private_key, node_ed25519_public_key_from_private_key, sign_node_request,
    signed_request_payload_digest, Capability, Digest, EnvironmentBackend, NodeCapabilities,
    NodeId,
};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde::Serialize;
use serde_json::{json, Value};

use crate::client::{authenticated_or_local_trusted_request, JsonLineSession};
use crate::config::{effective_scope_value, read_cli_session, StoredCliSession};
use crate::tools::{command_available, command_nonce, unix_timestamp_seconds};
use crate::{
    confirmation_required_report, AttachArgs, CliScopeArgs, NodeEnrollArgs, NodeListArgs,
    NodeRevokeArgs, NodeStatusArgs,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeAttachPlan {
    pub(crate) node: String,
    pub(crate) coordinator: Option<String>,
    pub(crate) capabilities: NodeCapabilities,
    pub(crate) detection: NodeAttachDetectionEvidence,
    pub(crate) grant_disclosures: Vec<CapabilityGrantDisclosure>,
    pub(crate) enrollment: Option<NodeEnrollmentPlan>,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct NodeAttachReport {
    pub(crate) command: String,
    pub(crate) node: String,
    pub(crate) plan: NodeAttachPlan,
    pub(crate) grant_disclosures: Vec<CapabilityGrantDisclosure>,
    pub(crate) boundary: NodeAttachBoundaryEvidence,
    pub(crate) coordinator_response: CoordinatorResponse,
    pub(crate) heartbeat_response: CoordinatorResponse,
    pub(crate) capability_response: CoordinatorResponse,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeAttachBoundaryEvidence {
    pub(crate) cli_contacted_coordinator: bool,
    pub(crate) coordinator_address: String,
    pub(crate) used_enrollment_exchange: bool,
    pub(crate) coordinator_session_requests: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct CapabilityGrantDisclosure {
    pub(crate) capability: Capability,
    pub(crate) grant: String,
    pub(crate) description: String,
    pub(crate) risk: String,
    pub(crate) coordinator_policy_limited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeAttachDetectionEvidence {
    pub(crate) auto_detected: bool,
    pub(crate) os: clusterflux_core::Os,
    pub(crate) arch: String,
    pub(crate) command_backend: String,
    pub(crate) command_backend_available: bool,
    pub(crate) container_backend: Option<String>,
    pub(crate) container_backend_reported: bool,
    pub(crate) container_backend_available: bool,
    pub(crate) source_provider_backends: Vec<SourceProviderBackendStatus>,
    pub(crate) manual_capability_overrides_allowed: bool,
    pub(crate) manual_capability_overrides: Vec<String>,
    pub(crate) recognized_capability_overrides: Vec<Capability>,
    pub(crate) unrecognized_capability_overrides: Vec<String>,
    pub(crate) os_arch_capabilities_require_manual_flags: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct SourceProviderBackendStatus {
    pub(crate) provider: String,
    pub(crate) detected: bool,
    pub(crate) available: bool,
    pub(crate) reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct NodeEnrollmentPlan {
    pub(crate) grant: String,
    pub(crate) public_key_fingerprint: Digest,
    pub(crate) exchanges_short_lived_grant_for_long_lived_node_identity: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct StoredNodeCredential {
    kind: String,
    node: String,
    private_key: String,
    public_key: String,
    credential_scope: String,
}

pub(crate) fn node_enroll_report(args: NodeEnrollArgs, cwd: PathBuf) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    if let Some(coordinator) = &coordinator {
        let tenant = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.tenant,
            |session| session.tenant.as_str(),
            "tenant",
        );
        let project = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.project,
            |session| session.project.as_str(),
            "project",
        );
        let user = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.user,
            |session| session.user.as_str(),
            "user",
        );
        let ttl_seconds = args.ttl_seconds;
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::CreateNodeEnrollmentGrant {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                ttl_seconds,
            },
        )?;
        let response = session.request(request)?;
        let enrollment_grant =
            node_enrollment_grant_summary(&response, &tenant, &project, &user, ttl_seconds)?;
        return Ok(json!({
            "command": "node enroll",
            "status": "created",
            "coordinator": coordinator,
            "tenant": tenant,
            "project": project,
            "user": user,
            "external_website_required": false,
            "enrollment_grant": enrollment_grant,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "node enroll",
        "status": "requires_coordinator",
        "external_website_required": false,
        "requested_ttl_seconds": args.ttl_seconds,
        "enrollment_grant": null,
        "reason": "enrollment grants are generated by the coordinator and cannot be planned client-side",
    }))
}

fn node_enrollment_grant_summary(
    response: &CoordinatorResponse,
    tenant: &str,
    project: &str,
    user: &str,
    ttl_seconds: u64,
) -> Result<Value> {
    let CoordinatorResponse::NodeEnrollmentGrantCreated {
        tenant: response_tenant,
        project: response_project,
        grant,
        scope,
        expires_at_epoch_seconds,
    } = response
    else {
        anyhow::bail!("coordinator returned an unexpected node-enrollment response");
    };
    if response_tenant.as_str() != tenant || response_project.as_str() != project {
        anyhow::bail!("coordinator enrollment grant scope does not match the request");
    }
    Ok(json!({
        "grant": grant,
        "tenant": response_tenant,
        "project": response_project,
        "user": user,
        "scope": scope,
        "ttl_seconds": ttl_seconds,
        "expires_at_epoch_seconds": expires_at_epoch_seconds,
        "short_lived": true,
        "exchange_for_persistent_node_identity": true,
        "node_credentials_separate_from_user_session": true,
    }))
}

pub(crate) fn node_list_report(args: NodeListArgs, cwd: PathBuf) -> Result<Value> {
    node_descriptors_report("node list", args.scope, None, cwd)
}

pub(crate) fn node_status_report(args: NodeStatusArgs, cwd: PathBuf) -> Result<Value> {
    node_descriptors_report("node status", args.scope, args.node, cwd)
}

fn node_descriptors_report(
    command: &str,
    scope: CliScopeArgs,
    node: Option<String>,
    cwd: PathBuf,
) -> Result<Value> {
    let stored_session = read_cli_session(&cwd)?;
    let coordinator = scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    if let Some(coordinator) = &coordinator {
        let tenant = session_or_effective_scope_value(
            stored_session.as_ref(),
            &scope.tenant,
            |session| session.tenant.as_str(),
            "tenant",
        );
        let project = session_or_effective_scope_value(
            stored_session.as_ref(),
            &scope.project,
            |session| session.project.as_str(),
            "project",
        );
        let user = session_or_effective_scope_value(
            stored_session.as_ref(),
            &scope.user,
            |session| session.user.as_str(),
            "user",
        );
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::ListNodeSummaries {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                cursor: None,
                limit: 100,
            },
        )?;
        let response = session.request(request)?;
        if !matches!(&response, CoordinatorResponse::NodeSummaries { .. }) {
            anyhow::bail!("coordinator returned an unexpected node-list response");
        }
        return Ok(json!({
            "command": command,
            "coordinator": coordinator,
            "node": node,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": command,
        "status": "local_capability_snapshot",
        "node": node.unwrap_or_else(default_node_id),
        "capabilities": NodeCapabilities::detect_current(),
    }))
}

pub(crate) fn node_revoke_report(args: NodeRevokeArgs, cwd: PathBuf) -> Result<Value> {
    if !args.yes {
        return Ok(confirmation_required_report(
            "node revoke",
            "revoke_node_credential",
            json!({
                "coordinator": args.scope.coordinator,
                "tenant": args.scope.tenant,
                "project": args.scope.project,
                "user": args.scope.user,
                "node": args.node,
            }),
            format!("clusterflux node revoke --node {} --yes", args.node),
        ));
    }
    let stored_session = read_cli_session(&cwd)?;
    let coordinator = args.scope.coordinator.clone().or_else(|| {
        stored_session
            .as_ref()
            .map(|session| session.coordinator.clone())
    });
    if let Some(coordinator) = &coordinator {
        let tenant = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.tenant,
            |session| session.tenant.as_str(),
            "tenant",
        );
        let project = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.project,
            |session| session.project.as_str(),
            "project",
        );
        let user = session_or_effective_scope_value(
            stored_session.as_ref(),
            &args.scope.user,
            |session| session.user.as_str(),
            "user",
        );
        let node = args.node.clone();
        let mut session = JsonLineSession::connect(coordinator)?;
        let request = authenticated_or_local_trusted_request(
            coordinator,
            stored_session.as_ref(),
            CoordinatorRequest::RevokeNodeCredential {
                tenant: tenant.clone(),
                project: project.clone(),
                actor_user: user.clone(),
                node: node.clone(),
            },
        )?;
        let response = session.request(request)?;
        let (descriptor_removed, queued_assignments_removed) = match &response {
            CoordinatorResponse::NodeCredentialRevoked {
                descriptor_removed,
                queued_assignments_removed,
                ..
            } => (*descriptor_removed, *queued_assignments_removed),
            _ => anyhow::bail!("coordinator returned an unexpected node-revoke response"),
        };
        return Ok(json!({
            "command": "node revoke",
            "coordinator": coordinator,
            "requires_confirmation": !args.yes,
            "tenant": tenant,
            "project": project,
            "user": user,
            "node": node,
            "credential_revoked": true,
            "descriptor_removed": descriptor_removed,
            "queued_assignments_removed": queued_assignments_removed,
            "node_credentials_separate_from_user_session": true,
            "response": serde_json::to_value(response)?,
            "coordinator_session_requests": session.requests(),
        }));
    }
    Ok(json!({
        "command": "node revoke",
        "status": "requires_coordinator",
        "requires_confirmation": !args.yes,
        "node": args.node,
    }))
}

fn session_or_effective_scope_value(
    stored_session: Option<&StoredCliSession>,
    cli_value: &str,
    session_value: impl FnOnce(&StoredCliSession) -> &str,
    default_value: &str,
) -> String {
    if let Some(session) = stored_session.filter(|session| session.session_secret.is_some()) {
        session_value(session).to_owned()
    } else {
        effective_scope_value(cli_value, stored_session.map(session_value), default_value)
    }
}

pub(crate) fn attach_plan(args: AttachArgs) -> NodeAttachPlan {
    let mut capabilities = NodeCapabilities::detect_current();
    let mut recognized_capability_overrides = Vec::new();
    let mut unrecognized_capability_overrides = Vec::new();
    for cap in &args.caps {
        if let Some(parsed) = parse_capability(cap) {
            recognized_capability_overrides.push(parsed.clone());
            capabilities.capabilities.insert(parsed);
        } else {
            unrecognized_capability_overrides.push(cap.clone());
        }
    }
    recognized_capability_overrides.sort();
    recognized_capability_overrides.dedup();
    let node = args.node.unwrap_or_else(default_node_id);
    let public_key = args
        .public_key
        .unwrap_or_else(|| default_node_public_key_for_plan(&node));
    let enrollment = args.enrollment_grant.map(|grant| NodeEnrollmentPlan {
        grant,
        public_key_fingerprint: Digest::sha256(public_key),
        exchanges_short_lived_grant_for_long_lived_node_identity: true,
    });
    let detection = node_attach_detection_evidence(
        &capabilities,
        args.caps,
        recognized_capability_overrides,
        unrecognized_capability_overrides,
    );
    let grant_disclosures = capability_grant_disclosures(&capabilities);

    NodeAttachPlan {
        node,
        coordinator: args.coordinator,
        capabilities,
        detection,
        grant_disclosures,
        enrollment,
    }
}

fn node_attach_detection_evidence(
    capabilities: &NodeCapabilities,
    manual_capability_overrides: Vec<String>,
    recognized_capability_overrides: Vec<Capability>,
    unrecognized_capability_overrides: Vec<String>,
) -> NodeAttachDetectionEvidence {
    let command_backend_available = capabilities.capabilities.contains(&Capability::Command);
    let container_backend_reported = capabilities
        .environment_backends
        .contains(&EnvironmentBackend::Container);
    let container_backend = container_backend_reported.then(|| "rootless-podman".to_owned());
    let container_backend_available = container_backend_reported
        && capabilities
            .capabilities
            .contains(&Capability::RootlessPodman)
        && command_available("podman");

    NodeAttachDetectionEvidence {
        auto_detected: true,
        os: capabilities.os.clone(),
        arch: capabilities.arch.clone(),
        command_backend: if command_backend_available {
            "native-command".to_owned()
        } else {
            "unavailable".to_owned()
        },
        command_backend_available,
        container_backend,
        container_backend_reported,
        container_backend_available,
        source_provider_backends: source_provider_backend_statuses(capabilities),
        manual_capability_overrides_allowed: true,
        manual_capability_overrides,
        recognized_capability_overrides,
        unrecognized_capability_overrides,
        os_arch_capabilities_require_manual_flags: false,
    }
}

fn source_provider_backend_statuses(
    capabilities: &NodeCapabilities,
) -> Vec<SourceProviderBackendStatus> {
    let mut statuses = BTreeMap::new();
    for provider in &capabilities.source_providers {
        let available = match provider.as_str() {
            "filesystem" => capabilities
                .capabilities
                .contains(&Capability::SourceFilesystem),
            "git" => command_available("git"),
            _ => true,
        };
        statuses.insert(
            provider.clone(),
            SourceProviderBackendStatus {
                provider: provider.clone(),
                detected: true,
                available,
                reason: if available {
                    "detected by local node capability probe".to_owned()
                } else {
                    format!(
                        "source provider `{provider}` was detected but its local helper is missing"
                    )
                },
            },
        );
    }
    statuses.into_values().collect()
}

fn capability_grant_disclosures(capabilities: &NodeCapabilities) -> Vec<CapabilityGrantDisclosure> {
    let mut disclosures = Vec::new();
    let mut push = |capability: Capability, grant: &str, description: &str, risk: &str| {
        if capabilities.capabilities.contains(&capability) {
            disclosures.push(CapabilityGrantDisclosure {
                capability,
                grant: grant.to_owned(),
                description: description.to_owned(),
                risk: risk.to_owned(),
                coordinator_policy_limited: true,
            });
        }
    };

    push(
        Capability::Command,
        "native_command_execution",
        "placed tasks may run native commands on this node",
        "local process execution under the node account",
    );
    push(
        Capability::WindowsCommandDev,
        "native_command_execution",
        "placed tasks may run Windows developer commands on this node",
        "local process execution under the node account",
    );
    push(
        Capability::SourceFilesystem,
        "source_access",
        "placed tasks may read the local project/source checkout exposed by this node",
        "broad local source visibility",
    );
    push(
        Capability::SourceGit,
        "source_access",
        "placed tasks may use Git-backed source access exposed by this node",
        "source-provider visibility",
    );
    push(
        Capability::Network,
        "network_access",
        "placed tasks may use outbound network access from this node",
        "network egress from the node environment",
    );
    push(
        Capability::HostFilesystem,
        "host_filesystem_access",
        "placed tasks may access configured host filesystem mounts",
        "host file visibility outside the project checkout",
    );
    push(
        Capability::Secrets,
        "secret_access",
        "placed tasks may receive configured secret material",
        "secret exposure to authorized task code",
    );
    push(
        Capability::InboundPorts,
        "inbound_ports",
        "placed tasks may expose inbound ports from this node",
        "network service exposure from the node environment",
    );
    push(
        Capability::ArbitrarySyscalls,
        "arbitrary_syscalls",
        "placed tasks may use broader host syscall surface",
        "reduced host isolation",
    );

    disclosures.sort_by(|left, right| {
        left.grant
            .cmp(&right.grant)
            .then_with(|| left.capability.cmp(&right.capability))
    });
    disclosures
}

pub(crate) fn execute_node_attach(args: AttachArgs) -> Result<NodeAttachReport> {
    let coordinator = args
        .coordinator
        .clone()
        .context("node attach execution requires --coordinator")?;
    let tenant = args.tenant.clone();
    let project = args.project.clone();
    let node = args.node.clone().unwrap_or_else(default_node_id);
    let node_private_key = node_private_key_for_attach(&node)?;
    let derived_public_key =
        node_ed25519_public_key_from_private_key(&node_private_key).map_err(anyhow::Error::msg)?;
    let public_key = args
        .public_key
        .clone()
        .unwrap_or(derived_public_key.clone());
    if public_key != derived_public_key {
        anyhow::bail!(
            "node attach --public-key must match CLUSTERFLUX_NODE_PRIVATE_KEY or the stored local node credential"
        );
    }
    let mut plan = attach_plan(args);
    if let Some(enrollment) = &mut plan.enrollment {
        enrollment.public_key_fingerprint = Digest::sha256(&public_key);
    }

    let mut session = JsonLineSession::connect(&coordinator)?;
    let used_enrollment_exchange = plan.enrollment.is_some();
    let coordinator_response = if let Some(enrollment) = &plan.enrollment {
        session.request(CoordinatorRequest::ExchangeNodeEnrollmentGrant {
            tenant: tenant.clone(),
            project: project.clone(),
            node: node.clone(),
            public_key: public_key.clone(),
            enrollment_grant: enrollment.grant.clone(),
        })?
    } else {
        session.request(CoordinatorRequest::AttachNode {
            tenant: tenant.clone(),
            project: project.clone(),
            node: node.clone(),
            public_key: public_key.clone(),
        })?
    };
    let identity_accepted = if used_enrollment_exchange {
        matches!(
            &coordinator_response,
            CoordinatorResponse::NodeEnrollmentExchanged { .. }
        )
    } else {
        matches!(
            &coordinator_response,
            CoordinatorResponse::NodeAttached { .. }
        )
    };
    if !identity_accepted {
        anyhow::bail!("coordinator returned an unexpected node-identity response");
    }
    let heartbeat_request = CoordinatorRequest::NodeHeartbeat {
        tenant: tenant.clone(),
        project: project.clone(),
        node: plan.node.clone(),
        node_signature: None,
    };
    let heartbeat_payload = serde_json::to_value(&heartbeat_request)?;
    let heartbeat_signature = sign_node_request(
        &node_private_key,
        &NodeId::from(plan.node.as_str()),
        "node_heartbeat",
        &signed_request_payload_digest(&heartbeat_payload),
        command_nonce("node-heartbeat"),
        unix_timestamp_seconds(),
    )
    .map_err(anyhow::Error::msg)?;
    let heartbeat_request = CoordinatorRequest::NodeHeartbeat {
        tenant: tenant.clone(),
        project: project.clone(),
        node: plan.node.clone(),
        node_signature: Some(heartbeat_signature),
    };
    let heartbeat_response = session.request(heartbeat_request)?;
    if !matches!(
        &heartbeat_response,
        CoordinatorResponse::NodeHeartbeat { .. }
    ) {
        anyhow::bail!("coordinator returned an unexpected node-heartbeat response");
    }
    let capability_response = session.request(signed_node_request(
        &node_private_key,
        &plan.node,
        "report_node_capabilities",
        CoordinatorRequest::ReportNodeCapabilities {
            tenant: tenant.clone(),
            project: project.clone(),
            node: plan.node.clone(),
            capabilities: plan.capabilities.clone(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: false,
        },
    )?)?;
    if !matches!(
        &capability_response,
        CoordinatorResponse::NodeCapabilitiesRecorded { .. }
    ) {
        anyhow::bail!("coordinator returned an unexpected node-capability response");
    }

    Ok(NodeAttachReport {
        command: "node attach".to_owned(),
        node: plan.node.clone(),
        grant_disclosures: plan.grant_disclosures.clone(),
        plan,
        boundary: NodeAttachBoundaryEvidence {
            cli_contacted_coordinator: true,
            coordinator_address: coordinator,
            used_enrollment_exchange,
            coordinator_session_requests: session.requests(),
        },
        coordinator_response,
        heartbeat_response,
        capability_response,
    })
}

fn node_private_key_for_attach(node: &str) -> Result<String> {
    if let Ok(private_key) = std::env::var("CLUSTERFLUX_NODE_PRIVATE_KEY") {
        return Ok(private_key);
    }
    load_or_create_local_node_credential(&std::env::current_dir()?, node)
}

pub(crate) fn load_or_create_local_node_credential(project: &Path, node: &str) -> Result<String> {
    let file = local_node_credential_file(project, node);
    if credential_file_exists_without_symlink(&file)? {
        let bytes =
            std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
        let credential: StoredNodeCredential = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse {}", file.display()))?;
        if credential.node != node {
            anyhow::bail!(
                "stored node credential {} belongs to node `{}` instead of `{}`",
                file.display(),
                credential.node,
                node
            );
        }
        let public_key = node_ed25519_public_key_from_private_key(&credential.private_key)
            .map_err(anyhow::Error::msg)?;
        if public_key != credential.public_key {
            anyhow::bail!(
                "stored node credential {} has a public key that does not match its private key",
                file.display()
            );
        }
        return Ok(credential.private_key);
    }

    let private_key = generate_ed25519_private_key().map_err(anyhow::Error::msg)?;
    let public_key =
        node_ed25519_public_key_from_private_key(&private_key).map_err(anyhow::Error::msg)?;
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

fn credential_file_exists_without_symlink(file: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(file) {
        Ok(metadata) if metadata.file_type().is_symlink() => anyhow::bail!(
            "refusing to read node credential through symbolic link {}",
            file.display()
        ),
        Ok(metadata) if !metadata.is_file() => anyhow::bail!(
            "node credential path {} is not a regular file",
            file.display()
        ),
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).with_context(|| format!("failed to inspect {}", file.display())),
    }
}

fn persist_node_credential(file: &Path, credential: &StoredNodeCredential) -> Result<()> {
    use std::io::Write;

    let parent = file
        .parent()
        .with_context(|| format!("node credential path {} has no parent", file.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    if std::fs::symlink_metadata(parent)?.file_type().is_symlink() {
        anyhow::bail!(
            "refusing to store node credential through symbolic-link directory {}",
            parent.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure {}", parent.display()))?;
    }

    let mut temporary = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "failed to create temporary credential in {}",
            parent.display()
        )
    })?;
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
        anyhow::anyhow!(
            "refusing to overwrite node credential {}: {}",
            file.display(),
            error.error
        )
    })?;
    Ok(())
}

pub(crate) fn local_node_credential_file(project: &Path, node: &str) -> PathBuf {
    let digest = Digest::sha256(node);
    let file_stem = digest.as_str().trim_start_matches("sha256:");
    project
        .join(".clusterflux-state")
        .join("nodes")
        .join(format!("{file_stem}.json"))
}

fn default_node_public_key_for_plan(node: &str) -> String {
    let private_key = generate_ed25519_private_key()
        .unwrap_or_else(|_| format!("unavailable-random-node-plan-key:{node}"));
    node_ed25519_public_key_from_private_key(&private_key)
        .unwrap_or_else(|_| format!("{node}-public-key"))
}

fn signed_node_request(
    node_private_key: &str,
    node: &str,
    request_kind: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorRequest> {
    let payload = serde_json::to_value(&request)?;
    let payload_digest = signed_request_payload_digest(&payload);
    let node_signature = sign_node_request(
        node_private_key,
        &NodeId::from(node),
        request_kind,
        &payload_digest,
        command_nonce(request_kind),
        unix_timestamp_seconds(),
    )
    .map_err(anyhow::Error::msg)?;
    Ok(CoordinatorRequest::SignedNode {
        node: node.to_owned(),
        node_signature,
        request: Box::new(request),
    })
}

pub(crate) fn default_node_id() -> String {
    std::env::var("CLUSTERFLUX_NODE_ID")
        .or_else(|_| std::env::var("HOSTNAME"))
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "node-local".to_owned())
}

fn parse_capability(cap: &str) -> Option<Capability> {
    match cap {
        "command" => Some(Capability::Command),
        "containers" => Some(Capability::Containers),
        "rootless-podman" => Some(Capability::RootlessPodman),
        "source-filesystem" => Some(Capability::SourceFilesystem),
        "source-git" => Some(Capability::SourceGit),
        "host-filesystem" => Some(Capability::HostFilesystem),
        "network" => Some(Capability::Network),
        "secrets" => Some(Capability::Secrets),
        "inbound-ports" => Some(Capability::InboundPorts),
        "arbitrary-syscalls" => Some(Capability::ArbitrarySyscalls),
        "vfs-artifacts" => Some(Capability::VfsArtifacts),
        "windows-command-dev" => Some(Capability::WindowsCommandDev),
        "artifact-transfer" => Some(Capability::ArtifactTransfer),
        _ => None,
    }
}
