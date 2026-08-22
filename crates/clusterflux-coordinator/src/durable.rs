use std::collections::{BTreeMap, VecDeque};

use clusterflux_core::{
    AgentId, AutomatedRunRecord, CommitTrigger, CompiledWorkflowBundle, CredentialKind, Digest,
    NodeId, ProcessId, ProjectId, RepositoryRevision, RunId, SourceProviderKind, TaskInstanceId,
    TenantId, TriggerContext, TriggerId, UserId, WorkflowCompilationRequest, WorkflowSource,
};
use serde::{Deserialize, Serialize};

mod btree_map_as_entries {
    use std::collections::BTreeMap;

    use serde::{de::DeserializeOwned, Deserialize, Serialize};

    pub fn serialize<K, V, S>(map: &BTreeMap<K, V>, serializer: S) -> Result<S::Ok, S::Error>
    where
        K: Serialize,
        V: Serialize,
        S: serde::Serializer,
    {
        map.iter().collect::<Vec<_>>().serialize(serializer)
    }

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: DeserializeOwned + Ord,
        V: DeserializeOwned,
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        if value.as_object().is_some_and(serde_json::Map::is_empty) {
            // Older durable records encoded an empty map as `{}`. A composite
            // key could never be persisted once populated, so that is the only
            // legacy object form that can exist.
            return Ok(BTreeMap::new());
        }
        let entries =
            serde_json::from_value::<Vec<(K, V)>>(value).map_err(serde::de::Error::custom)?;
        Ok(entries.into_iter().collect())
    }
}

pub use clusterflux_protocol::{AgentPublicKeyRecord, ProjectRecord, ServicePolicyRecord};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantRecord {
    pub id: TenantId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: UserId,
    pub tenant: TenantId,
    pub credential_kind: CredentialKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeIdentityRecord {
    pub id: NodeId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub public_key: String,
    pub enrollment_scope: String,
    #[serde(default)]
    pub last_seen_epoch_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct NodeScopeKey {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub node: NodeId,
}

impl NodeScopeKey {
    pub fn new(tenant: TenantId, project: ProjectId, node: NodeId) -> Self {
        Self {
            tenant,
            project,
            node,
        }
    }

    pub fn from_refs(tenant: &TenantId, project: &ProjectId, node: &NodeId) -> Self {
        Self::new(tenant.clone(), project.clone(), node.clone())
    }

    pub fn credential_subject(&self) -> String {
        format!(
            "node:{}:{}:{}:{}:{}:{}",
            self.tenant.as_str().len(),
            self.tenant,
            self.project.as_str().len(),
            self.project,
            self.node.as_str().len(),
            self.node
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecord {
    pub subject: String,
    pub tenant: TenantId,
    pub project: Option<ProjectId>,
    pub kind: CredentialKind,
    pub public_key_fingerprint: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CliSessionRecord {
    pub session_digest: Digest,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub user: UserId,
    pub credential_kind: CredentialKind,
    pub expires_at_epoch_seconds: Option<u64>,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProviderConfigRecord {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub provider: SourceProviderKind,
    pub manifest_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountPolicyState {
    pub account_status: String,
    pub suspended: bool,
    pub disabled: bool,
    pub deleted: bool,
    pub manual_review: bool,
    pub sanitized_reason: Option<String>,
    pub next_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectPermissionRecord {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub user: UserId,
    pub can_debug: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedCommitTriggerRecord {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub binding_id: String,
    pub body_digest: Digest,
    pub trigger: CommitTrigger,
}

/// Compiler-specific retry budget and monotonically increasing fencing seed.
/// Live ownership, offer, acknowledgement, and lease state exist only in the
/// generic assignment registry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerAssignmentRetryRecord {
    #[serde(default, rename = "assignment_lease_epoch")]
    pub next_offer_epoch: u64,
    #[serde(default, rename = "assignment_attempts")]
    pub attempts: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AssignmentKind {
    WorkflowCompiler {
        run_id: RunId,
    },
    ProcessTask {
        process: ProcessId,
        task: TaskInstanceId,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssignmentState {
    Pending,
    Offered,
    Acknowledged,
    Running,
    Terminal,
}

/// Durable generic authority for both process and system assignments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveAssignmentRecord {
    pub assignment_id: String,
    pub kind: AssignmentKind,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub node: NodeId,
    pub attempt_id: String,
    pub offer_epoch: u64,
    pub state: AssignmentState,
    pub offered_at: u64,
    pub acknowledged_at: Option<u64>,
    pub lease_expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalAssignmentRecord {
    pub assignment_id: String,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub node: NodeId,
    pub attempt_id: String,
    pub offer_epoch: u64,
    pub terminal_at: u64,
    #[serde(default)]
    pub replay_allowed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomatedRunStageRecord {
    pub run: AutomatedRunRecord,
    pub run_key: Digest,
    pub source: Option<WorkflowSource>,
    #[serde(default)]
    pub revision_environments: Vec<clusterflux_core::EnvironmentResource>,
    pub revision: Option<RepositoryRevision>,
    pub compilation_request: Option<WorkflowCompilationRequest>,
    #[serde(default, flatten)]
    pub assignment_retry: CompilerAssignmentRetryRecord,
    pub compiled_bundle: Option<CompiledWorkflowBundle>,
    #[serde(default)]
    pub compiled_summary: Option<clusterflux_core::CompiledWorkflowSummary>,
    pub trigger_context: Option<TriggerContext>,
    pub launch_attempt: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectEnvironmentRecord {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub name: String,
    pub immutable_digest: Digest,
    pub definition: clusterflux_core::EnvironmentResource,
    pub enabled: bool,
    pub updated_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedProjectSecretRecord {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub name: String,
    pub ciphertext_base64: String,
    pub nonce_base64: String,
    pub key_version: u32,
    pub allowed_entrypoint: String,
    pub allowed_task_definition: String,
    pub allowed_trusted_refs: Vec<String>,
    pub created_at: u64,
    pub updated_at: u64,
    pub revoked_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretAuditRecord {
    pub sequence: u64,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub name: String,
    pub process: Option<ProcessId>,
    pub task: Option<clusterflux_core::TaskInstanceId>,
    pub node: Option<NodeId>,
    pub event: String,
    pub occurred_at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AutomationDurableState {
    pub accepted_commit_triggers: BTreeMap<TriggerId, AcceptedCommitTriggerRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub trigger_deliveries: BTreeMap<(String, String), TriggerId>,
    pub automated_runs: BTreeMap<RunId, AutomatedRunStageRecord>,
    pub automated_run_keys: BTreeMap<Digest, RunId>,
    #[serde(default, with = "btree_map_as_entries")]
    pub project_environments: BTreeMap<(TenantId, ProjectId, String), ProjectEnvironmentRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub encrypted_project_secrets:
        BTreeMap<(TenantId, ProjectId, String), EncryptedProjectSecretRecord>,
    pub secret_audit: Vec<SecretAuditRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub trusted_secret_nodes: BTreeMap<(TenantId, ProjectId), NodeId>,
    #[serde(default)]
    pub active_assignments: BTreeMap<String, ActiveAssignmentRecord>,
    #[serde(default)]
    pub terminal_assignment_history: VecDeque<TerminalAssignmentRecord>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DurableState {
    pub tenants: BTreeMap<TenantId, TenantRecord>,
    pub users: BTreeMap<UserId, UserRecord>,
    pub projects: BTreeMap<ProjectId, ProjectRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub node_identities: BTreeMap<NodeScopeKey, NodeIdentityRecord>,
    pub credentials: BTreeMap<String, CredentialRecord>,
    pub cli_sessions: BTreeMap<Digest, CliSessionRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub source_provider_configs:
        BTreeMap<(TenantId, ProjectId, String), SourceProviderConfigRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub service_policy_records: BTreeMap<(TenantId, String), ServicePolicyRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub project_permissions: BTreeMap<(TenantId, ProjectId, UserId), ProjectPermissionRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub agent_public_keys: BTreeMap<(TenantId, ProjectId, AgentId), AgentPublicKeyRecord>,
    #[serde(default)]
    pub accepted_commit_triggers: BTreeMap<TriggerId, AcceptedCommitTriggerRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub trigger_deliveries: BTreeMap<(String, String), TriggerId>,
    #[serde(default)]
    pub automated_runs: BTreeMap<RunId, AutomatedRunStageRecord>,
    #[serde(default)]
    pub automated_run_keys: BTreeMap<Digest, RunId>,
    #[serde(default, with = "btree_map_as_entries")]
    pub project_environments: BTreeMap<(TenantId, ProjectId, String), ProjectEnvironmentRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub encrypted_project_secrets:
        BTreeMap<(TenantId, ProjectId, String), EncryptedProjectSecretRecord>,
    #[serde(default)]
    pub secret_audit: Vec<SecretAuditRecord>,
    #[serde(default, with = "btree_map_as_entries")]
    pub trusted_secret_nodes: BTreeMap<(TenantId, ProjectId), NodeId>,
    #[serde(default)]
    pub active_assignments: BTreeMap<String, ActiveAssignmentRecord>,
    #[serde(default)]
    pub terminal_assignment_history: VecDeque<TerminalAssignmentRecord>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct CompositeMapFixture {
        #[serde(default, with = "btree_map_as_entries")]
        values: BTreeMap<(String, String), u64>,
    }

    #[test]
    fn composite_durable_map_round_trips_as_entries_and_reads_legacy_empty_object() {
        let fixture = CompositeMapFixture {
            values: BTreeMap::from([(("tenant".to_owned(), "project".to_owned()), 7)]),
        };
        let encoded = serde_json::to_value(&fixture).unwrap();
        assert!(encoded["values"].is_array());
        assert_eq!(
            serde_json::from_value::<CompositeMapFixture>(encoded).unwrap(),
            fixture
        );
        assert_eq!(
            serde_json::from_value::<CompositeMapFixture>(serde_json::json!({
                "values": {}
            }))
            .unwrap()
            .values,
            BTreeMap::new()
        );
    }
}

impl DurableState {
    pub fn automation(&self) -> AutomationDurableState {
        AutomationDurableState {
            accepted_commit_triggers: self.accepted_commit_triggers.clone(),
            trigger_deliveries: self.trigger_deliveries.clone(),
            automated_runs: self.automated_runs.clone(),
            automated_run_keys: self.automated_run_keys.clone(),
            project_environments: self.project_environments.clone(),
            encrypted_project_secrets: self.encrypted_project_secrets.clone(),
            secret_audit: self.secret_audit.clone(),
            trusted_secret_nodes: self.trusted_secret_nodes.clone(),
            active_assignments: self.active_assignments.clone(),
            terminal_assignment_history: self.terminal_assignment_history.clone(),
        }
    }

    pub fn replace_automation(&mut self, state: AutomationDurableState) {
        self.accepted_commit_triggers = state.accepted_commit_triggers;
        self.trigger_deliveries = state.trigger_deliveries;
        self.automated_runs = state.automated_runs;
        self.automated_run_keys = state.automated_run_keys;
        self.project_environments = state.project_environments;
        self.encrypted_project_secrets = state.encrypted_project_secrets;
        self.secret_audit = state.secret_audit;
        self.trusted_secret_nodes = state.trusted_secret_nodes;
        self.active_assignments = state.active_assignments;
        self.terminal_assignment_history = state.terminal_assignment_history;
    }
}

pub trait DurableStore {
    fn load(&self) -> DurableState;
    fn save(&mut self, state: DurableState);
}

pub trait FallibleDurableStore {
    type Error;

    fn load_state(&mut self) -> Result<DurableState, Self::Error>;
    fn save_state(&mut self, state: &DurableState) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default)]
pub struct InMemoryDurableStore {
    state: DurableState,
}

impl DurableStore for InMemoryDurableStore {
    fn load(&self) -> DurableState {
        self.state.clone()
    }

    fn save(&mut self, state: DurableState) {
        self.state = state;
    }
}
