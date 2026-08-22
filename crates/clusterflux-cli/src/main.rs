#[cfg(test)]
use std::io::{BufRead, BufReader, Write};
#[cfg(test)]
use std::net::TcpListener;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use clusterflux_core::RunId;
#[cfg(test)]
use clusterflux_core::{Capability, Digest, ProjectModel, SourceProviderKind};
#[cfg(test)]
use serde_json::json;
use serde_json::Value;

mod admin;
mod agent;
mod artifact;
mod auth;
mod auth_scope;
mod automation;
mod build;
mod bundle;
mod client;
mod config;
mod confirm;
mod debug;
mod dispatch;
mod doctor;
mod errors;
mod key;
mod logout;
mod logs;
mod node;
mod output;
mod process;
mod process_events;
mod project;
mod quota;
mod run;
mod task;
mod tools;

use admin::{admin_bootstrap_report, admin_status_report, admin_suspend_tenant_report};
use agent::agent_enrollment_plan;
#[cfg(test)]
use artifact::{artifact_download_report, artifact_export_report, artifact_list_report};
use artifact::{
    artifact_download_report_with_session, artifact_export_report_with_session,
    artifact_list_report_with_session,
};
use auth::{
    auth_status_report, connect_self_hosted_report, execute_interactive_browser_login, login_plan,
    non_interactive_browser_login_report, print_browser_login_success,
    read_session_secret_from_stdin,
};
#[cfg(test)]
use auth::{contains_provider_token_field, stored_cli_session_from_login_response, LoginFlowPlan};
#[cfg(test)]
use auth_scope::login_args_for_project;
use automation::{
    run_cancel_report, run_list_report, run_show_report, secret_list_report, secret_revoke_report,
    secret_set_report,
};
use build::{build_report, check_report};
#[cfg(test)]
use bundle::task_abi_digest;
pub(crate) use bundle::{bundle_inspection, discovered_environment_names};
#[cfg(test)]
use client::control_endpoint_identity;
use config::{default_hosted_coordinator_endpoint, read_cli_session};
#[cfg(test)]
use config::{
    read_project_config, session_config_file, write_cli_session, write_project_config,
    ProjectConfig, StoredCliSession, DEFAULT_HOSTED_COORDINATOR_ENDPOINT,
};
pub(crate) use confirm::confirmation_required_report;
#[cfg(test)]
use debug::debug_attach_report_with_dap;
use debug::{dap_plan, debug_attach_report_with_dap_and_session, exec_dap};
use doctor::doctor_report;
use errors::cli_error_summary;
#[cfg(test)]
use errors::cli_error_summary_for_category;
#[cfg(test)]
use key::{key_add_report, key_list_report, key_revoke_report};
use key::{
    key_add_report_with_session, key_list_report_with_session, key_revoke_report_with_session,
};
use logout::{auth_logout_report, logout_report};
#[cfg(test)]
use logs::logs_report;
use logs::logs_report_with_session;
use node::{
    attach_plan, execute_node_attach, node_enroll_report, node_list_report, node_revoke_report,
    node_status_report,
};
use output::emit_report;
#[cfg(test)]
use output::{apply_command_report_exit_code, human_report};
use process::{
    process_abort_report_with_session, process_cancel_report, process_cancel_report_with_session,
    process_list_report_with_session, process_restart_report_with_session,
    process_status_report_with_session,
};
#[cfg(test)]
use process::{process_restart_report, process_status_report};
#[cfg(test)]
use process_events::task_summaries;
#[cfg(test)]
use process_events::{
    artifact_download_session_summary, artifact_export_plan_summary, log_entries,
};
use project::{
    project_init_report, project_list_report, project_select_report, project_status_report,
};
use quota::quota_status_report;
#[cfg(test)]
use run::{
    agent_session_from_keys, run_plan, run_start_summary, should_execute_local_node, CliSession,
    CoordinatorSelection,
};
use run::{run_report, session_from_sources};
#[cfg(test)]
use task::{task_list_report, task_restart_report};
use task::{task_list_report_with_session, task_restart_report_with_session};
use tools::dap_binary_path;

#[derive(Clone, Debug, Parser)]
#[command(
    name = "clusterflux",
    version,
    arg_required_else_help = true,
    about = "Clusterflux distributed Wasm runtime CLI.",
    after_help = "Primary workflow:
  1. clusterflux login --browser
  2. clusterflux project init
  3. clusterflux node enroll; clusterflux node attach; clusterflux-node --worker
  4. clusterflux run [entry] --project <path>
  5. Debug with VS Code \"Clusterflux: Launch Virtual Process\" or clusterflux dap
  6. Inspect with clusterflux process list, clusterflux process status, task list, logs, and artifact list
  7. Request cooperative shutdown with process cancel; force termination with process abort

Use --json on primary commands for scriptable output. Hosted account creation happens in the browser login flow."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    Doctor(DoctorArgs),
    Login(LoginArgs),
    Logout(AuthLogoutArgs),
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    Agent {
        #[command(subcommand)]
        command: AgentCommands,
    },
    Key {
        #[command(subcommand)]
        command: KeyCommands,
    },
    Project {
        #[command(subcommand)]
        command: ProjectCommands,
    },
    Inspect(BundleInspectArgs),
    Check(CheckArgs),
    Build(BuildArgs),
    Bundle {
        #[command(subcommand)]
        command: BundleCommands,
    },
    Run(RunArgs),
    Runs {
        #[command(subcommand)]
        command: RunsCommands,
    },
    Secret {
        #[command(subcommand)]
        command: SecretCommands,
    },
    Node {
        #[command(subcommand)]
        command: NodeCommands,
    },
    Process {
        #[command(subcommand)]
        command: ProcessCommands,
    },
    Task {
        #[command(subcommand)]
        command: TaskCommands,
    },
    Logs(LogsArgs),
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommands,
    },
    Dap(DapArgs),
    Debug {
        #[command(subcommand)]
        command: DebugCommands,
    },
    Quota {
        #[command(subcommand)]
        command: QuotaCommands,
    },
    Admin {
        #[command(subcommand)]
        command: AdminCommands,
    },
}

#[derive(Clone, Debug, Subcommand)]
enum RunsCommands {
    List(RunListArgs),
    Show(RunShowArgs),
    Cancel(RunCancelArgs),
}

#[derive(Clone, Debug, Parser)]
struct RunListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct RunShowArgs {
    #[arg(value_parser = parse_run_id)]
    run: RunId,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct RunCancelArgs {
    #[arg(value_parser = parse_run_id)]
    run: RunId,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Subcommand)]
enum SecretCommands {
    Set(SecretSetArgs),
    List(SecretListArgs),
    Revoke(SecretRevokeArgs),
}

#[derive(Clone, Debug, Parser)]
struct SecretSetArgs {
    name: String,
    #[arg(long)]
    stdin: bool,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct SecretListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct SecretRevokeArgs {
    name: String,
    #[command(flatten)]
    scope: CliScopeArgs,
}

fn parse_run_id(value: &str) -> Result<RunId, String> {
    RunId::try_new(value).map_err(|error| error.to_string())
}

#[derive(Clone, Debug, Parser)]
struct DoctorArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct LoginArgs {
    #[arg(long = "browser")]
    _browser: bool,
    #[arg(long)]
    non_interactive: bool,
    #[arg(long)]
    plan: bool,
    #[arg(long)]
    json: bool,
    #[arg(long, default_value_t = default_hosted_coordinator_endpoint())]
    coordinator: String,
    #[arg(long = "project-id", default_value = "project")]
    project: String,
}

#[derive(Clone, Debug, Subcommand)]
enum AuthCommands {
    Status(AuthStatusArgs),
    ConnectSelfHosted(ConnectSelfHostedArgs),
    Logout(AuthLogoutArgs),
}

#[derive(Clone, Debug, Parser)]
struct AuthStatusArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct ConnectSelfHostedArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, required = true)]
    session_secret_stdin: bool,
}

#[derive(Clone, Debug, Parser)]
struct AuthLogoutArgs {
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Subcommand)]
enum AgentCommands {
    Enroll(AgentEnrollArgs),
}

#[derive(Clone, Debug, Subcommand)]
enum KeyCommands {
    Add(KeyAddArgs),
    List(KeyListArgs),
    Revoke(KeyRevokeArgs),
}

#[derive(Clone, Debug, Subcommand)]
enum BundleCommands {
    Inspect(BundleInspectArgs),
}

#[derive(Clone, Debug, Parser)]
struct AgentEnrollArgs {
    #[arg(long)]
    json: bool,
    #[arg(long = "public-key")]
    public_key: String,
}

#[derive(Clone, Debug, Parser)]
struct KeyAddArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "agent")]
    agent: String,
    #[arg(long = "public-key")]
    public_key: String,
}

#[derive(Clone, Debug, Parser)]
struct KeyListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct KeyRevokeArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "agent")]
    agent: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Subcommand)]
enum ProjectCommands {
    Init(ProjectInitArgs),
    Inspect(BundleInspectArgs),
    Status(ProjectStatusArgs),
    List(ProjectListArgs),
    Select(ProjectSelectArgs),
}

#[derive(Clone, Debug, Parser)]
struct ProjectInitArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "project")]
    new_project: String,
    #[arg(long, default_value = "Clusterflux Project")]
    name: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Parser)]
struct ProjectStatusArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct ProjectListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct ProjectSelectArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(value_name = "PROJECT")]
    selected_project: String,
}

#[derive(Clone, Debug, Parser)]
struct BundleInspectArgs {
    #[arg(long)]
    project: Option<PathBuf>,
    #[arg(long = "source-provider")]
    source_provider: Option<String>,
    #[arg(long = "disable-source-provider")]
    disabled_source_providers: Vec<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Parser)]
struct BuildArgs {
    #[arg(long)]
    project: Option<PathBuf>,
    #[arg(long)]
    entry: Option<String>,
    #[arg(long = "source-provider")]
    source_provider: Option<String>,
    #[arg(long = "disable-source-provider")]
    disabled_source_providers: Vec<String>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Parser)]
struct CheckArgs {
    #[arg(long)]
    project: Option<PathBuf>,
    #[arg(long, default_value = "human", value_parser = ["human", "rustc-json"])]
    message_format: String,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Parser)]
struct RunArgs {
    entry: Option<String>,
    #[arg(long)]
    project: Option<PathBuf>,
    #[arg(long)]
    coordinator: Option<String>,
    #[arg(long)]
    local: bool,
    #[arg(long)]
    non_interactive: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Subcommand)]
enum NodeCommands {
    Attach(AttachArgs),
    Enroll(NodeEnrollArgs),
    List(NodeListArgs),
    Status(NodeStatusArgs),
    Revoke(NodeRevokeArgs),
}

#[derive(Clone, Debug, Parser)]
struct AttachArgs {
    #[arg(long)]
    coordinator: Option<String>,
    #[arg(long, default_value = "tenant")]
    tenant: String,
    #[arg(long = "project-id", default_value = "project")]
    project: String,
    #[arg(long)]
    node: Option<String>,
    #[arg(long = "cap")]
    caps: Vec<String>,
    #[arg(long = "enrollment-grant")]
    enrollment_grant: Option<String>,
    #[arg(long = "public-key")]
    public_key: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Clone, Debug, Parser)]
struct NodeEnrollArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value_t = 900)]
    ttl_seconds: u64,
}

#[derive(Clone, Debug, Parser)]
struct NodeListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct NodeStatusArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long)]
    node: Option<String>,
}

#[derive(Clone, Debug, Parser)]
struct NodeRevokeArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long)]
    node: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Subcommand)]
enum ProcessCommands {
    List(ProcessListArgs),
    Status(ProcessStatusArgs),
    Restart(ProcessRestartArgs),
    Cancel(ProcessCancelArgs),
    Abort(ProcessAbortArgs),
}

#[derive(Clone, Debug, Parser)]
struct ProcessListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Parser)]
struct ProcessStatusArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "vp-current")]
    process: String,
}

#[derive(Clone, Debug, Parser)]
struct ProcessRestartArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "vp-current")]
    process: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Parser)]
struct ProcessCancelArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "vp-current")]
    process: String,
    #[arg(long)]
    node: Option<String>,
    #[arg(long)]
    task: Option<String>,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Parser)]
struct ProcessAbortArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "vp-current")]
    process: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Subcommand)]
enum TaskCommands {
    List(TaskListArgs),
    Restart(TaskRestartArgs),
}

#[derive(Clone, Debug, Parser)]
struct TaskListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long)]
    process: Option<String>,
}

#[derive(Clone, Debug, Parser)]
struct TaskRestartArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    task: String,
    #[arg(long, default_value = "vp-current")]
    process: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Parser)]
struct LogsArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long)]
    process: Option<String>,
    #[arg(long)]
    task: Option<String>,
}

#[derive(Clone, Debug, Subcommand)]
enum ArtifactCommands {
    List(ArtifactListArgs),
    Download(ArtifactDownloadArgs),
    Export(ArtifactExportArgs),
}

#[derive(Clone, Debug, Parser)]
struct ArtifactListArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long)]
    process: Option<String>,
}

#[derive(Clone, Debug, Parser)]
struct ArtifactDownloadArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    artifact: String,
    /// Deprecated local-path hint; the coordinator never returns artifact bytes.
    #[arg(long)]
    to: Option<PathBuf>,
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Parser)]
struct ArtifactExportArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    artifact: String,
    /// Deprecated local-path hint; artifact bytes are exported directly to the receiver node.
    #[arg(long)]
    to: Option<PathBuf>,
    #[arg(long, default_value = "node-local")]
    receiver_node: String,
}

#[derive(Clone, Debug, Parser)]
struct DapArgs {
    #[arg(long)]
    plan: bool,
    #[arg(long)]
    json: bool,
    #[arg(last = true)]
    args: Vec<String>,
}

#[derive(Clone, Debug, Subcommand)]
enum DebugCommands {
    Attach(DebugAttachArgs),
}

#[derive(Clone, Debug, Parser)]
struct DebugAttachArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "vp-current")]
    process: String,
}

#[derive(Clone, Debug, Subcommand)]
enum QuotaCommands {
    Status(QuotaStatusArgs),
}

#[derive(Clone, Debug, Parser)]
struct QuotaStatusArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
}

#[derive(Clone, Debug, Subcommand)]
enum AdminCommands {
    Status(AdminStatusArgs),
    Bootstrap(AdminBootstrapArgs),
    RevokeNode(NodeRevokeArgs),
    StopProcess(ProcessCancelArgs),
    SuspendTenant(AdminSuspendTenantArgs),
}

#[derive(Clone, Debug, Parser)]
struct AdminStatusArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long)]
    admin_token: Option<String>,
}

#[derive(Clone, Debug, Parser)]
struct AdminBootstrapArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long, default_value = "Clusterflux Project")]
    name: String,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Parser)]
struct AdminSuspendTenantArgs {
    #[command(flatten)]
    scope: CliScopeArgs,
    #[arg(long = "target-tenant")]
    target_tenant: Option<String>,
    #[arg(long)]
    admin_token: Option<String>,
    #[arg(long)]
    yes: bool,
}

#[derive(Clone, Debug, Args)]
struct CliScopeArgs {
    #[arg(long)]
    coordinator: Option<String>,
    #[arg(long, default_value = "tenant")]
    tenant: String,
    #[arg(long = "project-id", default_value = "project")]
    project: String,
    #[arg(long, default_value = "user")]
    user: String,
    #[arg(long)]
    json: bool,
}

fn main() {
    if let Err(error) = dispatch::run_cli() {
        let message = error.to_string();
        let machine_error = cli_error_summary(&message);
        let category = machine_error
            .get("category")
            .and_then(Value::as_str)
            .unwrap_or("unknown");
        let exit_code = machine_error
            .get("stable_exit_code")
            .and_then(Value::as_i64)
            .and_then(|code| i32::try_from(code).ok())
            .unwrap_or(1);
        eprintln!("Error ({category}, exit {exit_code}): {error:#}");
        std::process::exit(exit_code);
    }
}

#[cfg(test)]
mod tests;
