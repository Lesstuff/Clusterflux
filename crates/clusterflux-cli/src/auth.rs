use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse, LoginRequest,
    LoginResponse,
};
use serde::Serialize;
use serde_json::{json, Value};
use url::{Host, Url};

use crate::client::{
    authenticated_or_local_trusted_request, stored_session_for_coordinator, BrowserLoginSession,
    JsonLineSession,
};
use crate::config::{
    default_hosted_coordinator_endpoint, effective_scope_value, read_cli_session,
    read_project_config, write_cli_session, write_project_config, ProjectConfig, StoredCliSession,
};
use crate::errors::cli_error_summary;
use crate::run::{session_from_env, CliSession};
use crate::ConnectSelfHostedArgs;
use crate::{AuthStatusArgs, LoginArgs};

const DEFAULT_BROWSER_LOGIN_TRANSACTION_TIMEOUT_SECONDS: u64 = 300;
const BROWSER_LOGIN_POLL_INTERVAL: Duration = Duration::from_secs(2);

pub(crate) fn read_session_secret_from_stdin() -> Result<String> {
    let mut secret = String::new();
    std::io::stdin()
        .read_line(&mut secret)
        .context("failed to read self-hosted session secret from stdin")?;
    let secret = secret.trim_end_matches(['\r', '\n']).to_owned();
    if secret.trim().is_empty() {
        anyhow::bail!("self-hosted session secret from stdin must not be empty");
    }
    Ok(secret)
}

pub(crate) fn connect_self_hosted_report(
    args: ConnectSelfHostedArgs,
    cwd: PathBuf,
    session_secret: String,
) -> Result<Value> {
    if !args.session_secret_stdin {
        anyhow::bail!("self-hosted session configuration requires --session-secret-stdin");
    }
    let coordinator = args
        .scope
        .coordinator
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .context("self-hosted session configuration requires --coordinator <host:port>")?;
    if session_secret.trim().is_empty() {
        anyhow::bail!("self-hosted session secret from stdin must not be empty");
    }

    let mut connection = JsonLineSession::connect(coordinator)?;
    let response = connection.request(CoordinatorRequest::Authenticated {
        session_secret: session_secret.clone(),
        request: AuthenticatedCoordinatorRequest::AuthStatus,
    })?;
    let CoordinatorResponse::AuthStatus {
        tenant,
        project,
        actor,
        authenticated,
        ..
    } = &response
    else {
        anyhow::bail!("self-hosted coordinator returned an unexpected auth-status response");
    };
    for (field, actual, expected) in [
        ("tenant", tenant.as_str(), args.scope.tenant.as_str()),
        ("project", project.as_str(), args.scope.project.as_str()),
        ("actor", actor.as_str(), args.scope.user.as_str()),
    ] {
        if actual != expected {
            anyhow::bail!(
                "self-hosted session {field} mismatch: coordinator returned {actual:?}, expected {expected:?}"
            );
        }
    }
    if !*authenticated {
        anyhow::bail!("self-hosted coordinator did not confirm the CLI session");
    }

    let stored = StoredCliSession {
        kind: "self_hosted".to_owned(),
        coordinator: coordinator.to_owned(),
        tenant: args.scope.tenant,
        project: args.scope.project,
        user: args.scope.user,
        cli_session_credential_kind: "CliDeviceSession".to_owned(),
        session_secret: Some(session_secret),
        token_expiry_posture: "configured_by_self_hosted_operator".to_owned(),
        expires_at: None,
        provider_tokens_exposed_to_cli: false,
        provider_tokens_sent_to_nodes: false,
        created_at_unix_seconds: unix_timestamp_seconds(),
    };
    let session_file = write_cli_session(&cwd, &stored)?;
    Ok(json!({
        "command": "auth connect-self-hosted",
        "status": "connected",
        "coordinator": coordinator,
        "tenant": stored.tenant,
        "project": stored.project,
        "user": stored.user,
        "session_file": session_file,
        "session_secret_read_from_stdin": true,
        "session_secret_exposed_in_report": false,
        "provider_tokens_exposed_to_cli": false,
        "provider_tokens_sent_to_nodes": false,
        "coordinator_response": response,
        "coordinator_session_requests": connection.requests(),
    }))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LoginPlan {
    pub(crate) coordinator: String,
    pub(crate) human_flow: LoginFlowPlan,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub(crate) struct LoginCompletionReport {
    pub(crate) plan: LoginPlan,
    pub(crate) boundary: LoginCompletionBoundaryEvidence,
    pub(crate) coordinator_response: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LoginCompletionBoundaryEvidence {
    pub(crate) cli_contacted_coordinator: bool,
    pub(crate) coordinator_address: String,
    pub(crate) scoped_cli_session_received: bool,
    pub(crate) local_cli_session_file_written: bool,
    pub(crate) provider_tokens_persisted_locally: bool,
    pub(crate) provider_tokens_exposed_to_cli: bool,
    pub(crate) provider_tokens_sent_to_nodes: bool,
    pub(crate) coordinator_session_requests: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) enum LoginFlowPlan {
    Browser(HostedBrowserLoginPlan),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct HostedBrowserLoginPlan {
    pub(crate) authorization_url: Option<String>,
    pub(crate) server_owns_state: bool,
    pub(crate) server_owns_nonce: bool,
    pub(crate) pkce_required: bool,
    pub(crate) hosted_callback: bool,
    pub(crate) cli_receives_provider_authorization_code: bool,
    pub(crate) cli_submits_identity_claims: bool,
}

pub(crate) fn auth_status_report(args: AuthStatusArgs, cwd: PathBuf) -> Result<Value> {
    let config = read_project_config(&cwd)?;
    let stored_session = read_cli_session(&cwd)?;
    let configured_coordinator = args
        .scope
        .coordinator
        .clone()
        .or_else(|| {
            config
                .as_ref()
                .and_then(|config| config.coordinator.clone())
        })
        .or_else(|| {
            stored_session
                .as_ref()
                .map(|session| session.coordinator.clone())
        });
    let active_coordinator = configured_coordinator
        .clone()
        .unwrap_or_else(default_hosted_coordinator_endpoint);
    let tenant = effective_scope_value(
        &args.scope.tenant,
        config
            .as_ref()
            .map(|config| config.tenant.as_str())
            .or_else(|| {
                stored_session
                    .as_ref()
                    .map(|session| session.tenant.as_str())
            }),
        "tenant",
    );
    let project = effective_scope_value(
        &args.scope.project,
        config
            .as_ref()
            .map(|config| config.project.as_str())
            .or_else(|| {
                stored_session
                    .as_ref()
                    .map(|session| session.project.as_str())
            }),
        "project",
    );
    let principal = effective_scope_value(
        &args.scope.user,
        config
            .as_ref()
            .map(|config| config.user.as_str())
            .or_else(|| stored_session.as_ref().map(|session| session.user.as_str())),
        "user",
    );
    let session_scope_mismatch = crate::auth_scope::session_scope_mismatch(
        stored_session.as_ref(),
        &active_coordinator,
        &tenant,
        &project,
        &principal,
    );
    let session_matches_project = stored_session.is_some() && session_scope_mismatch.is_none();
    let coordinator_account_status = configured_coordinator
        .as_ref()
        .filter(|_| session_scope_mismatch.is_none())
        .map(|coordinator| {
            coordinator_auth_status_summary(
                coordinator,
                &tenant,
                &project,
                &principal,
                stored_session.as_ref(),
            )
        })
        .unwrap_or_else(|| {
            if let Some(fields) = &session_scope_mismatch {
                return crate::auth_scope::session_scope_mismatch_status(fields);
            }
            json!({
                "checked": false,
                "reason": "no project or session coordinator configured",
                "suspension_known": false,
                "account_state_known": false,
                "account_status": "unknown",
                "sensitive_moderation_details_exposed": false,
                "signup_failure_details_exposed": false,
            })
        });
    Ok(json!({
        "command": "auth status",
        "active_coordinator": active_coordinator,
        "principal": principal,
        "tenant": tenant,
        "project": project,
        "session": auth_state_value(&cwd)?,
        "session_matches_current_project": session_matches_project,
        "session_scope_mismatch": session_scope_mismatch,
        "coordinator_account_status": coordinator_account_status,
        "project_config": config,
    }))
}

fn coordinator_auth_status_summary(
    coordinator: &str,
    tenant: &str,
    project: &str,
    principal: &str,
    stored_session: Option<&StoredCliSession>,
) -> Value {
    let mut session = match JsonLineSession::connect(coordinator) {
        Ok(session) => session,
        Err(error) => {
            let message = error.to_string();
            return json!({
                "checked": true,
                "reachable": false,
                "source": "public_coordinator_api",
                "account_status": "unknown",
                "suspension_known": false,
                "account_state_known": false,
                "sensitive_moderation_details_exposed": false,
                "signup_failure_details_exposed": false,
                "machine_error": cli_error_summary(&message),
                "error": message,
                "next_actions": ["clusterflux doctor", "check coordinator status"],
                "coordinator_session_requests": 0,
            });
        }
    };
    let request = match authenticated_or_local_trusted_request(
        coordinator,
        stored_session,
        CoordinatorRequest::AuthStatus {
            tenant: tenant.to_owned(),
            project: project.to_owned(),
            actor_user: principal.to_owned(),
        },
    ) {
        Ok(request) => request,
        Err(error) => {
            let message = error.to_string();
            return json!({
                "checked": false,
                "reachable": "not_checked",
                "source": "public_coordinator_api",
                "authenticated_for_current_project": false,
                "account_status": "unknown",
                "suspension_known": false,
                "account_state_known": false,
                "sensitive_moderation_details_exposed": false,
                "signup_failure_details_exposed": false,
                "machine_error": cli_error_summary(&message),
                "error": message,
                "next_actions": ["clusterflux login --browser"],
                "coordinator_session_requests": 0,
            });
        }
    };
    let response = match session.request_allow_error(request) {
        Ok(response) => response,
        Err(error) => {
            let message = error.to_string();
            return json!({
                "checked": true,
                "reachable": false,
                "source": "public_coordinator_api",
                "account_status": "unknown",
                "suspension_known": false,
                "account_state_known": false,
                "sensitive_moderation_details_exposed": false,
                "signup_failure_details_exposed": false,
                "machine_error": cli_error_summary(&message),
                "error": message,
                "next_actions": ["clusterflux doctor", "check coordinator status"],
                "coordinator_session_requests": session.requests(),
            });
        }
    };
    let coordinator_session_requests = session.requests();
    if let CoordinatorResponse::Error { error } = &response {
        let message = error.message.as_str();
        return json!({
            "checked": true,
            "reachable": true,
            "source": "public_coordinator_api",
            "account_status": "unknown",
            "suspension_known": false,
            "account_state_known": false,
            "sensitive_moderation_details_exposed": false,
            "signup_failure_details_exposed": false,
            "machine_error": cli_error_summary(message),
            "coordinator_response_type": "error",
            "next_actions": ["clusterflux doctor", "clusterflux login --browser"],
            "coordinator_session_requests": coordinator_session_requests,
        });
    }
    let CoordinatorResponse::AuthStatus {
        suspended,
        disabled,
        deleted,
        manual_review,
        account_status,
        sanitized_reason,
        next_actions,
        ..
    } = response
    else {
        return json!({
            "checked": true,
            "reachable": true,
            "source": "public_coordinator_api",
            "account_status": "unknown",
            "machine_error": cli_error_summary("coordinator returned an unexpected auth-status response"),
            "next_actions": ["clusterflux doctor"],
            "coordinator_session_requests": coordinator_session_requests,
        });
    };
    json!({
        "checked": true,
        "reachable": true,
        "source": "public_coordinator_api",
        "used_cli_session_credential": stored_session_for_coordinator(coordinator, stored_session).is_some(),
        "account_status": account_status,
        "suspension_known": true,
        "account_state_known": true,
        "suspended": suspended,
        "disabled": disabled,
        "deleted": deleted,
        "manual_review": manual_review,
        "sanitized_reason": sanitized_reason,
        "next_actions": next_actions,
        "sensitive_moderation_details_exposed": false,
        "signup_failure_details_exposed": false,
        "coordinator_response_type": "auth_status",
        "coordinator_session_requests": coordinator_session_requests,
    })
}

pub(crate) fn non_interactive_browser_login_report(args: &LoginArgs) -> Value {
    let message =
        "browser login requires an interactive browser, but non-interactive mode is enabled";
    let next_actions = vec![
        "rerun without --non-interactive to open the browser",
        "clusterflux login --browser --plan",
        "use CLUSTERFLUX_AGENT_PRIVATE_KEY for automation",
    ];
    json!({
        "command": "login",
        "status": "authentication_required",
        "coordinator": args.coordinator,
        "non_interactive": true,
        "browser_requested": true,
        "browser_opened": false,
        "safe_failure": true,
        "message": message,
        "next_actions": next_actions,
        "machine_error": crate::auth_scope::non_interactive_auth_machine_error(message, next_actions),
    })
}

pub(crate) fn auth_state_value(cwd: &Path) -> Result<Value> {
    match session_from_env()? {
        CliSession::Anonymous => {
            if let Some(session) = read_cli_session(cwd)? {
                return Ok(json!({
                    "kind": session.kind,
                    "authenticated": true,
                    "source": "session_file",
                    "coordinator": session.coordinator,
                    "tenant": session.tenant,
                    "project": session.project,
                    "principal": session.user,
                    "cli_session_credential_kind": session.cli_session_credential_kind,
                    "provider_tokens_exposed_to_cli": session.provider_tokens_exposed_to_cli,
                    "provider_tokens_exposed_to_nodes": session.provider_tokens_sent_to_nodes,
                    "expires_at": session.expires_at,
                    "token_expiry_posture": session.token_expiry_posture,
                }));
            }
            Ok(json!({
                "kind": "anonymous",
                "authenticated": false,
                "source": "environment",
                "token_expiry_posture": "no_session",
            }))
        }
        CliSession::HumanSession => {
            let expires_at = std::env::var("CLUSTERFLUX_TOKEN_EXPIRES_AT").ok();
            Ok(json!({
                "kind": "human",
                "authenticated": true,
                "source": "CLUSTERFLUX_TOKEN",
                "provider_tokens_exposed_to_nodes": false,
                "expires_at": expires_at,
                "token_expiry_posture": if expires_at.is_some() { "expires_at" } else { "unknown_env_token" },
            }))
        }
        CliSession::AgentPublicKey {
            agent,
            public_key_fingerprint,
            browser_interaction_required,
            ..
        } => Ok(json!({
            "kind": "agent_public_key",
            "authenticated": true,
            "agent": agent,
            "source": "CLUSTERFLUX_AGENT_PRIVATE_KEY",
            "public_key_fingerprint": public_key_fingerprint,
            "browser_interaction_required": browser_interaction_required,
            "token_expiry_posture": "not_applicable_public_key",
        })),
    }
}

pub(crate) fn login_plan(args: LoginArgs) -> LoginPlan {
    let human_flow = LoginFlowPlan::Browser(HostedBrowserLoginPlan {
        authorization_url: None,
        server_owns_state: true,
        server_owns_nonce: true,
        pkce_required: true,
        hosted_callback: true,
        cli_receives_provider_authorization_code: false,
        cli_submits_identity_claims: false,
    });

    LoginPlan {
        coordinator: args.coordinator,
        human_flow,
    }
}

fn finalize_browser_login(
    args: LoginArgs,
    plan: LoginPlan,
    coordinator_response: LoginResponse,
    coordinator_session_requests: u64,
) -> Result<LoginCompletionReport> {
    let coordinator_response = serde_json::to_value(coordinator_response)?;
    let coordinator = args.coordinator.clone();
    let scoped_cli_session_received = coordinator_response
        .pointer("/session/cli_session_credential_kind")
        .and_then(Value::as_str)
        == Some("CliDeviceSession");
    let provider_tokens_sent_to_nodes = coordinator_response
        .pointer("/session/provider_tokens_sent_to_nodes")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let provider_tokens_exposed_to_cli = contains_provider_token_field(&coordinator_response);
    let local_cli_session_file_written = if scoped_cli_session_received {
        let cwd = std::env::current_dir()?;
        let stored_session = stored_cli_session_from_login_response(
            &coordinator,
            &coordinator_response,
            provider_tokens_exposed_to_cli,
            provider_tokens_sent_to_nodes,
        )?;
        write_cli_session(&cwd, &stored_session)?;
        write_project_config(
            &cwd,
            &ProjectConfig {
                tenant: stored_session.tenant.clone(),
                project: stored_session.project.clone(),
                user: stored_session.user.clone(),
                coordinator: Some(stored_session.coordinator.clone()),
            },
        )?;
        true
    } else {
        false
    };

    Ok(LoginCompletionReport {
        plan,
        boundary: LoginCompletionBoundaryEvidence {
            cli_contacted_coordinator: true,
            coordinator_address: coordinator,
            scoped_cli_session_received,
            local_cli_session_file_written,
            provider_tokens_persisted_locally: false,
            provider_tokens_exposed_to_cli,
            provider_tokens_sent_to_nodes,
            coordinator_session_requests,
        },
        coordinator_response,
    })
}

pub(crate) fn stored_cli_session_from_login_response(
    coordinator: &str,
    coordinator_response: &Value,
    provider_tokens_exposed_to_cli: bool,
    provider_tokens_sent_to_nodes: bool,
) -> Result<StoredCliSession> {
    let session = coordinator_response.get("session").unwrap_or(&Value::Null);
    let expires_at = session
        .get("expires_at")
        .or_else(|| session.get("token_expires_at"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            session
                .get("expires_at_epoch_seconds")
                .and_then(Value::as_u64)
                .map(|value| value.to_string())
        });
    let tenant = session
        .get("tenant")
        .and_then(Value::as_str)
        .context("hosted login session omitted tenant")?;
    let project = session
        .get("project")
        .and_then(Value::as_str)
        .context("hosted login session omitted project")?;
    let user = session
        .get("user")
        .and_then(Value::as_str)
        .context("hosted login session omitted user")?;
    let session_secret = session
        .get("cli_session_secret")
        .or_else(|| session.get("session_secret"))
        .and_then(Value::as_str)
        .context("hosted login session omitted CLI session secret")?;
    Ok(StoredCliSession {
        kind: "human".to_owned(),
        coordinator: coordinator.to_owned(),
        tenant: tenant.to_owned(),
        project: project.to_owned(),
        user: user.to_owned(),
        cli_session_credential_kind: session
            .get("cli_session_credential_kind")
            .and_then(Value::as_str)
            .unwrap_or("CliDeviceSession")
            .to_owned(),
        session_secret: Some(session_secret.to_owned()),
        token_expiry_posture: if expires_at.is_some() {
            "expires_at".to_owned()
        } else {
            "unknown_coordinator_session".to_owned()
        },
        expires_at,
        provider_tokens_exposed_to_cli,
        provider_tokens_sent_to_nodes,
        created_at_unix_seconds: unix_timestamp_seconds(),
    })
}

pub(crate) fn execute_interactive_browser_login(args: LoginArgs) -> Result<LoginCompletionReport> {
    let coordinator = args.coordinator.clone();
    let mut session = BrowserLoginSession::connect(&coordinator)?;
    let deadline = Instant::now() + browser_login_timeout();
    let started = browser_login_request_with_rate_limit_retry(
        &mut session,
        LoginRequest::BeginOidcBrowserLogin {},
        deadline,
    )?;
    let (transaction_id, polling_secret, authorization_url) = match started {
        LoginResponse::OidcBrowserLoginStarted {
            transaction_id,
            polling_secret,
            authorization_url,
            ..
        } => (transaction_id, polling_secret, authorization_url),
        LoginResponse::Error { error } => anyhow::bail!(
            "coordinator returned an error while starting hosted browser login: {error}"
        ),
        _ => anyhow::bail!("coordinator did not start a hosted browser login transaction"),
    };
    let loopback_test_flow = coordinator.starts_with("http://")
        && crate::client::is_loopback_coordinator(&coordinator)
        && authorization_url_is_loopback_http(&authorization_url);
    if !authorization_url.starts_with("https://") && !loopback_test_flow {
        anyhow::bail!(
            "hosted login authorization URL must use HTTPS (plain HTTP is accepted only when both coordinator and identity provider are loopback test services)"
        );
    }
    let plan = LoginPlan {
        coordinator: coordinator.clone(),
        human_flow: LoginFlowPlan::Browser(HostedBrowserLoginPlan {
            authorization_url: Some(authorization_url.clone()),
            server_owns_state: true,
            server_owns_nonce: true,
            pkce_required: true,
            hosted_callback: true,
            cli_receives_provider_authorization_code: false,
            cli_submits_identity_claims: false,
        }),
    };

    eprintln!("Opening Clusterflux browser login: {authorization_url}");
    eprintln!("Waiting for the hosted login callback to complete.");
    open_browser(&authorization_url)?;

    loop {
        let response = browser_login_request_with_rate_limit_retry(
            &mut session,
            LoginRequest::PollOidcBrowserLogin {
                transaction_id: transaction_id.clone(),
                polling_secret: polling_secret.clone(),
            },
            deadline,
        )?;
        match response {
            LoginResponse::Error { error } => anyhow::bail!(
                "coordinator returned an error while polling hosted browser login: {error}"
            ),
            LoginResponse::OidcBrowserLoginPending { .. } => {
                if Instant::now()
                    .checked_add(BROWSER_LOGIN_POLL_INTERVAL)
                    .is_none_or(|next_poll| next_poll > deadline)
                {
                    anyhow::bail!("timed out waiting for hosted browser login completion");
                }
                std::thread::sleep(BROWSER_LOGIN_POLL_INTERVAL);
            }
            response @ LoginResponse::OidcBrowserSession { .. } => {
                return finalize_browser_login(args, plan, response, session.requests());
            }
            _ => anyhow::bail!("coordinator returned an invalid hosted login status"),
        }
    }
}

fn authorization_url_is_loopback_http(value: &str) -> bool {
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.scheme() != "http"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn browser_login_request_with_rate_limit_retry(
    session: &mut BrowserLoginSession,
    request: LoginRequest,
    deadline: Instant,
) -> Result<LoginResponse> {
    loop {
        match session.request_allow_transport_error(&request) {
            Ok(response) => return Ok(response),
            Err(error) if error.status_code() == Some(429) => {
                let delay = error
                    .retry_after()
                    .unwrap_or(BROWSER_LOGIN_POLL_INTERVAL)
                    .max(BROWSER_LOGIN_POLL_INTERVAL);
                if Instant::now()
                    .checked_add(delay)
                    .is_none_or(|next_attempt| next_attempt > deadline)
                {
                    anyhow::bail!("timed out waiting for hosted browser login completion");
                }
                std::thread::sleep(delay);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

pub(crate) fn print_browser_login_success(report: &LoginCompletionReport) {
    let session = report.coordinator_response.get("session");
    let tenant = session
        .and_then(|value| value.get("tenant"))
        .and_then(Value::as_str)
        .unwrap_or("tenant");
    let project = session
        .and_then(|value| value.get("project"))
        .and_then(Value::as_str)
        .unwrap_or("project");
    let user = session
        .and_then(|value| value.get("user"))
        .and_then(Value::as_str)
        .unwrap_or("user");
    println!(
        "Signed in to {} as {user} for {tenant}/{project}.",
        report.plan.coordinator
    );
    if report.boundary.scoped_cli_session_received {
        println!("Received a scoped CLI session from the coordinator.");
    }
}

fn open_browser(url: &str) -> Result<()> {
    let mut command = if let Some(command) = std::env::var_os("CLUSTERFLUX_BROWSER_OPEN_COMMAND") {
        Command::new(command)
    } else {
        platform_browser_command()
    };
    command
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command
        .spawn()
        .with_context(|| format!("failed to start browser opener for {url}"))?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn platform_browser_command() -> Command {
    Command::new("open")
}

#[cfg(target_os = "windows")]
fn platform_browser_command() -> Command {
    let mut command = Command::new("cmd");
    command.args(["/C", "start", ""]);
    command
}

#[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
fn platform_browser_command() -> Command {
    Command::new("xdg-open")
}

fn browser_login_timeout() -> Duration {
    let seconds = std::env::var("CLUSTERFLUX_BROWSER_LOGIN_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_BROWSER_LOGIN_TRANSACTION_TIMEOUT_SECONDS);
    Duration::from_secs(seconds)
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn contains_provider_token_field(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.iter().any(|(key, value)| {
            matches!(
                key.as_str(),
                "access_token" | "refresh_token" | "id_token" | "provider_token" | "oauth_token"
            ) || contains_provider_token_field(value)
        }),
        Value::Array(items) => items.iter().any(contains_provider_token_field),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn browser_login_polling_interval_is_proxy_compatible() {
        assert!(BROWSER_LOGIN_POLL_INTERVAL >= Duration::from_secs(2));
    }

    #[test]
    fn browser_login_allows_query_bearing_loopback_authorization_urls_only() {
        assert!(authorization_url_is_loopback_http(
            "http://127.0.0.1:8123/application/o/authorize/?state=fixture"
        ));
        assert!(authorization_url_is_loopback_http(
            "http://localhost:8123/authorize?state=fixture"
        ));
        assert!(authorization_url_is_loopback_http(
            "http://[::1]:8123/authorize?state=fixture"
        ));
        assert!(!authorization_url_is_loopback_http(
            "http://example.test/authorize?state=fixture"
        ));
        assert!(!authorization_url_is_loopback_http(
            "http://127.0.0.1.example.test/authorize?state=fixture"
        ));
        assert!(!authorization_url_is_loopback_http(
            "http://operator@127.0.0.1:8123/authorize?state=fixture"
        ));
        assert!(!authorization_url_is_loopback_http(
            "http://127.0.0.1:8123/authorize?state=fixture#fragment"
        ));
    }
}
