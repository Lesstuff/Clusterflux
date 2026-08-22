use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_protocol::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse,
};
use serde_json::{json, Value};

use crate::client::JsonLineSession;
use crate::config::StoredCliSession;
use crate::{
    RunCancelArgs, RunListArgs, RunShowArgs, SecretListArgs, SecretRevokeArgs, SecretSetArgs,
};

pub(crate) fn run_list_report(args: RunListArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::ListAutomatedRuns {
            cursor: None,
            limit: 64,
        },
    })? {
        CoordinatorResponse::AutomatedRuns { runs, actor, .. } => Ok(json!({
            "command": "runs list",
            "coordinator": coordinator,
            "actor": actor,
            "runs": runs,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected runs list response: {response:?}"),
    }
}

pub(crate) fn run_show_report(args: RunShowArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::GetAutomatedRun {
            run: args.run.to_string(),
        },
    })? {
        CoordinatorResponse::AutomatedRun { run, actor } => Ok(json!({
            "command": "runs show",
            "coordinator": coordinator,
            "actor": actor,
            "run": run,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected runs show response: {response:?}"),
    }
}

pub(crate) fn run_cancel_report(args: RunCancelArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::CancelAutomatedRun {
            run: args.run.to_string(),
        },
    })? {
        CoordinatorResponse::AutomatedRun { run, actor } => Ok(json!({
            "command": "runs cancel",
            "coordinator": coordinator,
            "actor": actor,
            "run": run,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected runs cancel response: {response:?}"),
    }
}

pub(crate) fn secret_set_report(args: SecretSetArgs, cwd: &Path) -> Result<Value> {
    if !args.stdin {
        anyhow::bail!("secret set requires --stdin; values are never accepted as arguments");
    }
    let mut value = Vec::new();
    std::io::stdin()
        .take((16 * 1024 + 1) as u64)
        .read_to_end(&mut value)
        .context("read project secret from stdin")?;
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        value.pop();
    }
    if value.len() < 16 || value.len() > 16 * 1024 {
        anyhow::bail!("project secret must contain 16 through 16384 bytes");
    }
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::SetProjectSecret {
            name: args.name,
            value_base64: BASE64_STANDARD.encode(value),
        },
    })? {
        CoordinatorResponse::ProjectSecretSet { secret, actor } => Ok(json!({
            "command": "secret set",
            "coordinator": coordinator,
            "actor": actor,
            "secret": secret,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected secret set response: {response:?}"),
    }
}

pub(crate) fn secret_list_report(args: SecretListArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::ListProjectSecrets,
    })? {
        CoordinatorResponse::ProjectSecrets { secrets, actor } => Ok(json!({
            "command": "secret list",
            "coordinator": coordinator,
            "actor": actor,
            "secrets": secrets,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected secret list response: {response:?}"),
    }
}

pub(crate) fn secret_revoke_report(args: SecretRevokeArgs, cwd: &Path) -> Result<Value> {
    let stored = crate::config::read_cli_session(cwd)?;
    let (coordinator, secret) = session_authority(&args.scope.coordinator, stored.as_ref())?;
    let mut session = JsonLineSession::connect(&coordinator)?;
    match session.request_typed(CoordinatorRequest::Authenticated {
        session_secret: secret,
        request: AuthenticatedCoordinatorRequest::RevokeProjectSecret { name: args.name },
    })? {
        CoordinatorResponse::ProjectSecretRevoked { secret, actor } => Ok(json!({
            "command": "secret revoke",
            "coordinator": coordinator,
            "actor": actor,
            "secret": secret,
            "coordinator_session_requests": session.requests(),
        })),
        response => anyhow::bail!("unexpected secret revoke response: {response:?}"),
    }
}

fn session_authority(
    configured: &Option<String>,
    stored: Option<&StoredCliSession>,
) -> Result<(String, String)> {
    let coordinator = configured
        .clone()
        .or_else(|| stored.map(|session| session.coordinator.clone()))
        .ok_or_else(|| anyhow::anyhow!("no coordinator is configured"))?;
    let session = stored
        .filter(|session| session.coordinator == coordinator)
        .and_then(|session| session.session_secret.clone())
        .ok_or_else(|| anyhow::anyhow!("no authenticated session matches {coordinator}"))?;
    Ok((coordinator, session))
}
