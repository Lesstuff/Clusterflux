use clusterflux_core::{
    Capability, CommandBackendKind, CommandInvocation, CommandPlan, GuestRuntimeKind,
};

use crate::{BackendError, CommandBackend};

#[derive(Clone, Debug, Default)]
pub struct WindowsCommandDevBackend;

impl CommandBackend for WindowsCommandDevBackend {
    fn kind(&self) -> CommandBackendKind {
        CommandBackendKind::WindowsCommandDev
    }

    fn plan(&self, _invocation: &CommandInvocation) -> Result<CommandPlan, BackendError> {
        Ok(CommandPlan {
            guest_runtime: GuestRuntimeKind::Wasmtime,
            backend: CommandBackendKind::WindowsCommandDev,
            required_capability: Capability::WindowsCommandDev,
            user_attached_development_execution: true,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct WindowsSandboxStubBackend;

impl CommandBackend for WindowsSandboxStubBackend {
    fn kind(&self) -> CommandBackendKind {
        CommandBackendKind::StubbedWindowsSandbox
    }

    fn plan(&self, _invocation: &CommandInvocation) -> Result<CommandPlan, BackendError> {
        Err(BackendError::Denied(
            "Windows sandbox backend is an explicit stub for MVP; use windows-command-dev only for user-attached development execution"
                .to_owned(),
        ))
    }
}
