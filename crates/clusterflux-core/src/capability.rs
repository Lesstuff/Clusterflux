use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    Command,
    Containers,
    RootlessPodman,
    SourceFilesystem,
    SourceGit,
    HostFilesystem,
    Network,
    Secrets,
    InboundPorts,
    ArbitrarySyscalls,
    VfsArtifacts,
    ArtifactTransfer,
    WindowsCommandDev,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeWorkPolicy {
    #[default]
    Normal,
    ExecutionOnly,
    SystemTasksOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemTaskSandbox {
    RootlessPodman,
    Gvisor,
    DedicatedVm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemBundleCapability {
    pub bundle_id: String,
    pub bundle_digest: crate::Digest,
    pub sdk_abi_version: u32,
    pub wasm_target: String,
    pub rust_toolchain: String,
    pub environment_digest: crate::Digest,
    pub sandbox: SystemTaskSandbox,
    pub max_source_bytes: usize,
    pub max_output_bytes: usize,
    pub max_concurrent_assignments: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnvironmentBackend {
    Container,
    NixFlake,
    WindowsCommandDev,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Os {
    Linux,
    Windows,
    Macos,
    Other(String),
}

impl Os {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "windows" => Self::Windows,
            "macos" => Self::Macos,
            other => Self::Other(other.to_owned()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub os: Os,
    pub arch: String,
    pub capabilities: BTreeSet<Capability>,
    pub environment_backends: BTreeSet<EnvironmentBackend>,
    pub source_providers: BTreeSet<String>,
    #[serde(default)]
    pub work_policy: NodeWorkPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_bundles: Vec<SystemBundleCapability>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CapabilityReportError {
    #[error("node architecture `{0}` is invalid")]
    InvalidArchitecture(String),
    #[error("node OS label `{0}` is invalid")]
    InvalidOsLabel(String),
    #[error("source provider id `{0}` is invalid")]
    InvalidSourceProvider(String),
    #[error("system bundle capability is invalid: {0}")]
    InvalidSystemBundle(String),
}

impl NodeCapabilities {
    pub fn detect_current() -> Self {
        let os = Os::current();
        let mut capabilities = BTreeSet::from([
            Capability::Command,
            Capability::SourceFilesystem,
            Capability::SourceGit,
            Capability::VfsArtifacts,
            Capability::ArtifactTransfer,
        ]);
        let mut environment_backends = BTreeSet::new();

        match os {
            Os::Linux => {
                if rootless_podman_available() {
                    capabilities.insert(Capability::Containers);
                    capabilities.insert(Capability::RootlessPodman);
                    environment_backends.insert(EnvironmentBackend::Container);
                }
            }
            Os::Windows => {
                capabilities.insert(Capability::WindowsCommandDev);
                environment_backends.insert(EnvironmentBackend::WindowsCommandDev);
            }
            Os::Macos | Os::Other(_) => {}
        }

        Self {
            os,
            arch: std::env::consts::ARCH.to_owned(),
            capabilities,
            environment_backends,
            source_providers: BTreeSet::from(["filesystem".to_owned(), "git".to_owned()]),
            work_policy: NodeWorkPolicy::Normal,
            system_bundles: Vec::new(),
        }
    }

    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    pub fn has_all(&self, required: &BTreeSet<Capability>) -> bool {
        required
            .iter()
            .all(|capability| self.capabilities.contains(capability))
    }

    pub fn validate_public_report(&self) -> Result<(), CapabilityReportError> {
        if !valid_capability_label(&self.arch) {
            return Err(CapabilityReportError::InvalidArchitecture(
                self.arch.clone(),
            ));
        }
        if let Os::Other(label) = &self.os {
            if !valid_capability_label(label) {
                return Err(CapabilityReportError::InvalidOsLabel(label.clone()));
            }
        }
        for provider in &self.source_providers {
            if !valid_source_provider_id(provider) {
                return Err(CapabilityReportError::InvalidSourceProvider(
                    provider.clone(),
                ));
            }
        }
        for profile in &self.system_bundles {
            if !valid_capability_label(&profile.bundle_id)
                || !profile.bundle_digest.is_valid_sha256()
                || profile.sdk_abi_version == 0
                || profile.wasm_target != "wasm32-unknown-unknown"
                || profile.rust_toolchain.trim().is_empty()
                || !profile.environment_digest.is_valid_sha256()
                || profile.max_source_bytes == 0
                || profile.max_output_bytes == 0
                || profile.max_concurrent_assignments == 0
            {
                return Err(CapabilityReportError::InvalidSystemBundle(
                    "metadata or limits are invalid".to_owned(),
                ));
            }
        }
        let identities = self
            .system_bundles
            .iter()
            .map(|profile| (&profile.bundle_id, &profile.bundle_digest))
            .collect::<BTreeSet<_>>();
        if identities.len() != self.system_bundles.len() {
            return Err(CapabilityReportError::InvalidSystemBundle(
                "duplicate system bundle identity".to_owned(),
            ));
        }
        Ok(())
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn rootless_podman_available() -> bool {
    const ATTEMPTS: usize = 3;
    for attempt in 0..ATTEMPTS {
        match std::process::Command::new("podman")
            .args(["info", "--format", "{{.Host.Security.Rootless}}"])
            .output()
        {
            Ok(output) if rootless_podman_probe_succeeded(&output) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            Ok(_) | Err(_) if attempt + 1 < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Ok(_) | Err(_) => {}
        }
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn rootless_podman_probe_succeeded(output: &std::process::Output) -> bool {
    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
}

#[cfg(target_arch = "wasm32")]
fn rootless_podman_available() -> bool {
    false
}

fn valid_capability_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.'),
        )
}

fn valid_source_provider_id(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 64
        && provider
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> NodeCapabilities {
        NodeCapabilities {
            os: Os::Linux,
            arch: "x86_64".to_owned(),
            capabilities: BTreeSet::from([Capability::Command]),
            environment_backends: BTreeSet::new(),
            source_providers: BTreeSet::from(["filesystem".to_owned(), "git".to_owned()]),
            work_policy: NodeWorkPolicy::Normal,
            system_bundles: Vec::new(),
        }
    }

    #[test]
    fn capability_reports_validate_hostile_strings() {
        assert!(capabilities().validate_public_report().is_ok());

        let mut invalid_arch = capabilities();
        invalid_arch.arch = "x86_64\nmalicious".to_owned();
        assert_eq!(
            invalid_arch.validate_public_report(),
            Err(CapabilityReportError::InvalidArchitecture(
                "x86_64\nmalicious".to_owned()
            ))
        );

        let mut invalid_provider = capabilities();
        invalid_provider
            .source_providers
            .insert("../checkout".to_owned());
        assert_eq!(
            invalid_provider.validate_public_report(),
            Err(CapabilityReportError::InvalidSourceProvider(
                "../checkout".to_owned()
            ))
        );
    }
}
