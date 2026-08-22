use std::time::Duration;

use clusterflux::prelude::*;
use clusterflux::serde::{Deserialize, Serialize};

pub const ARCHIVE_NAME: &str = "clusterflux-linux-x86_64.tar.gz";
pub const DEB_NAME: &str = "clusterflux-linux-amd64.deb";
pub const RPM_NAME: &str = "clusterflux-linux-x86_64.rpm";
pub const VSIX_NAME: &str = "clusterflux-vscode.vsix";
pub const INSTALLER_NAME: &str = "install.sh";
pub const CHECKSUMS_NAME: &str = "SHA256SUMS";

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct TestInput {
    pub source: SourceSnapshot,
    pub commit_sha: String,
}

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct BuildReleaseInput {
    pub source: SourceSnapshot,
    pub commit_sha: String,
    pub git_ref: String,
}

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct CacheNixInput {
    pub source: SourceSnapshot,
    pub commit_sha: String,
    pub tag: String,
}

#[derive(Clone, Serialize, Deserialize, clusterflux::TaskArg)]
#[serde(crate = "clusterflux::serde")]
pub struct ReleaseAssets {
    pub version: String,
    pub tag: String,
    pub prerelease: bool,
    pub archive: Artifact,
    pub deb: Artifact,
    pub rpm: Artifact,
    pub vscode: Artifact,
    pub installer: Artifact,
    pub checksums: Artifact,
}

#[clusterflux::task(capabilities = "command,network,source_filesystem,source_git,vfs_artifacts")]
pub async fn test_public_repo(input: TestInput) -> Result<()> {
    let root = input.source.mount()?;
    Command::new("sh")
        .args([
            "-eu",
            "-c",
            TEST_SCRIPT,
            "clusterflux-test",
            input.commit_sha.as_str(),
        ])
        .cwd(root)
        .env("CARGO_TARGET_DIR", "/tmp/clusterflux-test-target")
        .network_enabled()
        .timeout(Duration::from_secs(45 * 60))
        .run()
        .await?;
    Ok(())
}

#[clusterflux::task(capabilities = "command,network,source_filesystem,source_git,vfs_artifacts")]
pub async fn build_release_assets(input: BuildReleaseInput) -> Result<ReleaseAssets> {
    let root = input.source.mount()?;
    let archive = fs::output(ARCHIVE_NAME)?;
    let deb = fs::output(DEB_NAME)?;
    let rpm = fs::output(RPM_NAME)?;
    let vscode = fs::output(VSIX_NAME)?;
    let installer = fs::output(INSTALLER_NAME)?;
    let checksums = fs::output(CHECKSUMS_NAME)?;

    let output = Command::new("sh")
        .args([
            "packaging/build-release-assets.sh",
            input.commit_sha.as_str(),
            input.git_ref.as_str(),
            archive.as_str(),
            deb.as_str(),
            rpm.as_str(),
            vscode.as_str(),
            installer.as_str(),
            checksums.as_str(),
        ])
        .cwd(root)
        .env("CARGO_TARGET_DIR", "/tmp/clusterflux-release-target")
        .network_enabled()
        .timeout(Duration::from_secs(60 * 60))
        .run()
        .await?;

    let version = result_field(&output.stdout, "VERSION=")?;
    let tag = result_field(&output.stdout, "TAG=")?;
    let prerelease = match result_field(&output.stdout, "PRERELEASE=")?.as_str() {
        "true" => true,
        "false" => false,
        _ => {
            return Err(clusterflux::Error::Protocol(
                "release builder emitted invalid PRERELEASE result".to_owned(),
            ));
        }
    };

    Ok(ReleaseAssets {
        version,
        tag,
        prerelease,
        archive: fs::publish(&archive).await?,
        deb: fs::publish(&deb).await?,
        rpm: fs::publish(&rpm).await?,
        vscode: fs::publish(&vscode).await?,
        installer: fs::publish(&installer).await?,
        checksums: fs::publish(&checksums).await?,
    })
}

#[clusterflux::task(capabilities = "command,network,secrets,source_filesystem,source_git")]
pub async fn cache_nix_package(input: CacheNixInput) -> Result<()> {
    let root = input.source.mount()?;
    Command::new("sh")
        .args([
            "-eu",
            "-c",
            CACHE_NIX_SCRIPT,
            "clusterflux-cache",
            input.commit_sha.as_str(),
            input.tag.as_str(),
        ])
        .cwd(root)
        .secret_env("CACHIX_AUTH_TOKEN", "cachix-auth-token")
        .network_enabled()
        .timeout(Duration::from_secs(60 * 60))
        .run()
        .await?;
    Ok(())
}

fn result_field(stdout: &str, prefix: &str) -> Result<String> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            clusterflux::Error::Protocol(format!("release builder omitted result field {prefix}"))
        })
}

const TEST_SCRIPT: &str = r#"
test "$(git rev-parse HEAD)" = "$1"
test ! -e private
test ! -e internal
test ! -e web
test ! -e .forgejo
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
rm -rf /tmp/clusterflux-vscode-test
cp -a vscode-extension /tmp/clusterflux-vscode-test
cd /tmp/clusterflux-vscode-test
npm ci --ignore-scripts --no-audit --no-fund
node --check extension.js
"#;

const CACHE_NIX_SCRIPT: &str = r#"
test "$(git rev-parse HEAD)" = "$1"
case "$2" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "Cachix publication requires a stable version tag" >&2; exit 1 ;;
esac
output=$(nix build --accept-flake-config --no-link --print-out-paths .#clusterflux-tools)
case "$output" in
  /nix/store/*-clusterflux-tools-*) ;;
  *) echo "Nix build returned an unexpected Clusterflux output path" >&2; exit 1 ;;
esac
printf '%s\n' "$output" | cachix push clusterflux
cachix pin clusterflux stable "$output" --keep-revisions 2
"#;
