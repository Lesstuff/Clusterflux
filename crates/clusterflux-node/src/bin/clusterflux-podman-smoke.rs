use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{
    CommandInvocation, Digest, EnvironmentKind, EnvironmentRequirements, EnvironmentResource,
    NodeId, ProcessId, TaskInstanceId, VfsOverlay, VfsPath,
};
use clusterflux_node::{
    LinuxRootlessPodmanBackend, LocalCheckoutTaskRequest, LocalSourceCheckout, StdProcessRunner,
};
use serde_json::json;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let workspace = create_workspace()?;
    let env_dir = workspace.join("envs/linux");
    fs::create_dir_all(&env_dir)?;
    fs::write(
        env_dir.join("Containerfile"),
        "FROM docker.io/library/alpine:3.20\nWORKDIR /workspace\n",
    )?;
    fs::write(workspace.join("input.txt"), "node-local source\n")?;

    let env = EnvironmentResource {
        name: "linux".to_owned(),
        kind: EnvironmentKind::Containerfile,
        recipe_path: env_dir.join("Containerfile"),
        context_path: env_dir,
        context_manifest: Vec::new(),
        context_manifest_digest: Digest::from_parts([b"environment-context:v1"]),
        digest: Digest::sha256("phase2-podman-smoke-linux-env"),
        requirements: EnvironmentRequirements::linux_container(),
    };
    let invocation = CommandInvocation {
        program: "sh".to_owned(),
        args: vec![
            "-c".to_owned(),
            "printf 'podman-ok:' && cat input.txt".to_owned(),
        ],
        working_directory: "/workspace".to_owned(),
        environment_variables: Default::default(),
        timeout_ms: 60_000,
        network: clusterflux_core::CommandNetworkPolicy::Disabled,
        env: Some(env),
    };
    let checkout = LocalSourceCheckout {
        host_path: workspace.clone(),
        snapshot: Digest::sha256("phase2-podman-smoke-checkout"),
    };
    let task = TaskInstanceId::from("podman-smoke");
    let output_root = workspace.join("task-output");
    fs::create_dir_all(&output_root)?;
    let mut overlay = VfsOverlay::new(task.clone(), NodeId::from("node-podman-smoke"));
    let mut runner = StdProcessRunner;
    let output = LinuxRootlessPodmanBackend.execute_local_checkout_task(
        LocalCheckoutTaskRequest {
            process: ProcessId::from("vp-podman-smoke"),
            virtual_thread: task,
            invocation: &invocation,
            checkout,
            output_root,
            stage_stdout_as: Some(VfsPath::new("/vfs/artifacts/podman-smoke.txt")?),
            system_package_dir: None,
            run_policy: Default::default(),
        },
        &mut runner,
        &mut overlay,
    )?;
    let manifest = overlay.flush();

    println!(
        "{}",
        serde_json::to_string(&json!({
            "podman_status": "completed",
            "status_code": output.status_code,
            "stdout": output.stdout,
            "stderr": output.stderr,
            "staged_artifact": output.staged_artifact,
            "large_bytes_uploaded": manifest.large_bytes_uploaded,
            "uses_full_repo_tarball": false,
            "coordinator_routed_file_reads": false,
        }))?
    );
    let _ = fs::remove_dir_all(workspace);
    Ok(())
}

fn create_workspace() -> Result<PathBuf, std::io::Error> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let workspace = std::env::temp_dir().join(format!(
        "clusterflux-podman-smoke-{}-{nanos}",
        std::process::id()
    ));
    fs::create_dir_all(&workspace)?;
    Ok(workspace)
}
