use std::collections::BTreeSet;
use std::path::PathBuf;

use clap::Parser;
use clusterflux_node::{LinuxRootlessPodmanBackend, StdProcessRunner};
use serde::Serialize;

#[derive(Parser)]
#[command(
    name = "clusterflux-environment-setup",
    version,
    about = "Prebuild immutable Clusterflux task environments"
)]
struct Args {
    #[arg(long, value_name = "PATH")]
    project_root: PathBuf,
    #[arg(long = "name", value_name = "ENVIRONMENT")]
    names: Vec<String>,
}

#[derive(Serialize)]
struct MaterializedRecord {
    name: String,
    definition_digest: clusterflux_core::Digest,
    local_image: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let selected = args.names.into_iter().collect::<BTreeSet<_>>();
    let environments = clusterflux_core::discover_environments(&args.project_root)?;
    let discovered = environments
        .iter()
        .map(|environment| environment.name.as_str())
        .collect::<BTreeSet<_>>();
    if let Some(missing) = selected
        .iter()
        .find(|name| !discovered.contains(name.as_str()))
    {
        return Err(format!(
            "environment `{missing}` was not discovered under {}/envs",
            args.project_root.display()
        )
        .into());
    }
    let mut records = Vec::new();
    let mut runner = StdProcessRunner;
    for environment in environments
        .into_iter()
        .filter(|environment| selected.is_empty() || selected.contains(&environment.name))
    {
        let materialized = LinuxRootlessPodmanBackend
            .execute_environment_materialization(&environment, &mut runner)?;
        records.push(MaterializedRecord {
            name: environment.name,
            definition_digest: environment.digest,
            local_image: materialized.local_reference,
        });
    }
    if records.is_empty() {
        return Err("no task environments were selected".into());
    }
    println!("{}", serde_json::to_string_pretty(&records)?);
    Ok(())
}
