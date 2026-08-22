mod release;
mod tasks;

use clusterflux::prelude::*;
use release::{PublicationResult, PublishInput, publish};
use tasks::{
    BuildReleaseInput, CacheNixInput, TestInput, build_release_assets, cache_nix_package,
    test_public_repo,
};

#[clusterflux::main]
pub async fn main() -> Result<Option<PublicationResult>> {
    let trigger = trigger::current().await?;
    let source = trigger.source.clone();

    clusterflux::spawn!(test_public_repo(TestInput {
        source: source.clone(),
        commit_sha: trigger.commit_sha.clone(),
    }))
    .on(clusterflux::env!("release-build"))
    .await?
    .join()
    .await?;

    // Non-release refs still get the full test gate, but never receive the
    // publication secret or spend node time building distributable packages.
    if !trigger.trusted || !publishable_ref(&trigger.git_ref) {
        return Ok(None);
    }

    let assets = clusterflux::spawn!(build_release_assets(BuildReleaseInput {
        source: source.clone(),
        commit_sha: trigger.commit_sha.clone(),
        git_ref: trigger.git_ref.clone(),
    }))
    .on(clusterflux::env!("release-build"))
    .await?
    .join()
    .await?;

    if stable_release_ref(&trigger.git_ref) {
        clusterflux::spawn!(cache_nix_package(CacheNixInput {
            source,
            commit_sha: trigger.commit_sha.clone(),
            tag: assets.tag.clone(),
        }))
        .on(clusterflux::env!("nix-cache-publish"))
        .secret("cachix-auth-token")
        .await?
        .join()
        .await?;
    }

    let publication = clusterflux::spawn!(publish(PublishInput {
        repository_id: trigger.repository_id,
        commit_sha: trigger.commit_sha,
        git_ref: trigger.git_ref,
        trusted: trigger.trusted,
        assets,
    }))
    .on(clusterflux::env!("github-publish"))
    .secret("github-release")
    .await?
    .join()
    .await?;

    Ok(Some(publication))
}

fn publishable_ref(git_ref: &str) -> bool {
    git_ref == "refs/heads/main" || stable_release_ref(git_ref)
}

fn stable_release_ref(git_ref: &str) -> bool {
    git_ref
        .strip_prefix("refs/tags/v")
        .is_some_and(is_semver_core)
}

fn is_semver_core(value: &str) -> bool {
    let mut parts = value.split('.');
    let valid = (0..3).all(|_| {
        parts
            .next()
            .is_some_and(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    });
    valid && parts.next().is_none()
}
