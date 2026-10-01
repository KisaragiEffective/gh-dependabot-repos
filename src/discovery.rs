use crate::api::Api;
use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt, stream};
use graphql_query_macro::validate_given_graphql;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Repository {
    pub name_with_owner: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PageInfo {
    has_next_page: bool,
    end_cursor: Option<String>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Connection<T> {
    nodes: Vec<Option<T>>,
    page_info: PageInfo,
}
#[derive(Deserialize)]
struct Owner {
    repositories: Connection<Repository>,
}
#[derive(Deserialize)]
struct UserRepos {
    viewer: Owner,
}
#[derive(Deserialize)]
struct OrgRepos {
    organization: Option<Owner>,
}
#[derive(Deserialize)]
struct Organization {
    login: String,
}
#[derive(Deserialize)]
struct Memberships {
    organizations: Connection<Organization>,
}
#[derive(Deserialize)]
struct Orgs {
    viewer: Memberships,
}

const USER_REPOS: &str = validate_given_graphql!(include_str!("query/user_repos.graphql"));
const ORGS: &str = validate_given_graphql!(include_str!("query/orgs.graphql"));
const ORG_REPOS: &str = validate_given_graphql!(include_str!("query/org_repos.graphql"));

fn advance(page: PageInfo, previous: &Option<String>) -> Result<Option<String>> {
    if !page.has_next_page {
        return Ok(None);
    }
    let next = page
        .end_cursor
        .context("paginated connection has no endCursor")?;
    if previous.as_ref() == Some(&next) {
        bail!("GitHub returned a non-advancing pagination cursor");
    }
    Ok(Some(next))
}

async fn repositories(api: &Api, org: Option<&str>) -> Result<Vec<Repository>> {
    let mut cursor = None;
    let mut repos = Vec::new();
    loop {
        let connection = if let Some(login) = org {
            let data: OrgRepos = api
                .strict(ORG_REPOS, json!({"login":login,"cursor":cursor}))
                .await
                .with_context(|| format!("discovering repositories for {login}"))?;
            data.organization
                .context("organization became unavailable during discovery")?
                .repositories
        } else {
            let data: UserRepos = api.strict(USER_REPOS, json!({"cursor":cursor})).await?;
            data.viewer.repositories
        };
        for node in connection.nodes {
            repos.push(node.context("null repository in discovery response")?);
        }
        cursor = advance(connection.page_info, &cursor)?;
        if cursor.is_none() {
            break;
        }
    }
    Ok(repos)
}

pub fn deduplicate(repos: Vec<Repository>) -> Vec<Repository> {
    repos
        .into_iter()
        .map(|r| (r.name_with_owner.to_ascii_lowercase(), r))
        .collect::<BTreeMap<_, _>>()
        .into_values()
        .collect()
}

pub async fn discover(api: &Api, concurrency: usize) -> Result<Vec<Repository>> {
    let mut repos = repositories(api, None).await?;
    let mut organizations = Vec::new();
    let mut cursor = None;
    loop {
        let data: Orgs = api.strict(ORGS, json!({"cursor":cursor})).await?;
        for node in data.viewer.organizations.nodes {
            organizations.push(
                node.context("null organization in discovery response")?
                    .login,
            );
        }
        cursor = advance(data.viewer.organizations.page_info, &cursor)?;
        if cursor.is_none() {
            break;
        }
    }
    let pages: Vec<Vec<Repository>> =
        stream::iter(organizations.iter().map(|org| repositories(api, Some(org))))
            .buffer_unordered(concurrency)
            .try_collect()
            .await?;
    repos.extend(pages.into_iter().flatten());
    Ok(deduplicate(repos))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unique_repositories() {
        let repos = ["a/b", "c/d", "a/b", "A/B"].map(|s| Repository {
            name_with_owner: s.into(),
        });
        assert_eq!(deduplicate(repos.to_vec()).len(), 2);
    }
    #[test]
    fn pagination_requires_progress() {
        assert!(
            advance(
                PageInfo {
                    has_next_page: true,
                    end_cursor: None
                },
                &None
            )
            .is_err()
        );
        assert!(
            advance(
                PageInfo {
                    has_next_page: true,
                    end_cursor: Some("x".into())
                },
                &Some("x".into())
            )
            .is_err()
        );
        assert_eq!(
            advance(
                PageInfo {
                    has_next_page: true,
                    end_cursor: Some("y".into())
                },
                &Some("x".into())
            )
            .unwrap(),
            Some("y".into())
        );
        assert!(
            advance(
                PageInfo {
                    has_next_page: false,
                    end_cursor: Some("x".into())
                },
                &None
            )
            .unwrap()
            .is_none()
        );
    }
}
