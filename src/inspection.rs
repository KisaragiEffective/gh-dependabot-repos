use crate::{
    api::{Api, ApiError, GraphqlError, Response},
    discovery::Repository,
};
use futures::{StreamExt, TryStreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InspectionError {
    #[error(transparent)]
    Api(#[from] ApiError),
    #[error("invalid repository name: {name}")]
    InvalidRepositoryName { name: String },
    #[error("could not serialize GraphQL query arguments: {0}")]
    QuerySerialization(#[from] serde_json::Error),
    #[error("GitHub GraphQL: {source}")]
    GlobalGraphql { source: GraphqlError },
    #[error("GitHub GraphQL for {repository}: {source}")]
    RepositoryGraphql {
        repository: String,
        source: GraphqlError,
    },
    #[error("GitHub returned no batch data")]
    MissingData,
    #[error("GitHub batch response is missing alias {alias}")]
    MissingAlias { alias: String },
}

type Result<T> = std::result::Result<T, InspectionError>;

#[derive(Debug, Error)]
pub enum SkipReason {
    #[error("{0}")]
    Graphql(#[source] GraphqlError),
    #[error("vulnerability alerts unavailable")]
    AlertsUnavailable,
    #[error("repository no longer accessible")]
    RepositoryUnavailable,
}

#[derive(Debug, Error)]
#[error("skipping {repository}: {reason}")]
pub struct SkippedRepository {
    pub repository: String,
    #[source]
    pub reason: SkipReason,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckedRepository {
    name_with_owner: String,
    vulnerability_alerts: Option<Alerts>,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Alerts {
    total_count: u64,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Match {
    pub name_with_owner: String,
    pub open_alerts: u64,
}
type BatchData = BTreeMap<String, Option<CheckedRepository>>;

pub fn batch_query(repos: &[Repository]) -> Result<String> {
    let mut query = String::from("query {\n");
    for (i, repo) in repos.iter().enumerate() {
        let (owner, name) = repo.name_with_owner.split_once('/').ok_or_else(|| {
            InspectionError::InvalidRepositoryName {
                name: repo.name_with_owner.clone(),
            }
        })?;
        // JSON string literals are also valid GraphQL string literals.
        query.push_str(&format!("r{i}: repository(owner: {}, name: {}) {{ nameWithOwner vulnerabilityAlerts(first: 1, states: OPEN) {{ totalCount }} }}\n",
            serde_json::to_string(owner)?, serde_json::to_string(name)?));
    }
    query.push('}');
    Ok(query)
}

pub fn interpret(
    response: Response<BatchData>,
    repos: &[Repository],
) -> Result<(Vec<Match>, Vec<SkippedRepository>)> {
    let mut skipped = BTreeSet::new();
    let mut warnings = Vec::new();
    for error in response.errors {
        let alias = error.path.first().and_then(|p| p.as_str());
        let index = alias
            .and_then(|a| a.strip_prefix('r'))
            .and_then(|i| i.parse::<usize>().ok());
        // Only explicitly repository-scoped permission/unavailable errors are safe to skip.
        let Some(index) = index.filter(|i| *i < repos.len()) else {
            return Err(InspectionError::GlobalGraphql { source: error });
        };
        if !error.skippable() {
            return Err(InspectionError::RepositoryGraphql {
                repository: repos[index].name_with_owner.clone(),
                source: error,
            });
        }
        skipped.insert(index);
        warnings.push(SkippedRepository {
            repository: repos[index].name_with_owner.clone(),
            reason: SkipReason::Graphql(error),
        });
    }
    let data = response.data.ok_or(InspectionError::MissingData)?;
    let mut matches = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        if skipped.contains(&i) {
            continue;
        }
        let entry = data
            .get(&format!("r{i}"))
            .ok_or_else(|| InspectionError::MissingAlias {
                alias: format!("r{i}"),
            })?;
        match entry {
            Some(checked) => match &checked.vulnerability_alerts {
                Some(alerts) if alerts.total_count > 0 => matches.push(Match {
                    name_with_owner: checked.name_with_owner.clone(),
                    open_alerts: alerts.total_count,
                }),
                Some(_) => {}
                None => warnings.push(SkippedRepository {
                    repository: repo.name_with_owner.clone(),
                    reason: SkipReason::AlertsUnavailable,
                }),
            },
            None => warnings.push(SkippedRepository {
                repository: repo.name_with_owner.clone(),
                reason: SkipReason::RepositoryUnavailable,
            }),
        }
    }
    Ok((matches, warnings))
}

pub async fn inspect(
    api: &Api,
    repos: &[Repository],
    batch_size: usize,
    concurrency: usize,
) -> Result<Vec<Match>> {
    let batches: Vec<Vec<Match>> = stream::iter(repos.chunks(batch_size).map(|batch| async move {
        let query = batch_query(batch)?;
        let response = api.query(&query, json!({})).await?;
        let (matches, warnings) = interpret(response, batch)?;
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
        Ok::<_, InspectionError>(matches)
    }))
    .buffer_unordered(concurrency)
    .try_collect()
    .await?;
    // A repository may have been renamed/transferred while the run was in progress.
    let mut matches: Vec<_> = batches.into_iter().flatten().collect();
    matches.sort_by_key(|repo| repo.name_with_owner.to_ascii_lowercase());
    matches.dedup_by(|a, b| a.name_with_owner.eq_ignore_ascii_case(&b.name_with_owner));
    matches.sort_by(|a, b| a.name_with_owner.cmp(&b.name_with_owner));
    Ok(matches)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn repos() -> Vec<Repository> {
        ["foo/a", "bar/b"]
            .map(|s| Repository {
                name_with_owner: s.into(),
            })
            .to_vec()
    }
    #[test]
    fn aliases_and_escaping() {
        let query = batch_query(&repos()).unwrap();
        assert!(query.contains("r0: repository(owner: \"foo\", name: \"a\")"));
        assert!(query.contains("r1: repository(owner: \"bar\", name: \"b\")"));
        assert_eq!(query.matches("first: 1, states: OPEN").count(), 2);
        assert!(!query.contains("nodes"));
        let query = batch_query(&[Repository {
            name_with_owner: "foo/a\"b".into(),
        }])
        .unwrap();
        assert!(query.contains("name: \"a\\\"b\""));
    }
    fn parse(value: serde_json::Value) -> Response<BatchData> {
        serde_json::from_value(value).unwrap()
    }
    #[test]
    fn filters_zero_alerts() {
        let (matches, warnings) = interpret(
            parse(json!({"data": {
                "r0":{"nameWithOwner":"foo/a","vulnerabilityAlerts":{"totalCount":3}},
                "r1":{"nameWithOwner":"bar/b","vulnerabilityAlerts":{"totalCount":0}}
            }})),
            &repos(),
        )
        .unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].open_alerts, 3);
        assert!(warnings.is_empty());
    }
    #[test]
    fn partial_permission_error_preserves_success() {
        let (matches, warnings) = interpret(parse(json!({"data": {
            "r0":{"nameWithOwner":"foo/a","vulnerabilityAlerts":{"totalCount":3}},"r1":null
        }, "errors":[{"type":"FORBIDDEN","message":"denied","path":["r1","vulnerabilityAlerts"]}]})), &repos()).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].repository, "bar/b");
        assert!(matches!(&warnings[0].reason, SkipReason::Graphql(error)
            if error.kind.as_deref() == Some("FORBIDDEN") && error.message == "denied"));
    }
    #[test]
    fn unexpected_repository_errors_preserve_repository_and_cause() {
        for (kind, alias, repository) in
            [("INTERNAL", "r1", "bar/b"), ("RATE_LIMITED", "r0", "foo/a")]
        {
            let result = interpret(
                parse(json!({"data":{},"errors":[{
                    "type":kind,"message":"API failure","path":[alias,"vulnerabilityAlerts"]
                }]})),
                &repos(),
            );
            assert!(
                matches!(result, Err(InspectionError::RepositoryGraphql { repository: actual, source })
                if actual == repository && source.kind.as_deref() == Some(kind)
                && source.message == "API failure")
            );
        }
    }

    #[test]
    fn global_errors_are_never_skipped() {
        let result = interpret(
            parse(json!({"data":{},"errors":[{
                "type":"FORBIDDEN","message":"bad token"
            }]})),
            &repos(),
        );
        assert!(
            matches!(result, Err(InspectionError::GlobalGraphql { source })
            if source.message == "bad token" && source.kind.as_deref() == Some("FORBIDDEN"))
        );
    }

    #[test]
    fn missing_data_and_alias_are_distinct() {
        assert!(matches!(
            interpret(parse(json!({"data":null})), &repos()),
            Err(InspectionError::MissingData)
        ));
        assert!(matches!(interpret(parse(json!({"data":{}})), &repos()),
            Err(InspectionError::MissingAlias { alias }) if alias == "r0"));
    }

    #[test]
    fn invalid_repository_name_is_typed() {
        let result = batch_query(&[Repository {
            name_with_owner: "invalid".into(),
        }]);
        assert!(
            matches!(result, Err(InspectionError::InvalidRepositoryName { name }) if name == "invalid")
        );
    }

    #[test]
    fn unavailable_is_reported() {
        let (matches, warnings) = interpret(
            parse(json!({"data": {
                "r0":{"nameWithOwner":"foo/a","vulnerabilityAlerts":null},"r1":null
            }})),
            &repos(),
        )
        .unwrap();
        assert!(matches.is_empty());
        assert_eq!(warnings.len(), 2);
        assert!(matches!(warnings[0].reason, SkipReason::AlertsUnavailable));
        assert!(matches!(
            warnings[1].reason,
            SkipReason::RepositoryUnavailable
        ));
    }
}
