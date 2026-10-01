use crate::{
    api::{Api, Response},
    discovery::Repository,
};
use anyhow::{Context, Result, bail};
use futures::{StreamExt, TryStreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

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
        let (owner, name) = repo
            .name_with_owner
            .split_once('/')
            .context("invalid repository name")?;
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
) -> Result<(Vec<Match>, Vec<String>)> {
    let mut skipped = BTreeSet::new();
    let mut warnings = Vec::new();
    for error in response.errors {
        let alias = error.path.first().and_then(|p| p.as_str());
        let index = alias
            .and_then(|a| a.strip_prefix('r'))
            .and_then(|i| i.parse::<usize>().ok());
        // Only explicitly repository-scoped permission/unavailable errors are safe to skip.
        let Some(index) = index.filter(|i| *i < repos.len()) else {
            bail!("GitHub GraphQL: {}", error.message);
        };
        if !error.skippable() {
            bail!(
                "GitHub GraphQL for {}: {}",
                repos[index].name_with_owner,
                error.message
            );
        }
        skipped.insert(index);
        warnings.push(format!(
            "skipping {}: {}",
            repos[index].name_with_owner, error.message
        ));
    }
    let data = response.data.context("GitHub returned no batch data")?;
    let mut matches = Vec::new();
    for (i, repo) in repos.iter().enumerate() {
        if skipped.contains(&i) {
            continue;
        }
        let entry = data
            .get(&format!("r{i}"))
            .context("GitHub batch response is missing an alias")?;
        match entry {
            Some(checked) => match &checked.vulnerability_alerts {
                Some(alerts) if alerts.total_count > 0 => matches.push(Match {
                    name_with_owner: checked.name_with_owner.clone(),
                    open_alerts: alerts.total_count,
                }),
                Some(_) => {}
                None => warnings.push(format!(
                    "skipping {}: vulnerability alerts unavailable",
                    repo.name_with_owner
                )),
            },
            None => warnings.push(format!(
                "skipping {}: repository no longer accessible",
                repo.name_with_owner
            )),
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
        Ok::<_, anyhow::Error>(matches)
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
    }
    #[test]
    fn unexpected_and_global_errors_fail() {
        for error in [
            json!({"type":"INTERNAL","message":"oops","path":["r1"]}),
            json!({"type":"FORBIDDEN","message":"bad token"}),
            json!({"type":"RATE_LIMITED","message":"rate limit","path":["r0"]}),
        ] {
            assert!(interpret(parse(json!({"data":{},"errors":[error]})), &repos()).is_err());
        }
        assert!(interpret(parse(json!({"data":{}})), &repos()).is_err());
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
    }
}
