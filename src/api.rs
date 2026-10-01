use anyhow::{Context, Result, bail};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct Response<T> {
    pub data: Option<T>,
    #[serde(default)]
    pub errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize)]
pub struct GraphqlError {
    pub message: String,
    #[serde(default)]
    pub path: Vec<Value>,
    #[serde(rename = "type")]
    pub kind: Option<String>,
}

impl GraphqlError {
    pub fn skippable(&self) -> bool {
        matches!(self.kind.as_deref(), Some("FORBIDDEN" | "NOT_FOUND"))
            || (self.kind.as_deref() == Some("UNPROCESSABLE")
                && self
                    .message
                    .to_ascii_lowercase()
                    .contains("vulnerability alerts"))
    }
}

pub struct Api {
    client: Client,
}

pub fn retryable(status: StatusCode) -> bool {
    matches!(status.as_u16(), 502..=504)
}

impl Api {
    pub async fn authenticated() -> Result<Self> {
        let output = tokio::process::Command::new("gh")
            .args(["auth", "token", "--hostname", "github.com"])
            .output()
            .await
            .context("could not run gh auth token; install GitHub CLI and run gh auth login")?;
        if !output.status.success() {
            bail!(
                "gh auth token failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let token = String::from_utf8(output.stdout).context("gh returned an invalid token")?;
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {}", token.trim()))
                .context("gh returned an invalid token header")?;
        authorization.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        let client = Client::builder()
            .default_headers(headers)
            .user_agent("gh-dependabot-repos")
            .timeout(Duration::from_secs(60))
            .build()?;
        Ok(Self { client })
    }

    pub async fn query<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: Value,
    ) -> Result<Response<T>> {
        for attempt in 0..4 {
            let result = self
                .client
                .post("https://api.github.com/graphql")
                .json(&serde_json::json!({"query": query, "variables": variables}))
                .send()
                .await;
            let response = match result {
                Ok(response) => response,
                Err(error) if attempt < 3 && (error.is_timeout() || error.is_connect()) => {
                    eprintln!("warning: transient network error; retry {}/3", attempt + 1);
                    backoff(attempt).await;
                    continue;
                }
                Err(error) => return Err(error).context("GitHub GraphQL request failed"),
            };
            let status = response.status();
            if retryable(status) && attempt < 3 {
                eprintln!(
                    "warning: GitHub returned HTTP {status}; retry {}/3",
                    attempt + 1
                );
                backoff(attempt).await;
                continue;
            }
            if !status.is_success() {
                let body = response
                    .text()
                    .await
                    .context("reading GitHub error response")?;
                bail!(
                    "GitHub GraphQL HTTP {status}: {}",
                    body.chars().take(2000).collect::<String>()
                );
            }
            return response
                .json()
                .await
                .context("invalid GitHub GraphQL response");
        }
        unreachable!()
    }

    pub async fn strict<T: DeserializeOwned>(&self, query: &str, variables: Value) -> Result<T> {
        let response: Response<T> = self.query(query, variables).await?;
        if !response.errors.is_empty() {
            bail!(
                "GitHub GraphQL: {}",
                response
                    .errors
                    .iter()
                    .map(|e| e.message.as_str())
                    .collect::<Vec<_>>()
                    .join("; ")
            );
        }
        response.data.context("GitHub returned no GraphQL data")
    }
}

async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retry_classification() {
        for code in [502, 503, 504] {
            assert!(retryable(StatusCode::from_u16(code).unwrap()));
        }
        for code in [200, 400, 401, 403, 404, 429, 500] {
            assert!(!retryable(StatusCode::from_u16(code).unwrap()));
        }
    }
}
