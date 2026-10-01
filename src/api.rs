use anyhow::{Context, Result, bail};
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
    agent: ureq::Agent,
    authorization: String,
}

pub const fn retryable(status: u16) -> bool {
    matches!(status, 502..=504)
}

fn retryable_transport(error: &ureq::Error) -> bool {
    match error {
        ureq::Error::Timeout(_) | ureq::Error::ConnectionFailed | ureq::Error::HostNotFound => true,
        ureq::Error::Io(error) => matches!(
            error.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::UnexpectedEof
                | std::io::ErrorKind::BrokenPipe
        ),
        _ => false,
    }
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
        let authorization = format!("Bearer {}", token.trim());
        let agent = ureq::Agent::config_builder()
            .user_agent("gh-dependabot-repos")
            .timeout_global(Some(Duration::from_secs(60)))
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        Ok(Self {
            agent,
            authorization,
        })
    }

    pub async fn query<T: DeserializeOwned>(
        &self,
        query: &str,
        variables: Value,
    ) -> Result<Response<T>> {
        let payload = serde_json::json!({"query": query, "variables": variables});
        for attempt in 0..4 {
            let agent = self.agent.clone();
            let authorization = self.authorization.clone();
            let payload = payload.clone();
            // ureq is blocking; keep both the request and response I/O off async workers.
            // Callers bound the number of in-flight requests with buffer_unordered.
            let result = tokio::task::spawn_blocking(move || {
                let mut response = agent
                    .post("https://api.github.com/graphql")
                    .header("Authorization", &authorization)
                    .send_json(&payload)?;
                let status = response.status().as_u16();
                let body = response.body_mut().read_to_string()?;
                Ok::<_, ureq::Error>((status, body))
            })
            .await
            .context("GitHub request worker failed")?;
            let (status, body) = match result {
                Ok(response) => response,
                Err(error) if attempt < 3 && retryable_transport(&error) => {
                    eprintln!("warning: transient network error; retry {}/3", attempt + 1);
                    backoff(attempt).await;
                    continue;
                }
                Err(error) => return Err(error).context("GitHub GraphQL request failed"),
            };
            if retryable(status) && attempt < 3 {
                eprintln!(
                    "warning: GitHub returned HTTP {status}; retry {}/3",
                    attempt + 1
                );
                backoff(attempt).await;
                continue;
            }
            if !(200..300).contains(&status) {
                bail!(
                    "GitHub GraphQL HTTP {status}: {}",
                    body.chars().take(2000).collect::<String>()
                );
            }
            return serde_json::from_str(&body).context("invalid GitHub GraphQL response");
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
    fn transport_retry_classification() {
        assert!(retryable_transport(&ureq::Error::ConnectionFailed));
        assert!(retryable_transport(&ureq::Error::HostNotFound));
        assert!(retryable_transport(&ureq::Error::Io(
            std::io::ErrorKind::ConnectionReset.into()
        )));
        assert!(!retryable_transport(&ureq::Error::Io(
            std::io::ErrorKind::PermissionDenied.into()
        )));
        assert!(!retryable_transport(&ureq::Error::StatusCode(401)));
    }
    #[test]
    fn retry_classification() {
        for code in [502, 503, 504] {
            assert!(retryable(code));
        }
        for code in [200, 400, 401, 403, 404, 429, 500] {
            assert!(!retryable(code));
        }
    }
}
