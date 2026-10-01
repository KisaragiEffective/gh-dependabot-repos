use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Deserialize)]
pub struct Response<T> {
    pub data: Option<T>,
    #[serde(default)]
    pub errors: Vec<GraphqlError>,
}

#[derive(Debug, Deserialize, Error)]
#[error("{message}")]
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

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("could not run gh auth token; install GitHub CLI and run gh auth login: {0}")]
    AuthCommand(#[source] std::io::Error),
    #[error("gh auth token failed ({status}): {stderr}")]
    AuthRejected {
        status: std::process::ExitStatus,
        stderr: String,
    },
    #[error("gh returned an invalid token: {0}")]
    InvalidToken(#[source] std::string::FromUtf8Error),
    #[error("GitHub request worker failed: {0}")]
    Worker(#[source] tokio::task::JoinError),
    #[error("GitHub GraphQL request failed: {0}")]
    Transport(#[source] Box<ureq::Error>),
    #[error("GitHub GraphQL HTTP {status}: {body}")]
    Http { status: u16, body: String },
    #[error("invalid GitHub GraphQL response: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("GitHub GraphQL: {}", .0.iter().map(|e| e.message.as_str()).collect::<Vec<_>>().join("; "))]
    Graphql(Vec<GraphqlError>),
    #[error("GitHub returned no GraphQL data")]
    MissingData,
}

type Result<T> = std::result::Result<T, ApiError>;

impl<T> Response<T> {
    pub fn into_data(self) -> Result<T> {
        if !self.errors.is_empty() {
            return Err(ApiError::Graphql(self.errors));
        }
        self.data.ok_or(ApiError::MissingData)
    }
}

fn decode_response<T: DeserializeOwned>(status: u16, body: &str) -> Result<Response<T>> {
    if !(200..300).contains(&status) {
        return Err(ApiError::Http {
            status,
            body: body.chars().take(2000).collect(),
        });
    }
    serde_json::from_str(body).map_err(ApiError::Decode)
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
            .map_err(ApiError::AuthCommand)?;
        if !output.status.success() {
            return Err(ApiError::AuthRejected {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        let token = String::from_utf8(output.stdout).map_err(ApiError::InvalidToken)?;
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
                let status = response.status();
                let body = response.body_mut().read_to_string()?;
                Ok((status, body))
            })
            .await
            .map_err(ApiError::Worker)?;

            let (status, body) = match result {
                Ok(response) => response,
                Err(error) if attempt < 3 && retryable_transport(&error) => {
                    eprintln!("warning: transient network error; retry {}/3", attempt + 1);
                    backoff(attempt).await;
                    continue;
                }
                Err(error) => return Err(ApiError::Transport(Box::new(error))),
            };

            if retryable(status.as_u16()) && attempt < 3 {
                eprintln!(
                    "warning: GitHub returned HTTP {}; retry {}/3",
                    status.as_u16(),
                    attempt + 1
                );
                backoff(attempt).await;
                continue;
            }
            return decode_response(status.as_u16(), &body);
        }
        unreachable!()
    }

    pub async fn strict<T: DeserializeOwned>(&self, query: &str, variables: Value) -> Result<T> {
        let response: Response<T> = self.query(query, variables).await?;
        response.into_data()
    }
}

async fn backoff(attempt: u32) {
    tokio::time::sleep(Duration::from_millis(500 * (1 << attempt))).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn http_failures_preserve_status_and_diagnostic() {
        let error = decode_response::<Value>(401, "bad credentials").unwrap_err();
        assert!(matches!(error, ApiError::Http { status: 401, body } if body == "bad credentials"));
        let error = decode_response::<Value>(504, &"x".repeat(3000)).unwrap_err();
        assert!(matches!(error, ApiError::Http { status: 504, body } if body.len() == 2000));
    }

    #[test]
    fn invalid_json_preserves_parse_error() {
        let error = decode_response::<Value>(200, "not JSON").unwrap_err();
        assert!(matches!(error, ApiError::Decode(source) if source.is_syntax()));
    }

    #[test]
    fn strict_responses_keep_graphql_errors_and_reject_missing_data() {
        let response = decode_response::<Value>(200,
            r#"{"data":{"viewer":null},"errors":[{"type":"FORBIDDEN","message":"denied","path":["viewer"]}]}"#).unwrap();
        let error = response.into_data().unwrap_err();
        assert!(
            matches!(error, ApiError::Graphql(errors) if errors.len() == 1
            && errors[0].kind.as_deref() == Some("FORBIDDEN")
            && errors[0].path == vec![serde_json::json!("viewer")])
        );
        assert!(matches!(
            decode_response::<Value>(200, r#"{"data":null}"#)
                .unwrap()
                .into_data(),
            Err(ApiError::MissingData)
        ));
    }

    #[test]
    fn errors_retain_sources_and_useful_diagnostics() {
        use std::error::Error as _;
        let error = ApiError::Transport(Box::new(ureq::Error::ConnectionFailed));
        assert!(error.source().is_some());
        assert!(error.to_string().contains("GitHub GraphQL request failed"));
    }

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
