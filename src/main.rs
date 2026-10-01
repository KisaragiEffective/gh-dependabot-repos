#![deny(clippy::all)]
#![warn(clippy::nursery)]

mod api;
mod discovery;
mod inspection;

use clap::Parser;
use std::io::{self, Write};
use thiserror::Error;

#[derive(Debug, Error)]
enum AppError {
    #[error(transparent)]
    Api(#[from] api::ApiError),
    #[error(transparent)]
    Discovery(#[from] discovery::DiscoveryError),
    #[error(transparent)]
    Inspection(#[from] inspection::InspectionError),
    #[error("could not serialize JSON output: {0}")]
    JsonOutput(#[from] serde_json::Error),
    #[error("could not write output: {0}")]
    Output(#[from] io::Error),
}

#[derive(Debug, Parser)]
#[command(
    name = "gh-dependabot-repos",
    bin_name = "gh dependabot-repos",
    version,
    about = "List accessible owned and member-organization repositories with open Dependabot alerts"
)]
struct Options {
    /// Repository checks per request (1–100)
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u16).range(1..=100))]
    batch_size: u16,
    /// Maximum simultaneous requests (1–32)
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=32))]
    concurrency: u16,
    /// Emit a JSON array with repository names and open alert counts
    #[arg(long)]
    json: bool,
}

async fn run() -> Result<(), AppError> {
    let options = Options::parse();
    let api = api::Api::authenticated().await?;
    let repositories = discovery::discover(&api, usize::from(options.concurrency)).await?;
    let matches = inspection::inspect(
        &api,
        &repositories,
        usize::from(options.batch_size),
        usize::from(options.concurrency),
    )
    .await?;
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    if options.json {
        serde_json::to_writer(&mut stdout, &matches)?;
        writeln!(stdout)?;
    } else {
        for repo in matches {
            writeln!(stdout, "{}", repo.name_with_owner)?;
        }
    }
    stdout.flush()?;
    Ok(())
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_definition_and_defaults() {
        use clap::CommandFactory;
        Options::command().debug_assert();
        let options = Options::try_parse_from(["gh-dependabot-repos"]).unwrap();
        assert_eq!(options.batch_size, 20);
        assert_eq!(options.concurrency, 4);
        assert!(!options.json);
        for flag in ["--help", "--version"] {
            let error = Options::try_parse_from(["gh-dependabot-repos", flag]).unwrap_err();
            assert_eq!(error.exit_code(), 0);
        }
    }
    #[test]
    fn options_are_bounded() {
        for args in [
            vec!["--batch-size", "0"],
            vec!["--concurrency", "33"],
            vec!["--batch-size", "101"],
            vec!["--batch-size"],
            vec!["--bad"],
        ] {
            assert!(
                Options::try_parse_from(std::iter::once("gh-dependabot-repos").chain(args))
                    .is_err()
            );
        }
        let options = Options::try_parse_from([
            "gh-dependabot-repos",
            "--json",
            "--batch-size",
            "10",
            "--concurrency",
            "2",
        ])
        .unwrap();
        assert!(options.json);
        assert_eq!(options.batch_size, 10);
        assert_eq!(options.concurrency, 2);
    }
}
