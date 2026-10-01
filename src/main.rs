#![deny(clippy::all)]
#![warn(clippy::nursery)]

mod api;
mod discovery;
mod inspection;

use anyhow::{Context, Result, bail};
use std::io::{self, Write};

#[derive(Debug)]
struct Options {
    batch_size: usize,
    concurrency: usize,
    json: bool,
}
impl Options {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Option<Self>> {
        let mut options = Self {
            batch_size: 20,
            concurrency: 4,
            json: false,
        };
        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--batch-size" | "--concurrency" => {
                    let value: usize = args
                        .next()
                        .with_context(|| format!("{arg} requires a value"))?
                        .parse()
                        .with_context(|| format!("{arg} requires a positive integer"))?;
                    let max = if arg == "--batch-size" { 100 } else { 32 };
                    if value == 0 || value > max {
                        bail!("{arg} must be between 1 and {max}");
                    }
                    if arg == "--batch-size" {
                        options.batch_size = value;
                    } else {
                        options.concurrency = value;
                    }
                }
                "--json" => options.json = true,
                "--help" | "-h" => {
                    println!(
                        "Usage: gh dependabot-repos [--batch-size N] [--concurrency N] [--json]\n\nList accessible owned and member-organization repositories with open Dependabot alerts.\nDefaults: batch size 20 (1–100), concurrency 4 (1–32). JSON emits an array."
                    );
                    return Ok(None);
                }
                _ => bail!("unknown argument {arg}; use --help"),
            }
        }
        Ok(Some(options))
    }
}

async fn run() -> Result<()> {
    let Some(options) = Options::parse(std::env::args().skip(1))? else {
        return Ok(());
    };
    let api = api::Api::authenticated().await?;
    let repositories = discovery::discover(&api, options.concurrency).await?;
    let matches =
        inspection::inspect(&api, &repositories, options.batch_size, options.concurrency).await?;
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
            eprintln!("error: {error:#}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn options_are_bounded() {
        for args in [
            vec!["--batch-size", "0"],
            vec!["--concurrency", "33"],
            vec!["--batch-size", "101"],
            vec!["--batch-size"],
            vec!["--bad"],
        ] {
            assert!(Options::parse(args.into_iter().map(String::from)).is_err());
        }
        let options = Options::parse(
            ["--json", "--batch-size", "10", "--concurrency", "2"].map(String::from),
        )
        .unwrap()
        .unwrap();
        assert!(options.json);
        assert_eq!(options.batch_size, 10);
        assert_eq!(options.concurrency, 2);
    }
}
