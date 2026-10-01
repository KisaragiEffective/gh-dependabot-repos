# gh-dependabot-repos

A small async Rust GitHub CLI extension that prints sorted, unique `owner/repo`
names with at least one open Dependabot vulnerability alert. Targets **github.com**.

## Local installation

Requires a current Rust toolchain and [GitHub CLI](https://cli.github.com/).
Authenticate with `gh auth login --hostname github.com`, then from this checkout:

```sh
cargo build --release
mkdir -p target/gh-dependabot-repos
cp target/release/gh-dependabot-repos target/gh-dependabot-repos/gh-dependabot-repos
gh extension install ./target/gh-dependabot-repos
gh dependabot-repos
```

The staging directory intentionally matches the executable's name, even if this
checkout has another name. Local extensions reference their local files: keep that
staging directory, and repeat the build/copy commands after updates. `cargo clean`
removes it. See GitHub's [extension installation documentation](https://docs.github.com/en/github-cli/github-cli/creating-github-cli-extensions).
For eventual publication, name the repository `gh-dependabot-repos` and attach
platform-specific binaries to releases using GitHub CLI's naming convention.

## Usage

```sh
gh dependabot-repos --batch-size 20 --concurrency 4
gh dependabot-repos --json
```

Batch size defaults to 20 (allowed: 1–100); concurrency defaults to 4 (allowed:
1–32). JSON is a sorted array, for example:

```json
[{"nameWithOwner":"owner/repo","openAlerts":3}]
```

An empty result prints nothing, or `[]` with `--json`. Diagnostics go to stderr.
No output is written until all checks succeed. Unreadable repositories are skipped
with warnings and do not cause a non-zero exit; their alerts are unknown, not zero.
Unexpected API, authentication, discovery, and exhausted transient failures exit
non-zero. HTTP 502/503/504 and connection/timeouts receive at most three retries,
with 0.5, 1, and 2 second delays; each request has a 60 second timeout. Rate limits
are reported as errors rather than retried indefinitely.

## Authentication and permissions

The extension obtains its token via `gh auth token --hostname github.com`; it does
not store tokens or implement login. It can only discover what that token exposes.
For normal GitHub CLI OAuth/classic-token authentication, use `repo` for private
repository access and `read:org` for organization membership discovery:

```sh
gh auth refresh --hostname github.com --scopes repo,read:org
```

Repository visibility alone does not grant security-alert access. Your account
must have permission to view Dependabot alerts (for example, repository admin or
an appropriate security role/grant). Organization SSO and OAuth restrictions may
also require authorization. Fine-grained tokens need access to the selected
repositories and the **Dependabot alerts: read** repository permission; their
organization/resource restrictions can limit discovery. GitHub documents alert
access in [Viewing Dependabot alerts](https://docs.github.com/en/code-security/how-tos/manage-security-alerts/manage-dependabot-alerts/view-dependabot-alerts)
and token permissions in the [Dependabot API documentation](https://docs.github.com/en/rest/dependabot/alerts).
If GraphQL reports missing scopes, fix the token permissions indicated by GitHub.

## Implementation and development

Discovery independently paginates `viewer.repositories(ownerAffiliations: [OWNER])`,
`viewer.organizations`, and each `Organization.repositories` connection, using its
own cursor and 100 entries per page. Organization discovery requests run with
bounded concurrency. Accessible member-organization repositories are included;
personal repositories owned by other users are excluded.

Repositories are deduplicated before inspection. Separate alias batches request
only `vulnerabilityAlerts(first: 1, states: OPEN) { totalCount }`, never alert
objects. Inspection also uses bounded concurrency. Discovery/API/inspection/output
live in separate small modules; alias responses use a map of typed values.

Schema references: [User](https://docs.github.com/en/graphql/reference/users),
[Organization](https://docs.github.com/en/graphql/reference/orgs),
[Repository](https://docs.github.com/en/graphql/reference/repos), and
[pagination](https://docs.github.com/en/graphql/guides/using-pagination-in-the-graphql-api).

```sh
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Tests use fixtures and require no GitHub credentials or network access. They cover
repository deduplication, pagination progress, alias escaping, counts and filtering,
partial permission errors, unavailable fields, fatal errors, retry classification,
and CLI bounds.
