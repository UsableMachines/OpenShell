# Contributing to OpenShell

OpenShell is built agent-first. We design systems and use agents to implement them. Your agent is your first collaborator — point it at this repo before opening issues, asking questions, or submitting code.

## The Critical Rule

**You must understand your code.** Using AI agents to write code is not just acceptable, it's how this project works. But you must be able to explain what your changes do and how they interact with the rest of the system. If you can't, don't submit it.

Submitting agent-generated code without understanding it — regardless of how clean it looks — wastes maintainer time and will result in your PR being closed. Repeat offenders will be blocked from the project.

## AI Usage

OpenShell is agent-first, not agent-only. The distinction matters:

- **Do** use agents to explore the codebase, run diagnostics, generate code, and iterate on implementations.
- **Do** use the skills in `.agents/skills/` — they exist to make your agent effective.
- **Do** interrogate your agent until you understand every edge case and interaction in your changes.
- **Don't** submit code you can't explain without your agent open.
- **Don't** use agents as a substitute for understanding the system. Read the architecture docs.

## First-Time Contributors

We use a vouch system. This exists because AI makes it trivial to generate plausible-looking but low-quality contributions, and we can no longer trust by default.

1. Open a [Vouch Request](https://github.com/NVIDIA/OpenShell/discussions/new?category=vouch-request) discussion.
2. Describe what you want to change and why.
3. Write in your own words. AI-generated vouch requests will be denied.
4. A maintainer will comment `/vouch` if approved.
5. Once vouched, you can submit pull requests.

**If you are not vouched, any pull request you open will be automatically closed.** Org members and collaborators with push access bypass this check.

### Finding Work

Issues labeled [`good first issue`](https://github.com/NVIDIA/OpenShell/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) are scoped, well-documented, and friendly to new contributors. Start there. If you need guidance, comment on the issue.

An open issue is not necessarily accepted or ready to be worked on. Human contributors should look for `state:accepted`, `good first issue`, or `help wanted`, or ask a maintainer before starting. Agents additionally require the appropriate human-applied `agent:*` request label. Roadmap placement describes sequencing and does not authorize work.

## Before You Open an Issue

This project ships with [agent skills](#agent-skills-for-contributors) that can diagnose problems, explore the codebase, generate policies, and walk you through common workflows. Before filing an issue:

1. Clone the repo and point your coding agent at it.
2. Load the relevant skill - `debug-openshell-cluster` for gateway or deployment problems, `debug-inference` for inference setup problems, `openshell-cli` for usage questions, `generate-sandbox-policy` for policy help.
3. Have your agent investigate. Let it run diagnostics, read the architecture docs, and attempt a fix.
4. If the agent cannot resolve it, open an issue **with the agent's diagnostic output attached**. The issue template requires this.

### When to Open an Issue

- A real bug that your agent confirmed and could not fix.
- A feature proposal with a design — not a "please build this" request.
- An infrastructure problem that the gateway deployment troubleshooting skill could not resolve.
- An inference setup problem that the `debug-inference` skill could not resolve.
- Security vulnerabilities must follow [SECURITY.md](SECURITY.md) — **not** GitHub issues.

### When NOT to Open an Issue

- Questions about how things work — your agent can answer these from the codebase and architecture docs.
- Configuration problems - your agent can diagnose these with `openshell-cli`, `debug-openshell-cluster`, and `debug-inference`.
- "How do I..." requests — the skills cover CLI usage, policy generation, TUI development, and more.

## Agent Skills for Contributors

Skills live in `.agents/skills/`. Your agent's harness can discover and load them natively. Here is the full inventory:

| Category        | Skill                     | Purpose                                                                                             |
| --------------- | ------------------------- | --------------------------------------------------------------------------------------------------- |
| Getting Started | `openshell-cli`           | CLI usage, sandbox lifecycle, provider management, BYOC workflows                                   |
| Getting Started | `debug-openshell-cluster` | Diagnose gateway deployment and health issues                                                       |
| Getting Started | `debug-inference`         | Diagnose `inference.local`, host-backed local inference, and direct external inference setup issues |
| Contributing    | `create-spike`            | Investigate a problem, produce a structured GitHub issue                                            |
| Contributing    | `create-rfc`              | Create RFC proposals from the repository template                                                   |
| Contributing    | `build-from-issue`        | Plan and implement work from a GitHub issue (maintainer workflow)                                   |
| Contributing    | `create-github-issue`     | Create well-structured GitHub issues                                                                |
| Contributing    | `create-github-pr`        | Create pull requests with proper conventions                                                        |
| Reviewing       | `review-github-pr`        | Summarize PR diffs and key design decisions                                                         |
| Reviewing       | `review-security-changes` | Review code changes for security vulnerabilities and boundary regressions                           |
| Reviewing       | `review-security-issue`   | Assess security issues for severity and remediation                                                 |
| Reviewing       | `fix-security-issue`      | Implement an approved security remediation plan                                                     |
| Reviewing       | `watch-github-actions`    | Monitor CI pipeline status and logs                                                                 |
| Reviewing       | `launch-openshell-gator`  | Launch and supervise OpenShell gator agents for issue and PR monitoring                             |
| Reviewing       | `test-release-canary`     | Dispatch and iterate on the Release Canary workflow that smoke-tests published artifacts            |
| Triage          | `triage-issue`            | Assess, classify, and route community-filed issues                                                  |
| Platform        | `generate-sandbox-policy` | Generate YAML sandbox policies from requirements or API docs                                        |
| Platform        | `helm-dev-environment`    | Start and manage the local Kubernetes development environment                                       |
| Platform        | `tui-development`         | Development guide for the ratatui-based terminal UI                                                 |
| Documentation   | `update-docs`             | Scan recent commits and draft doc updates for user-facing changes                                   |
| Maintenance     | `sync-agent-infra`        | Detect and fix drift across agent-first infrastructure files                                        |
| Reference       | `sbom`                    | Generate SBOMs and resolve dependency licenses                                                      |

### Workflow Chains

Skills connect into pipelines. Individual skill files don't describe these relationships.

- **Community inflow:** `triage-issue` → human disposition and roadmap placement → `create-spike` when needed → `build-from-issue`
- **Internal development:** `create-spike` → human disposition and roadmap placement → `build-from-issue`
- **Security:** `review-security-issue` → `fix-security-issue`
- **Policy iteration:** `openshell-cli` → `generate-sandbox-policy`

### Issue Lifecycle, Roadmap, and Agent Work

See [Issue Triage and Lifecycle](docs/resources/issue-lifecycle.mdx) for the human-facing process, including triage outcomes, maintainer decisions, roadmap placement, ownership, spikes, and agent delegation.

Label namespaces represent independent dimensions. `state:*` records the issue's universal disposition and `agent:*` is an optional workflow used only when maintainers delegate planning or implementation to an agent. Sequencing is not a label: it comes from the [OpenShell Roadmap](https://github.com/orgs/NVIDIA/projects/233).

| State | Meaning |
|---|---|
| `state:triage-needed` | The issue has not been assessed. New issues from users without repository write access receive this automatically. |
| `state:needs-info` | Triage needs specific evidence or reproduction details from the reporter. |
| `state:validated` | The factual assessment is complete and awaits a human accept/decline decision. This is not roadmap acceptance. |
| `state:accepted` | A human decided that OpenShell should pursue the issue. This does not assign the work to an agent. |

For an issue labeled `state:validated`, a maintainer makes one of these decisions:

- **Decline:** close it as not planned and record the rationale.
- **Accept:** replace `state:validated` with `state:accepted` and associate the issue with a roadmap item.
- **Await more evidence:** replace `state:validated` with `state:needs-info` and leave it off the roadmap.

OpenShell does not use priority labels. Accepted work is sequenced by associating it with an item on the [OpenShell Roadmap](https://github.com/orgs/NVIDIA/projects/233); the roadmap item's timing implies the urgency. Issues tracked there carry the `roadmap` label. An accepted issue with no roadmap association is intended work that is not yet scheduled.

Roadmap placement is sequencing metadata. `build-from-issue` requires both `state:accepted` and the human-applied `agent:plan-requested` label before it creates an implementation plan; roadmap placement does not gate agent work.

Accepted issues may be implemented by humans without any `agent:*` labels. To delegate work to an agent, maintainers move the issue through exactly one agent-workflow label at a time:

| Agent workflow | Applied by | Meaning |
|---|---|---|
| `agent:plan-requested` | Human | Ask an agent to produce an implementation plan. |
| `agent:plan-ready` | Agent | The plan is ready for human review. |
| `agent:implementation-requested` | Human | The plan is approved; replace `agent:plan-ready` with this label to request implementation. |
| `agent:in-progress` | Agent | Authorized agent implementation is underway. |
| `agent:pr-opened` | Agent | Agent implementation produced a pull request. |

Agents never apply the two request labels. GitHub permits users with the Triage repository role or greater to apply existing labels, but OpenShell reserves `agent:plan-requested` and `agent:implementation-requested` for maintainers. General implementation agents must exclude `topic:security`; the specialized security workflow uses the same two human gates.

`help wanted` and `good first issue` describe contributor suitability, not sequencing. `good first issue` is suitable for someone with very little project experience; `help wanted` invites broader contributor involvement.

GitHub issue templates assign built-in issue types where applicable, and agent-created issues should use issue types or manual follow-up rather than type labels. Security work uses `topic:security` and follows the separate process in `SECURITY.md`.

Inactive issues and pull requests are automatically labeled `state:stale` after 14 days without activity. Automated closing is currently disabled. Comment on the item or remove `state:stale` to keep it active. Issues awaiting triage or human disposition, accepted issues, active agent workflows, and roadmap issues are exempt. `state:needs-info` may become stale when no new evidence arrives.

## Prerequisites

Install [mise](https://mise.jdx.dev/). This is used to set up the development environment.

```bash
# Install mise (macOS/Linux)
curl https://mise.run | sh
```

After installing `mise`, activate it with `mise activate` or [add it to your shell](https://mise.jdx.dev/getting-started.html).

Shell setup examples:

```bash
# Bash
echo 'eval "$(~/.local/bin/mise activate bash)"' >> ~/.bashrc

# Fish
echo '~/.local/bin/mise activate fish | source' >> ~/.config/fish/config.fish

# Zsh
echo 'eval "$(~/.local/bin/mise activate zsh)"' >> ~/.zshrc
```

Project requirements:

- Rust 1.90+
- Python 3.11+
- Docker (running)
- Z3 solver library (for the policy prover crate)

### macOS build tools

Install Apple Command Line Tools before building locally:

```bash
xcode-select --install
```

If Cargo fails while building `protobuf-src` with an error such as
`fatal error: 'utility' file not found`, `fatal error: 'cstdlib' file not
found`, or `A compiler with support for C++11 language features is required`,
your Command Line Tools install may not expose the libc++ headers on the
compiler's default include path. Reinstall Command Line Tools to correct the error:

```bash
sudo rm -rf /Library/Developer/CommandLineTools
xcode-select --install
```

### Z3 installation

The `openshell-prover` crate links against the system Z3 library via pkg-config.

```bash
# macOS
brew install z3

# Ubuntu / Debian
sudo apt install libz3-dev

# Fedora
sudo dnf install z3-devel
```

If you prefer not to install Z3 system-wide, you can compile it from source as a one-time step:

```bash
cargo build -p openshell-prover --features bundled-z3
```

## Getting Started

```bash
# One-time trust
mise trust

# Run a standalone gateway for local development
mise run gateway
```

## Building the `openshell` CLI

Inside this repository, `openshell` is a local shortcut script at `scripts/bin/openshell`. The script will

1. Build `openshell-cli` if needed.
2. Run the local debug CLI binary under `target/debug/openshell`.

Because `mise` adds `scripts/bin` to `PATH` for this project, you can run `openshell` directly from the repo.

```bash
openshell --help
openshell sandbox create -- codex
```

### Rust build cache

Mise preserves an existing `SCCACHE_DIR` so each environment can choose where
to store compiler cache entries. When `SCCACHE_DIR` is unset, OpenShell uses
the worktree-local `.cache/sccache` directory. To make cache entries available
to multiple worktrees on a workstation, set the variable to a user-level
directory before activating mise. For example:

```shell
export SCCACHE_DIR="$HOME/.cache/openshell/sccache"
```

CI can select a different directory or configure a remote sccache backend
without changing the workstation setting. Cargo output remains in each
worktree's `target/` directory.

OpenShell does not set `SCCACHE_BASEDIRS`. Sccache loads base directories when
its machine-local daemon starts, but the correct workspace root differs for
each worktree. Cache reuse therefore depends on the compiler inputs: outputs
that embed absolute paths, including Rust dependencies in some builds, can
still miss across worktrees.

## Main Tasks

These are the primary `mise` tasks for day-to-day development:

| Task                 | Purpose                                                 |
| -------------------- | ------------------------------------------------------- |
| `mise run gateway`   | Run a standalone gateway for local development          |
| `mise run sandbox`   | Create or reconnect to the dev sandbox                  |
| `mise run test`      | Default test suite                                      |
| `mise run e2e`       | Default end-to-end test lane                            |
| `mise run ci`        | Full local CI checks (lint, compile/type checks, tests) |
| `mise run docs`      | Validate Fern docs locally                              |
| `mise run helm:docs` | Regenerate the Helm chart README                        |
| `mise run clean`     | Clean build artifacts                                   |

## Project Structure

| Path            | Purpose                                       |
| --------------- | --------------------------------------------- |
| `crates/`       | Rust crates                                   |
| `python/`       | Python SDK and bindings                       |
| `proto/`        | Protocol buffer definitions                   |
| `tasks/`        | `mise` task definitions and build scripts     |
| `deploy/`       | Dockerfiles, Helm chart, Kubernetes manifests |
| `docs/`         | Published Fern docs source, navigation, and content assets |
| `fern/`         | Fern site config, components, and theme assets |
| `architecture/` | Architecture docs and plans                   |
| `rfc/`          | Request for Comments proposals                |
| `.agents/`      | Agent skills and persona definitions          |

## RFCs

New features always start as GitHub issues using the feature request template. For cross-cutting architectural decisions, API contract changes, or process proposals that need broad consensus, maintainers may ask for an RFC from the issue and assign an RFC number there. RFCs live in `rfc/`. See [rfc/README.md](rfc/README.md) for the full lifecycle and guidelines.

## Documentation

If your change affects user-facing behavior (new flags, changed defaults, new features, bug fixes that contradict existing docs), update the relevant pages under `docs/` in the same PR and adjust `docs/index.yml` if navigation changes. For explicit navigation entries, keep `page:` aligned with `sidebar-title` when present and put relative `slug:` values in `docs/index.yml`. Reserve frontmatter `slug` for folder-discovered pages or absolute URL overrides.

To ensure your doc changes follow NVIDIA documentation style, use the `update-docs` skill.
It scans commits, identifies doc pages that need updates, and drafts content that follows the style guide in `docs/CONTRIBUTING.mdx`.

To preview Fern docs locally:

```bash
mise run docs:serve
```

To run non-interactive validation:

```bash
mise run docs
```

PRs that touch `docs/**` or `fern/**` are validated by `.github/workflows/branch-docs.yml`, and they get a preview when `FERN_TOKEN` is available to the workflow.

Fern docs publishing is handled by the `publish-fern-docs` job in `.github/workflows/release-tag.yml` when a release tag is created.

`docs/` is the source-of-truth docs tree. `fern/` contains the site config, components, and theme assets that publish those pages.

See [docs/CONTRIBUTING.mdx](docs/CONTRIBUTING.mdx) for the current docs authoring guide.

## Pull Requests

1. Create a feature branch from `main`.
2. Make your changes with tests.
3. Run `mise run ci` to verify.
4. Open a PR using the `create-github-pr` skill or manually following the [PR template](.github/PULL_REQUEST_TEMPLATE.md).

PRs for new features, user-visible behavior changes, public API changes, architecture changes, or multi-PR efforts must link an accepted issue. Small documentation fixes, mechanical maintenance, and obvious localized bug fixes may omit a separate issue when the PR contains enough context to review the decision and implementation together.

In the PR's **Related Issue** section, use `Fixes #NNN` or `Closes #NNN` when an issue is required. For an exempt change, write `No issue required:` followed by a brief reason. Security fixes follow the private disclosure process in [SECURITY.md](SECURITY.md).

### Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/). All commit messages must follow the format:

```text
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

**Types:**

- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation only
- `chore` - Maintenance tasks (dependencies, build config)
- `refactor` - Code change that neither fixes a bug nor adds a feature
- `test` - Adding or updating tests
- `ci` - CI/CD changes
- `perf` - Performance improvements

**Examples:**

```text
feat(cli): add --verbose flag to openshell run
fix(sandbox): handle timeout errors gracefully
docs: update installation instructions
chore(deps): bump tokio to 1.40
```

### DCO

All human contributions must include a `Signed-off-by` line in each commit message. This certifies you have the right to submit the work under the project license. See the [Developer Certificate of Origin](https://developercertificate.org/). Dependabot-authored dependency update PRs are allowlisted because the bot cannot sign commits.

```bash
git commit -s -m "feat(sandbox): add new capability"
```

DCO sign-off is separate from cryptographic commit signing. CI requires signing for org members so that copy-pr-bot can mirror your PR automatically; see [CI.md](CI.md#commit-signing) for setup.

## CI

How PR CI runs, the `test:e2e`, `test:e2e-gpu`, and `test:e2e-kubernetes` labels, copy-pr-bot, and commit-signing setup are documented in [CI.md](CI.md).
