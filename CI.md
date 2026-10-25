# Continuous integration

What `.github/workflows/ci.yml` checks, why each check exists, and what to do
when one fails.

The pipeline runs with **no Azure credentials, no secrets and no network access
to Azure**. Every test uses in-process fakes. That is a property to defend, not
a gap: it means a fork can run the full suite, and a malicious pull request has
nothing to steal.

---

## Jobs

| Job | Runs on | Blocks merge | Purpose |
|---|---|:---:|---|
| `hygiene` | every push and PR | yes | the per-tenant config is not committed; required docs exist |
| `test` | every push and PR, Python 3.12 and 3.13 | yes | lock-file integrity, then ~150 tests |
| `lint` | every push and PR | no | ruff check and format |
| `image` | after `test` passes | yes | the image builds and contains exactly the reviewed dependency set |
| `dependency-review` | pull requests only | no | flags known-vulnerable dependency changes |

---

## `hygiene` — why a whole job for four `grep`s

This repository is public and the deployed configuration is not. The split only
holds if nobody ever commits `config/mcp-server-config.yaml`, and that file
names your tenant, subscription, workspace and app registrations.

`.gitignore` prevents the accident. It does not prevent `git add -f`, a merge
that resurrects the path, or a well-meaning contributor "fixing" the missing
config. This job is the backstop.

It also asserts that `config/mcp-server-config.example.yaml` exists and uses an
`example.invalid` hostname. A clean clone must be able to run `pytest` before
the developer has a tenant — `tests/conftest.py` and `tests/_support.py` load
the example, and several tests assert against the shipped policy.

**If it fails:**

| Message | Fix |
|---|---|
| per-tenant config is tracked | `git rm --cached config/mcp-server-config.yaml` and commit. Then **rotate nothing** — GUIDs are not secrets — but check the git history: if it was ever pushed, the IDs are public. |
| example config is missing | restore it; a clean clone cannot run the test suite without it |
| example does not use `example.invalid` | someone copied a real config over the template |
| `.gitignore` entry missing | re-add `config/mcp-server-config.yaml` |
| a required doc is missing | restore it, or remove it from the job's list if it was retired deliberately |
| per-tenant config file(s) tracked | `git rm --cached <path>` for each. The `.gitignore` allowlists exactly one file: `config/mcp-server-config.example.yaml`. If a leaked file was ever pushed, its tenant/subscription/workspace IDs are in public history — not secrets, but treat them as disclosed. |


---

## `test` — lock integrity first, then tests

Three gates run before `pytest`, in this order:

1. **`poetry check --lock`** — `poetry.lock` matches `pyproject.toml`.
2. **`requirements.lock` drift** — regenerated from `poetry.lock` and compared
   byte for byte.
3. **hash presence** — `requirements.lock` contains `sha256:` entries.

Gate 2 is the important one. The image installs from `requirements.lock`, not
from `poetry.lock`. If they drift, the container runs a dependency set that was
never reviewed or scanned, and nothing else would notice.

**If gate 2 fails:**

```bash
poetry export --only main --format requirements.txt --output requirements.lock
git add requirements.lock && git commit --amend --no-edit
```

Always in the same commit as the `poetry.lock` change. A Dependabot PR that
updates `poetry.lock` alone will fail here — that is intentional; regenerate and
push to the PR branch.

**If gate 3 fails:** the export lost its hashes. Confirm
`poetry-plugin-export` is installed and re-run. An image built from a
hash-less lock file fails at `pip install --require-hashes` anyway, so this
catches it earlier and more clearly.

**Why both 3.12 and 3.13:** `pyproject.toml` declares
`python = ">=3.12,<3.14"`. Testing only one of them means the declared range is
a guess. The image uses 3.12; 3.13 is the forward-compatibility canary.

---

## `lint`

`ruff check` and `ruff format --check` over `src` and `tests`. Non-blocking by
default — make it required once the codebase is clean.

```bash
poetry run ruff check src tests --fix
poetry run ruff format src tests
```

The `S` (bandit) rules are enabled with three exceptions documented in
`pyproject.toml`: `S101` because pytest is built on `assert`, and `S105`/`S106`
because claim and token *names* look like hardcoded passwords to the rule.

---

## `image` — three checks a normal Docker build does not do

### Why it stages a placeholder config

The Dockerfile copies `config/mcp-server-config.yaml` **by name**, and that file
is gitignored, so the build cannot run in CI without one. The job copies the
example over it first.

```yaml
- run: cp config/mcp-server-config.example.yaml config/mcp-server-config.yaml
```

> **The resulting image must never be pushed.** Its `base_url` is
> `https://mcp.example.invalid` and its identity block is placeholder GUIDs. It
> cannot start against a real tenant, and if it somehow did it would fail
> host-header validation on every request. Keep publishing in a separate
> workflow with an `environment:` gate.

### 1. Installed packages match `requirements.lock`

`pip freeze` inside the built image, compared against the lock file. Catches:

- a stale build-cache layer,
- pip resolving something on its own despite `--no-deps`,
- a base-image change bringing in new site-packages.

### 2. Build-context exclusions held

Asserts `/app/tests`, `/app/README.md`, `/app/poetry.lock` and `/app/.git` are
**absent**. `.dockerignore` is easy to break silently, and a `.git` directory in
a production image is a credential and history leak.

### 3. The container does not run as root

`id -un` must return `mcp`. One line, and it catches a reordered `USER`
directive.

### Trivy

Fails on `CRITICAL` and `HIGH` with `ignore-unfixed: true`. Unfixed findings
are reported but do not block — there is nothing to upgrade to, and a permanently
red pipeline gets ignored, which is worse than a yellow one.

**If Trivy fails on a fixable finding:**

```bash
poetry update <package>
poetry export --only main -f requirements.txt -o requirements.lock
poetry run pytest -q
```

If the fix is in the base image, refresh the digest:

```bash
docker pull python:3.12-slim
docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim
```

and update `ARG PYTHON_IMAGE` in the Dockerfile. The digest pin is deliberate —
`python:3.12-slim` is a moving tag, and a tag is not a pin.

---

## Running the same checks locally

```bash
# hygiene
git ls-files --error-unmatch config/mcp-server-config.yaml && echo "TRACKED - fix this"

# test
poetry check --lock
poetry export --only main -f requirements.txt -o /tmp/rl && diff -u requirements.lock /tmp/rl
poetry install --with dev
poetry run pytest -q

# lint
poetry run ruff check src tests && poetry run ruff format --check src tests

# image
cp config/mcp-server-config.example.yaml /tmp/real-config-backup.yaml   # if you have one
docker build -t sentinel-mcp:local .
docker run --rm --entrypoint id sentinel-mcp:local -un     # must print: mcp
```

A pre-push hook for the two cheap, high-value checks:

```bash
cat > .git/hooks/pre-push <<'SH'
#!/bin/sh
set -e
if git ls-files --error-unmatch config/mcp-server-config.yaml >/dev/null 2>&1; then
  echo "REFUSING: config/mcp-server-config.yaml is tracked"
  exit 1
fi
poetry run pytest -q
SH
chmod +x .git/hooks/pre-push
```

---

## Repository settings CI cannot enforce

A workflow only runs after a commit exists. These close the remaining gap:

**Settings → Code security and analysis**
- **Secret scanning** — on
- **Push protection** — on. This is the only control that stops a real config or
  an API key reaching a public commit *before* the hygiene job runs.
- **Dependabot alerts** and **security updates** — on

**Settings → Branches → protect `main`**
- Require status checks: `hygiene`, `test (3.12)`, `test (3.13)`, `image`
- Require branches to be up to date before merging
- Require a pull request review
- Disallow force pushes and deletions

**Settings → Actions → General**
- Fork pull request workflows: *Require approval for first-time contributors*
- Workflow permissions: **read-only** by default

---

## Action pinning

The workflow pins actions to major version tags for readability. For a
security-sensitive public repository, pin to full commit SHAs:

```yaml
- uses: actions/checkout@<40-char-sha>   # v4.2.2
```

A tag is mutable; a SHA is not. Resolve the SHAs yourself at adoption time —
do not copy them out of documentation, including this file. Renovate can keep
SHA pins updated with the version in a trailing comment.

---

## What this pipeline deliberately does not do

**No deployment.** Publishing an image and rolling a Container Apps revision
needs federated credentials and registry write access. Keep it in a separate
workflow, gated by a protected `environment:` with a manual approval, so a pull
request from a fork can never reach it.

**No integration tests against Azure.** Every test uses fakes
(`FakeLAW`, `FakeSentinel` in `tests/test_tools.py`). Post-deployment
verification belongs in a smoke test run against a real environment by whoever
deploys, not in CI.

**No coverage threshold.** Coverage percentage is a weak proxy for this
codebase. The meaningful standard is the definition-of-done checklist in
`EXTENDING.md` §6: every new control has a test that fails when the control is
removed. That is a review obligation, not something a number enforces.

**No secret scanning of its own.** GitHub's native secret scanning with push
protection is strictly better — it runs before the commit lands.
