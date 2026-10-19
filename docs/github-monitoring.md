# GitHub Actions monitoring

Dashboard now tracks repositories by URL and reads Central results from GitHub Actions.
The browser's Sync buttons do not clone repositories or start scanners. Existing scan
API endpoints remain available for compatibility. Scanner, score and policy rules are unchanged.

1. Create a GitHub App in the account that owns the private target repositories.
   Give repository permissions **Metadata: read**, **Contents: read**, and **Actions: read**.
   No webhook is required for this polling implementation. User authorization/OAuth is
   not required. Install the App only on repositories that this Dashboard should read.
2. In the App settings open **Credentials > Key pairs > New key**.
   Keep the downloaded PEM **outside this repository**.
   Copy its App ID and installation ID. Do not paste the key into chat or a workflow.
3. Install `requirements.txt` and export these variables before starting the backend:

   ```powershell
   $env:DEVSECOPS_GITHUB_APP_ID = 'YOUR_APP_ID'
   $env:DEVSECOPS_GITHUB_INSTALLATION_ID = 'YOUR_INSTALLATION_ID'
   $env:DEVSECOPS_GITHUB_PRIVATE_KEY_PATH = 'C:\secure\central-app.pem'
   $env:DEVSECOPS_GITHUB_WORKFLOW = 'security-gate-test.yml'
   .\.venv\Scripts\python.exe -m uvicorn api.app:app --host 127.0.0.1 --port 8000
   ```

4. Login and add a `https://github.com/TRM-MYOS/REPOSITORY` URL once.
   All branches are discovered automatically, including branches created later.
   No branch input is needed. The existing workflow still determines which pushes
   are scanned: the updated Test workflow scans pushes on every branch (`**`) after
   that workflow change is published. Branches without
   a matching push run show no policy decision; monitoring does not create workflows
   or broaden scanner triggers. Pull-request merge commits are not imported as push results.

The backend polls all tracked repositories and branches on startup and approximately
30 seconds after each polling cycle, even when the browser is closed. Keep the backend
running. Use one Uvicorn worker to avoid duplicate pollers. Set process environment
`DEVSECOPS_GITHUB_POLL_ENABLED=false` to disable background polling if needed.
Visible Dashboard, Monitoring and History pages reload stored data every 5 seconds;
Sync buttons request an immediate update. Viewers can read the results without write
access. `github_branches` stores per-branch snapshots and the repository snapshot lists
only currently discovered branches. History remains intact when branches are deleted.

Current branch snapshots require the exact branch head SHA. History additionally pages
through all retained push workflow runs and their attempts, including older heads and
deleted branches. A push with no workflow run cannot be reconstructed, and GitHub may
already have deleted old runs or expired their artifacts. Failed, cancelled, queued and
invalid-report attempts are retained without a score or policy decision in `github_run_history`.
Each validated import is bound to its repository, commit SHA, workflow run and attempt.
It validates the three reports against `security-summary.json`, stores the Central decision
without recalculating policy, and imports a given run attempt once. Cached decisions are revalidated
once with the updated parser. If their artifacts cannot be validated, the original database
record is preserved but the History API shows the attempt as unvalidated instead of ALLOW.
A new commit, cancelled run, expired/missing artifact, failed ALLOW run, or invalid report
has **no current policy decision**. Previous scans remain visible in History as previous
results. Commit time is displayed as commit time, not claimed to be the push timestamp.

API additions (existing session/role/CSRF rules apply):
- `GET /api/github/status`: configuration status only; never returns credentials.
- `POST /api/repositories/{id}/sync`: all branches by default; explicit branch retained for API compatibility.
- `POST /api/github/sync`: synchronize all tracked repositories independently.

Artifacts are limited to 20 MB compressed and 10 MB per report. Raw reports are validated
in a temporary directory; normalized findings and commit/run metadata persist in SQLite.
GitHub App credentials are backend-only and installation tokens are short-lived. Private
Actions sharing access remains separate from the App access needed by this Dashboard.
All authorized Dashboard users can read the tracked repositories (the existing shared
workspace authorization model). Live private-repository access must be verified after
the administrator configures the App; no PAT fallback is implemented.

For local startup, put these settings in the ignored `.env` file at the project root
and run `./start-dashboard.ps1`. The launcher loads `.env` into the server process.
Do not put private key contents in `.env`; configure the path to the PEM only.

GitHub credentials are also read directly from the project-root `.env` by the backend.
This works with direct Uvicorn startup and with a different working directory; nonempty
process environment values override file values. Other app settings still follow their
existing environment configuration. No private key contents are copied into the project.

## Trusted producer and deployment checks

The importer requires GitHub's `referenced_workflows` metadata to identify
`TRM-MYOS/devsecops-security-platform/.github/workflows/security-scan.yml@main`,
and exactly one completed job named `Central Security Gate / Run Central Security Scan`.
A connector containing extra jobs is rejected because another job could forge the report
artifact. Report name, run/commit identity when supplied by GitHub, attempt timestamps,
report contents, and ALLOW/success consistency are checked. These checks trust Central;
they do not replace branch protection or cryptographic artifact attestations. Historical
policies are not recalculated using today's policy configuration.

Before publishing the changes:

- Protect Central `main`: require a pull request, restrict bypass, require review of changes
  to `.github/workflows/`, `action.yml`, `scanner/`, `security/`, and `security-policy.yaml`.
  This is essential while the reusable workflow and action use the mutable `@main` ref.
- Protect Test `main`: require `Central Security Gate / Run Central Security Scan`, bound
  to the GitHub Actions integration. Keep the exact job names; review bypass permissions
  and workflow changes. A failed status alone does not enforce merge blocking without this rule.
- The Test trigger is now all push branches plus pull requests into `main`. Apply the same
  connector to other repositories that should generate scan results.
- Publish Central's parser/scanner changes before relying on Test's widened trigger.
  Local changes do not change existing remote workflow runs. No commit or push is performed
  by the application.
- Start one backend worker and keep the database path stable across restarts. Schema setup
  only adds missing tables and preserves existing users, sessions, repositories and scans.

Every scanner subprocess has a default 600-second timeout. Set
`DEVSECOPS_SCANNER_TIMEOUT_SECONDS` to a positive integer in the backend/CLI environment
if necessary. The reusable job has a 40-minute overall timeout. Timeout, tool errors and
invalid reports fail closed. Trivy Secrets contribute SECRET findings with their actual
severity; sensitive Match and Code fields are not copied into normalized findings.

Regression checks:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
node --test tests/dashboard-ui.test.cjs
```

Tests include two independent Python processes sharing an isolated persistent database,
real subprocess timeout termination, failed reports, and historical run import. Live checks
must use temporary target directories/databases, never replace the active database.
