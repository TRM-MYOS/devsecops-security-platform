from datetime import datetime, timezone
from pathlib import Path
import os
import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ConfigDict
from repository import github_monitor
from repository.github_client import configured as github_configured
from scanner.repository_scanner import validate_repository

from api.auth_routes import router as auth_router
from api.owner_settings_routes import router as owner_settings_router
from api.member_routes import router as member_router
from repository import membership
from auth.settings import Settings
from auth.web import AuthenticationMiddleware

from repository.repository_manager import (
    RepositoryManager,
)

from scanner.security_scanner import (
    run_security_scan,
)

from security.parser import (
    parse_reports,
)

from security.policy import (
    evaluate_policy,
    load_policy_config,
    load_local_policy,
)

from security.scoring import (
    SEVERITY_PENALTY,
    calculate_grade,
    calculate_score,
)


# =========================================================
# APPLICATION
# =========================================================

auth_settings = Settings.from_environment()


@asynccontextmanager
async def lifespan(application):
    stop = threading.Event()
    worker = None
    if os.environ.get("DEVSECOPS_GITHUB_POLL_ENABLED", "true").lower() == "true":
        worker = threading.Thread(target=github_monitor.poll_repositories,
                                  args=(repository_manager, stop), daemon=True, name="github-monitor")
        worker.start()
    try:
        yield
    finally:
        stop.set()
        if worker:
            worker.join(timeout=1)


app = FastAPI(
    lifespan=lifespan,
    title="DevSecOps Security Platform",
    version="1.0.0",
    description=(
        "Central security platform "
        "for multiple repositories"
    ),
    docs_url="/docs" if auth_settings.environment == "development" else None,
    redoc_url="/redoc" if auth_settings.environment == "development" else None,
    openapi_url="/openapi.json" if auth_settings.environment == "development" else None,
)

app.state.auth_settings = auth_settings
app.include_router(auth_router)
app.include_router(owner_settings_router)
app.include_router(member_router)
app.add_middleware(AuthenticationMiddleware)


@app.exception_handler(membership.NotFound)
async def missing_resource(request, error):
    return JSONResponse(status_code=404, content={"detail": str(error)})


@app.exception_handler(membership.Conflict)
async def conflicting_resource(request, error):
    return JSONResponse(status_code=409, content={"detail": str(error)})


@app.exception_handler(PermissionError)
async def denied_resource(request, error):
    return JSONResponse(status_code=403, content={"detail": "Insufficient permissions"})


@app.exception_handler(ValueError)
async def invalid_resource(request, error):
    return JSONResponse(status_code=400, content={"detail": str(error)})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request, error):
    # FastAPI normally echoes invalid input; login/user payloads contain passwords.
    return JSONResponse(
        status_code=422,
        content={
            "detail": [
                {"loc": issue["loc"], "msg": issue["msg"], "type": issue["type"]}
                for issue in error.errors()
            ]
        },
    )


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=list(app.state.auth_settings.allowed_origins),
    allow_credentials=True,
    allow_methods=["GET", "HEAD", "POST", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-CSRF-Token"],
)


# =========================================================
# PATHS
# =========================================================

BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DASHBOARD_DIR = BASE_DIR / "dashboard"


# =========================================================
# DASHBOARD
# =========================================================

app.mount(
    "/dashboard",
    StaticFiles(
        directory=DASHBOARD_DIR,
        html=True,
    ),
    name="dashboard",
)


# =========================================================
# REPOSITORY MANAGER
# =========================================================

repository_manager = RepositoryManager()


def visible_repositories(request):
    allowed = membership.visible_ids(request.state.user["id"])
    return [r for r in repository_manager.get_repositories() if r["id"] in allowed]


# =========================================================
# REQUEST MODEL
# =========================================================

class RepositoryRequest(BaseModel):
    repo_url: str


# =========================================================
# ROOT
# =========================================================

@app.get("/")
def root():
    return RedirectResponse(
        url="/dashboard/"
    )


# =========================================================
# HEALTH
# =========================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "DevSecOps Security Platform",
    }


@app.get("/api/policy")
def get_security_policy():
    from repository import policy_settings
    try:
        config = load_local_policy()
        settings = policy_settings.status()
    except (OSError, RuntimeError, ValueError) as error:
        raise HTTPException(status_code=503, detail="Security policy configuration is unavailable") from error
    if not isinstance(config, dict):
        raise HTTPException(status_code=503, detail="Security policy configuration is invalid")
    policy = config.get("policy", {})
    baseline_minimum = policy["minimum_score"]
    policy["minimum_score"] = settings["minimum_score"]
    severity = config.get("severity", {})
    if not isinstance(policy, dict) or not isinstance(severity, dict):
        raise HTTPException(status_code=503, detail="Security policy configuration is invalid")
    minimum_by_grade = {}
    for score in range(101):
        minimum_by_grade.setdefault(calculate_grade(score), score)
    grade_bands = [
        {"grade": grade, "minimum_score": minimum}
        for grade, minimum in sorted(
            minimum_by_grade.items(), key=lambda item: item[1], reverse=True
        )
    ]
    return {
        "policy": policy,
        "severity": severity,
        "severity_penalties": dict(SEVERITY_PENALTY),
        "grade_bands": grade_bands,
        "settings": settings,
        "central_file_minimum": baseline_minimum,
    }


class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    minimum_score: int = Field(ge=0, le=100, strict=True)


@app.patch("/api/policy")
def update_security_policy(payload: PolicyRequest, request: Request):
    from repository import policy_settings
    policy_settings.save(payload.minimum_score, request.state.user["id"])
    return get_security_policy()


class PolicyPublicationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(min_length=1, max_length=100)


@app.post("/api/policy/publish")
def publish_security_policy(payload: PolicyPublicationRequest, request: Request):
    from repository import policy_publisher
    try:
        policy_publisher.publish(payload.version, request.state.user["id"])
        return get_security_policy()
    except policy_publisher.PublicationError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.post("/api/policy/publication/check")
def check_policy_publication(payload: PolicyPublicationRequest, request: Request):
    from repository import policy_publisher
    try:
        policy_publisher.check(payload.version, request.state.user["id"])
        return get_security_policy()
    except policy_publisher.PublicationError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error


@app.get("/policy/v1")
def public_policy():
    from repository import policy_settings
    try:
        return JSONResponse(policy_settings.publication(), headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
    except RuntimeError as error:
        raise HTTPException(status_code=503, detail="Policy publication unavailable") from error


# =========================================================
# ADD REPOSITORY
# =========================================================

@app.post("/api/repositories")
def add_repository(
    request: RepositoryRequest,
    http_request: Request,
):

    try:

        repository = membership.enroll(request.repo_url, http_request.state.user["id"])

        return {
            "status": "success",
            "repository": repository,
        }

    except ValueError as error:

        raise HTTPException(
            status_code=400,
            detail=str(error),
        )


# =========================================================
# GET ALL REPOSITORIES
# =========================================================

@app.get("/api/repositories")
def get_repositories(request: Request):

    repositories = visible_repositories(request)

    return {
        "repositories": [dict(repository, tracking=github_monitor.tracking(repository["id"])) for repository in repositories],
        "count": len(repositories),
    }


# =========================================================
# GET SINGLE REPOSITORY
# =========================================================

@app.get(
    "/api/repositories/{repository_id}"
)
def get_repository(
    repository_id: int,
):

    repository = (
        repository_manager
        .get_repository(
            repository_id
        )
    )

    if repository is None:

        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )

    return {
        "repository": repository,
    }


# =========================================================
# DELETE REPOSITORY
# =========================================================

@app.delete(
    "/api/repositories/{repository_id}"
)
def delete_repository(
    repository_id: int,
    request: Request,
):

    membership.delete_repository(request.state.user["id"], repository_id)
    deleted = True

    if not deleted:

        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )

    return {
        "status": "success",
        "message": "Repository deleted",
        "repository_id": repository_id,
    }


# =========================================================
# INTERNAL SCAN FUNCTION
# =========================================================

def execute_repository_scan(
    repository_id: int,
):

    repository = (
        repository_manager
        .get_repository(
            repository_id
        )
    )

    if repository is None:

        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )


    scan_time = (
        datetime.now(
            timezone.utc
        ).isoformat()
    )


    scan_data = None


    try:

        # -------------------------------------------------
        # 1. Clone repository
        # -------------------------------------------------

        scan_data = (
            repository_manager
            .scan_repository(
                repository["url"]
            )
        )


        temp_dir = (
            scan_data["temp_dir"]
        )


        repo_path = (
            scan_data["repo_path"]
        )


        # -------------------------------------------------
        # 2. Reports directory
        # -------------------------------------------------

        reports_path = (
            Path(temp_dir.name)
            / "reports"
        )


        # -------------------------------------------------
        # 3. Run scanners
        # -------------------------------------------------

        scanner_results = (
            run_security_scan(
                repo_path,
                reports_path,
            )
        )


        # -------------------------------------------------
        # 4. Report files
        # -------------------------------------------------

        bandit_file = (
            reports_path
            / "bandit.json"
        )

        trivy_file = (
            reports_path
            / "trivy.json"
        )

        gitleaks_file = (
            reports_path
            / "gitleaks.json"
        )


        # -------------------------------------------------
        # 5. Parse findings
        # -------------------------------------------------

        # Parser also serves the CLI, where SystemExit is intentional. Convert
        # it only at this boundary so report failures cannot escape an API call.
        try:
            findings = parse_reports(
                bandit_file,
                trivy_file,
                gitleaks_file,
            )
        except SystemExit as error:
            raise HTTPException(
                status_code=500,
                detail=str(error) or "Report validation failed",
            ) from error


        # -------------------------------------------------
        # 6. Score
        # -------------------------------------------------

        score = calculate_score(
            findings
        )


        # -------------------------------------------------
        # 7. Grade
        # -------------------------------------------------

        grade = calculate_grade(
            score
        )


        # -------------------------------------------------
        # 8. Security policy
        # -------------------------------------------------

        policy_result = (
            evaluate_policy(
                findings,
                score,
            )
        )


        status = (
            policy_result["status"]
        )

        reason = (
            policy_result["reason"]
        )


        # -------------------------------------------------
        # 9. Save scan to database
        # -------------------------------------------------

        scan_id = (
            repository_manager
            .save_scan(
                repository_id=repository_id,
                scanned_at=scan_time,
                score=score,
                grade=grade,
                status=status,
                reason=reason,
                findings=findings,
                policy=policy_result.get("policy"),
            )
        )


        # -------------------------------------------------
        # 10. Scanner counts
        # -------------------------------------------------

        scanner_counts = {
            "Bandit": 0,
            "Trivy": 0,
            "Gitleaks": 0,
        }


        # -------------------------------------------------
        # 11. Severity counts
        # -------------------------------------------------

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }


        for finding in findings:

            scanner = finding.get(
                "scanner"
            )


            if scanner in scanner_counts:

                scanner_counts[
                    scanner
                ] += 1


            severity = str(
                finding.get(
                    "severity",
                    "UNKNOWN",
                )
            ).upper()


            if severity not in severity_counts:

                severity = "UNKNOWN"


            severity_counts[
                severity
            ] += 1


        # -------------------------------------------------
        # 12. Return result
        # -------------------------------------------------

        return {

            "scan_id": scan_id,

            "repository":
                repository_manager
                .get_repository(
                    repository_id
                ),

            "status": status,

            "score": score,

            "grade": grade,

            "reason": reason,

            "findings":
                len(findings),

            "scanner_counts":
                scanner_counts,

            "severity_counts":
                severity_counts,

            "findings_data":
                findings,

            "scanner_results": {

                "bandit":
                    scanner_results[
                        "bandit"
                    ][
                        "returncode"
                    ],

                "trivy":
                    scanner_results[
                        "trivy"
                    ][
                        "returncode"
                    ],

                "gitleaks":
                    scanner_results[
                        "gitleaks"
                    ][
                        "returncode"
                    ],

            },

        }


    except (OSError, RuntimeError) as error:
        raise HTTPException(
            status_code=500,
            detail=f"Scan execution failed: {error}",
        ) from error

    finally:

        if scan_data is not None:

            temp_dir = (
                scan_data["temp_dir"]
            )

            temp_dir.cleanup()


# =========================================================
# SCAN ONE REPOSITORY
# =========================================================

@app.post(
    "/api/repositories/{repository_id}/scan"
)
def scan_repository(
    repository_id: int,
    request: Request,
):

    result = execute_repository_scan(
        repository_id
    )
    membership.check(request.state.user["id"], repository_id, manage=True)
    return result


# =========================================================
# SCAN ALL REPOSITORIES
# =========================================================

@app.post(
    "/api/repositories/scan-all"
)
def scan_all_repositories(request: Request):

    repositories = visible_repositories(request)


    if not repositories:

        return {
            "status": "success",
            "message": "No repositories found",
            "total": 0,
            "successful": 0,
            "failed": 0,
            "results": [],
        }


    results = []


    for repository in repositories:

        repository_id = (
            repository["id"]
        )


        try:

            membership.check(request.state.user["id"], repository_id, manage=True)

            scan_result = (
                execute_repository_scan(
                    repository_id
                )
            )
            membership.check(request.state.user["id"], repository_id, manage=True)


            results.append({

                "repository_id":
                    repository_id,

                "repository_name":
                    repository["name"],

                "status":
                    "success",

                "scan":
                    scan_result,

            })


        except (membership.NotFound, PermissionError):
            continue

        except Exception as error:

            results.append({

                "repository_id":
                    repository_id,

                "repository_name":
                    repository["name"],

                "status":
                    "failed",

                "error":
                    error.detail if isinstance(error, HTTPException) else str(error),

            })


    successful = sum(
        1
        for result in results
        if result["status"]
        == "success"
    )


    failed = (
        len(results)
        - successful
    )


    return {

        "status":
            "completed",

        "total":
            len(results),

        "successful":
            successful,

        "failed":
            failed,

        "results":
            results,

    }


# =========================================================
# REPOSITORY HISTORY
# =========================================================

@app.get(
    "/api/repositories/{repository_id}/history"
)
def get_repository_history(
    repository_id: int,
):

    repository = (
        repository_manager
        .get_repository(
            repository_id
        )
    )


    if repository is None:

        raise HTTPException(
            status_code=404,
            detail="Repository not found",
        )


    history = (
        repository_manager
        .get_scan_history(
            repository_id
        )
    )


    return {

        "repository":
            repository,

        "history":
            history,

        "count":
            len(history),

    }


# =========================================================
# ALL SCAN HISTORY
# =========================================================

@app.get("/api/scans")
def get_all_scans(request: Request):

    scans = (
        repository_manager
        .get_all_scans()
    )

    allowed = membership.visible_ids(request.state.user["id"])
    scans = [scan for scan in scans if scan["repository_id"] in allowed]
    attempts = [row for row in github_monitor.run_history() if row["repository_id"] in allowed]
    invalidated = {(row["repository_id"], row["github"].get("run_id"), row["github"].get("run_attempt")) for row in attempts}
    records = []
    for scan in scans:
        metadata = github_monitor.scan_metadata(scan["id"])
        if metadata and (scan["repository_id"], metadata.get("run_id"), metadata.get("run_attempt")) in invalidated:
            continue
        records.append(dict(scan, github=metadata, policy=(metadata or {}).get("policy") or repository_manager.get_scan_policy(scan["id"])))
    records.extend(attempts)
    records.sort(key=lambda record: record.get("scanned_at") or "", reverse=True)


    return {

        "scans": records,

        "count":
            len(records),

    }


# =========================================================
# SCAN FINDINGS
# =========================================================

@app.get("/api/scans/{record_id}")
def get_scan_record(record_id: str, request: Request):
    if record_id.isdigit():
        record = repository_manager.get_scan(membership.parse_id(record_id))
    else:
        parts = record_id.split("-")
        row = github_monitor.run_record(*(membership.parse_id(part) for part in parts[1:])) if len(parts)==4 and parts[0]=="run" else None
        record = (repository_manager.get_scan(row["scan_id"]) if row["scan_id"] is not None else github_monitor.error_record(row)) if row else None
    if record is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    membership.check(request.state.user["id"], record["repository_id"])
    if record.get("report_available") is not False:
        metadata = github_monitor.scan_metadata(record["id"])
        row = github_monitor.run_record(record["repository_id"], metadata["run_id"], metadata.get("run_attempt", 1)) if metadata and metadata.get("run_id") else None
        if row is not None and row["scan_id"] is None:
            record = dict(github_monitor.error_record(row), id=record["id"])
        else:
            record.update(github=metadata, policy=(metadata or {}).get("policy") or repository_manager.get_scan_policy(record["id"]))
    return {"scan": record}


@app.get(
    "/api/scans/{scan_id}/findings"
)
def get_scan_findings(
    scan_id: int,
):

    findings = (
        repository_manager
        .get_scan_findings(
            scan_id
        )
    )


    return {

        "scan_id":
            scan_id,

        "findings":
            findings,

        "count":
            len(findings),

    }


# =========================================================
# LEGACY SCAN
# =========================================================

class GitHubSyncRequest(BaseModel):
    branch: str | None = None


@app.get("/api/github/status")
def github_status():
    from repository.owner_settings import current, FIELDS
    return {"configured": github_configured(), "authentication": "github_app",
            "owner": current()[FIELDS["owner"]]}


@app.post("/api/repositories/{repository_id}/sync")
def sync_github_repository(repository_id: int, http_request: Request, request: GitHubSyncRequest | None = None):
    if repository_manager.get_repository(repository_id) is None:
        raise HTTPException(status_code=404, detail="Repository not found")
    try:
        if request and request.branch:
            result = github_monitor.sync_repository(repository_manager, repository_id, request.branch)
        else:
            result = github_monitor.sync_all_branches(repository_manager, repository_id)
        membership.check(http_request.state.user["id"], repository_id, manage=True)
        return result
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error


@app.post("/api/github/sync")
def sync_github_repositories(request: Request):
    results = []
    for repository in visible_repositories(request):
        try:
            membership.check(request.state.user["id"], repository["id"], manage=True)
            result = github_monitor.sync_all_branches(repository_manager, repository["id"])
            membership.check(request.state.user["id"], repository["id"], manage=True)
        except (membership.NotFound, PermissionError):
            continue
        except Exception:
            result = {"execution_status": "error", "policy_status": None, "message": "Repository synchronization failed"}
        results.append({"repository_name": repository["name"], **result})
    return {"results": results, "total": len(results)}


@app.post("/scan")
def legacy_scan(
    request: RepositoryRequest,
    http_request: Request,
):

    repository = membership.enroll(request.repo_url, http_request.state.user["id"])


    result = execute_repository_scan(
        repository["id"]
    )
    membership.check(http_request.state.user["id"], repository["id"], manage=True)
    return result
