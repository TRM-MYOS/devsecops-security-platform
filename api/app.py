from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

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
)

from security.scoring import (
    calculate_grade,
    calculate_score,
)


# =========================================================
# APPLICATION
# =========================================================

app = FastAPI(
    title="DevSecOps Security Platform",
    version="1.0.0",
    description=(
        "Central security platform "
        "for multiple repositories"
    ),
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
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


# =========================================================
# ADD REPOSITORY
# =========================================================

@app.post("/api/repositories")
def add_repository(
    request: RepositoryRequest,
):

    try:

        repository = (
            repository_manager
            .add_repository(
                request.repo_url
            )
        )

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
def get_repositories():

    repositories = (
        repository_manager
        .get_repositories()
    )

    return {
        "repositories": repositories,
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
):

    deleted = (
        repository_manager
        .delete_repository(
            repository_id
        )
    )

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

        findings = (
            parse_reports(
                bandit_file,
                trivy_file,
                gitleaks_file,
            )
        )


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
):

    return execute_repository_scan(
        repository_id
    )


# =========================================================
# SCAN ALL REPOSITORIES
# =========================================================

@app.post(
    "/api/repositories/scan-all"
)
def scan_all_repositories():

    repositories = (
        repository_manager
        .get_repositories()
    )


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

            scan_result = (
                execute_repository_scan(
                    repository_id
                )
            )


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


        except Exception as error:

            results.append({

                "repository_id":
                    repository_id,

                "repository_name":
                    repository["name"],

                "status":
                    "failed",

                "error":
                    str(error),

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
            len(repositories),

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
def get_all_scans():

    scans = (
        repository_manager
        .get_all_scans()
    )


    return {

        "scans":
            scans,

        "count":
            len(scans),

    }


# =========================================================
# SCAN FINDINGS
# =========================================================

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

@app.post("/scan")
def legacy_scan(
    request: RepositoryRequest,
):

    repository = (
        repository_manager
        .add_repository(
            request.repo_url
        )
    )


    return execute_repository_scan(
        repository["id"]
    )