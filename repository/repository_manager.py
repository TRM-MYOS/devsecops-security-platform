from datetime import datetime, timezone
from pathlib import Path

from repository.database import (
    get_connection,
    initialize_database,
)
from scanner.repository_scanner import (
    clone_repository,
)


class RepositoryManager:

    def __init__(self):
        initialize_database()


    # =====================================================
    # REPOSITORY
    # =====================================================

    def add_repository(
        self,
        repo_url: str,
    ):

        repo_url = repo_url.strip()


        if not repo_url:

            raise ValueError(
                "Repository URL is required"
            )


        name = (
            repo_url
            .rstrip("/")
            .split("/")[-1]
        )


        if name.endswith(".git"):

            name = name[:-4]


        if not name:

            raise ValueError(
                "Unable to determine repository name"
            )


        created_at = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


        connection = get_connection()


        try:

            existing = connection.execute(
                """
                SELECT *
                FROM repositories
                WHERE url = ?
                """,
                (repo_url,),
            ).fetchone()


            if existing:

                return dict(existing)


            cursor = connection.execute(
                """
                INSERT INTO repositories (
                    name,
                    url,
                    created_at
                )
                VALUES (?, ?, ?)
                """,
                (
                    name,
                    repo_url,
                    created_at,
                ),
            )


            connection.commit()


            repository_id =cursor.lastrowid


            repository = connection.execute(
                """
                SELECT *
                FROM repositories
                WHERE id = ?
                """,
                (repository_id,),
            ).fetchone()


            return dict(repository)

        finally:

            connection.close()


    def get_repositories(self):

        connection = get_connection()


        try:

            rows = connection.execute(
                """
                SELECT *
                FROM repositories
                ORDER BY
                    COALESCE(
                        last_scan,
                        created_at
                    ) DESC
                """
            ).fetchall()


            return [
                dict(row)
                for row in rows
            ]

        finally:

            connection.close()


    def get_repository(
        self,
        repository_id: int,
    ):

        connection = get_connection()


        try:

            row = connection.execute(
                """
                SELECT *
                FROM repositories
                WHERE id = ?
                """,
                (repository_id,),
            ).fetchone()


            if row is None:

                return None


            return dict(row)

        finally:

            connection.close()


    def delete_repository(
        self,
        repository_id: int,
    ):

        connection = get_connection()


        try:

            cursor = connection.execute(
                """
                DELETE FROM repositories
                WHERE id = ?
                """,
                (repository_id,),
            )


            connection.commit()


            return cursor.rowcount > 0

        finally:

            connection.close()


    # =====================================================
    # CLONE
    # =====================================================

    def scan_repository(
        self,
        repo_url: str,
    ):

        temp_dir, repo_path = (
            clone_repository(
                repo_url
            )
        )


        return {
            "temp_dir": temp_dir,
            "repo_path": Path(
                repo_path
            ),
        }


    # =====================================================
    # SAVE SCAN
    # =====================================================

    def save_scan(
        self,
        repository_id: int,
        scanned_at: str,
        score: int,
        grade: str,
        status: str,
        reason: str,
        findings: list,
        connection=None,
    ):

        owns_connection = connection is None
        connection = connection if connection is not None else get_connection()


        try:

            cursor = connection.execute(
                """
                INSERT INTO scans (
                    repository_id,
                    scanned_at,
                    score,
                    grade,
                    status,
                    reason,
                    findings
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    repository_id,
                    scanned_at,
                    score,
                    grade,
                    status,
                    reason,
                    len(findings),
                ),
            )


            scan_id = cursor.lastrowid


            for finding in findings:

                connection.execute(
                    """
                    INSERT INTO findings (
                        scan_id,
                        scanner,
                        category,
                        severity,
                        confidence,
                        file,
                        line,
                        rule_id,
                        message,
                        cwe
                    )
                    VALUES (
                        ?, ?, ?, ?, ?, ?,
                        ?, ?, ?, ?
                    )
                    """,
                    (
                        scan_id,
                        finding.get(
                            "scanner"
                        ),
                        finding.get(
                            "category"
                        ),
                        finding.get(
                            "severity"
                        ),
                        finding.get(
                            "confidence"
                        ),
                        finding.get(
                            "file"
                        ),
                        finding.get(
                            "line"
                        ),
                        finding.get(
                            "rule_id"
                        ),
                        finding.get(
                            "message"
                        ),
                        finding.get(
                            "cwe"
                        ),
                    ),
                )


            connection.execute(
                """
                UPDATE repositories
                SET
                    last_scan = ?,
                    score = ?,
                    grade = ?,
                    status = ?,
                    reason = ?,
                    findings = ?
                WHERE id = ?
                  AND (julianday(last_scan) IS NULL OR julianday(last_scan) <= julianday(?))
                """,
                (
                    scanned_at,
                    score,
                    grade,
                    status,
                    reason,
                    len(findings),
                    repository_id,
                    scanned_at,
                ),
            )


            if owns_connection:
                connection.commit()


            return scan_id

        finally:

            if owns_connection:
                connection.close()


    # =====================================================
    # SCAN HISTORY
    # =====================================================

    def get_scan_history(
        self,
        repository_id: int,
    ):

        connection = get_connection()


        try:

            rows = connection.execute(
                """
                SELECT *
                FROM scans
                WHERE repository_id = ?
                ORDER BY
                    scanned_at DESC
                """
            ,
                (repository_id,),
            ).fetchall()


            return [
                dict(row)
                for row in rows
            ]

        finally:

            connection.close()


    # =====================================================
    # FINDINGS
    # =====================================================

    def get_scan_findings(
        self,
        scan_id: int,
    ):

        connection = get_connection()


        try:

            rows = connection.execute(
                """
                SELECT *
                FROM findings
                WHERE scan_id = ?
                ORDER BY id ASC
                """,
                (scan_id,),
            ).fetchall()


            return [
                dict(row)
                for row in rows
            ]

        finally:

            connection.close()


    # =====================================================
    # LATEST SCAN
    # =====================================================

    def get_latest_scan(
        self,
        repository_id: int,
    ):

        connection = get_connection()


        try:

            row = connection.execute(
                """
                SELECT *
                FROM scans
                WHERE repository_id = ?
                ORDER BY
                    scanned_at DESC
                LIMIT 1
                """,
                (repository_id,),
            ).fetchone()


            if row is None:

                return None


            return dict(row)

        finally:

            connection.close()


    # =====================================================
    # ALL SCANS
    # =====================================================

    def get_all_scans(self):

        connection = get_connection()


        try:

            rows = connection.execute(
                """
                SELECT
                    scans.*,
                    repositories.name
                        AS repository_name,
                    repositories.url
                        AS repository_url
                FROM scans
                JOIN repositories
                    ON repositories.id =
                       scans.repository_id
                ORDER BY
                    scans.scanned_at DESC
                """
            ).fetchall()


            return [
                dict(row)
                for row in rows
            ]

        finally:

            connection.close()
