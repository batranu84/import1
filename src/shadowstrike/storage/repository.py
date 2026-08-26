from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Iterable, Optional, Union
from uuid import UUID

from shadowstrike.models.domain import AssessmentRequest, AssessmentResult, ModuleStatus


SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    request_json TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS module_checkpoints (
    assessment_id TEXT NOT NULL,
    module_name TEXT NOT NULL,
    status_json TEXT NOT NULL,
    PRIMARY KEY (assessment_id, module_name)
);
CREATE TABLE IF NOT EXISTS engine_checkpoints (
    assessment_id TEXT NOT NULL,
    engine_name TEXT NOT NULL,
    checkpoint_json TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (assessment_id, engine_name)
);
CREATE TABLE IF NOT EXISTS adapter_cache (
    cache_key TEXT PRIMARY KEY,
    payload_json TEXT NOT NULL,
    expires_at REAL NOT NULL
);
"""


class AssessmentRepository:
    """Small durable store used by both CLI and API.

    JSON snapshots deliberately mirror the public Pydantic models so that migrations can
    remain explicit as the evidence schema evolves.
    """

    def __init__(self, path: Union[str, Path] = "shadowstrike.db") -> None:
        self.path = str(path)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        return con

    def _init_schema(self) -> None:
        with self._connect() as con:
            con.executescript(SCHEMA)

    def save(self, request: AssessmentRequest, result: AssessmentResult) -> None:
        request_json = request.model_dump_json()
        result_json = result.model_dump_json()
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO assessments(id, name, profile, status, request_json, result_json)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name,
                    profile=excluded.profile,
                    status=excluded.status,
                    request_json=excluded.request_json,
                    result_json=excluded.result_json,
                    updated_at=CURRENT_TIMESTAMP
                """,
                (str(result.id), result.name, result.profile, result.status, request_json, result_json),
            )

    def save_module_statuses(self, assessment_id: UUID, statuses: Iterable[ModuleStatus]) -> None:
        with self._connect() as con:
            for status in statuses:
                con.execute(
                    """
                    INSERT INTO module_checkpoints(assessment_id, module_name, status_json)
                    VALUES (?, ?, ?)
                    ON CONFLICT(assessment_id, module_name) DO UPDATE SET status_json=excluded.status_json
                    """,
                    (str(assessment_id), status.name, status.model_dump_json()),
                )

    def load(self, assessment_id: Union[UUID, str]) -> Optional[tuple[AssessmentRequest, AssessmentResult]]:
        with self._connect() as con:
            row = con.execute(
                "SELECT request_json, result_json FROM assessments WHERE id=?", (str(assessment_id),)
            ).fetchone()
        if row is None:
            return None
        return (
            AssessmentRequest.model_validate_json(row["request_json"]),
            AssessmentResult.model_validate_json(row["result_json"]),
        )


    def save_engine_checkpoint(self, assessment_id: Union[UUID, str], engine_name: str, state: dict) -> None:
        payload = json.dumps(state, sort_keys=True)
        with self._connect() as con:
            con.execute(
                """
                INSERT INTO engine_checkpoints(assessment_id, engine_name, checkpoint_json)
                VALUES (?, ?, ?)
                ON CONFLICT(assessment_id, engine_name) DO UPDATE SET
                    checkpoint_json=excluded.checkpoint_json, updated_at=CURRENT_TIMESTAMP
                """,
                (str(assessment_id), engine_name, payload),
            )

    def load_engine_checkpoint(self, assessment_id: Union[UUID, str], engine_name: str) -> Optional[dict]:
        with self._connect() as con:
            row = con.execute(
                "SELECT checkpoint_json FROM engine_checkpoints WHERE assessment_id=? AND engine_name=?",
                (str(assessment_id), engine_name),
            ).fetchone()
        return json.loads(row["checkpoint_json"]) if row else None

    def clear_engine_checkpoint(self, assessment_id: Union[UUID, str], engine_name: str) -> None:
        with self._connect() as con:
            con.execute(
                "DELETE FROM engine_checkpoints WHERE assessment_id=? AND engine_name=?",
                (str(assessment_id), engine_name),
            )

    def cache_put(self, key: str, payload: dict, expires_at: float) -> None:
        with self._connect() as con:
            con.execute(
                """INSERT INTO adapter_cache(cache_key,payload_json,expires_at) VALUES(?,?,?)
                ON CONFLICT(cache_key) DO UPDATE SET payload_json=excluded.payload_json, expires_at=excluded.expires_at""",
                (key, json.dumps(payload, sort_keys=True), expires_at),
            )

    def cache_get(self, key: str, now: float) -> Optional[dict]:
        with self._connect() as con:
            row = con.execute(
                "SELECT payload_json, expires_at FROM adapter_cache WHERE cache_key=?", (key,)
            ).fetchone()
            if not row or float(row["expires_at"]) < now:
                if row:
                    con.execute("DELETE FROM adapter_cache WHERE cache_key=?", (key,))
                return None
        return json.loads(row["payload_json"])

    def list_recent(self, limit: int = 20) -> list[dict[str, str]]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT id, name, profile, status, updated_at FROM assessments ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_by_name(self, name: str, limit: int = 20) -> list[AssessmentResult]:
        with self._connect() as con:
            rows = con.execute(
                "SELECT result_json FROM assessments WHERE name=? ORDER BY updated_at DESC LIMIT ?",
                (name, limit),
            ).fetchall()
        return [AssessmentResult.model_validate_json(row["result_json"]) for row in rows]
