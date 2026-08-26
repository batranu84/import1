from __future__ import annotations

from datetime import datetime, timezone
from shadowstrike.utils.compat import StrEnum
from typing import Any, Optional
from urllib.parse import urlparse
import ipaddress
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    INFORMATIONAL = "informational"
    PROBABLE = "probable"
    HIGH = "high"
    CONFIRMED = "confirmed"


class AssessmentMode(StrEnum):
    EXTERNAL = "external"
    INTERNAL = "internal"
    HYBRID = "hybrid"


class ModuleState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class ScopePolicy(BaseModel):
    allowed_domains: list[str] = Field(default_factory=list)
    allowed_cidrs: list[str] = Field(default_factory=list)
    excluded_domains: list[str] = Field(default_factory=list)
    excluded_cidrs: list[str] = Field(default_factory=list)
    max_requests_per_second: int = Field(default=25, ge=1, le=10000)
    max_concurrency: int = Field(default=128, ge=1, le=4096)
    allow_active_web: bool = True
    allow_load_testing: bool = False
    allow_controlled_validation: bool = False
    allow_udp_discovery: bool = True
    max_udp_hosts: int = Field(default=256, ge=1, le=4096)
    snmp_communities: list[str] = Field(default_factory=list)
    allow_specialist_tools: bool = False
    specialist_tools: list[str] = Field(default_factory=list)
    allow_deep_nmap: bool = True
    allow_deep_crawl: bool = True
    max_crawl_pages: int = Field(default=300, ge=10, le=5000)
    max_crawl_depth: int = Field(default=6, ge=1, le=20)
    validation_authorization_reference: Optional[str] = None

    @field_validator("allowed_domains", "excluded_domains", mode="before")
    @classmethod
    def normalize_domains(cls, value):
        out: list[str] = []
        for raw in value or []:
            item = str(raw).strip()
            if not item:
                continue
            wildcard = item.startswith("*.")
            parse_item = item[2:] if wildcard else item
            parsed = urlparse(parse_item if "://" in parse_item else f"//{parse_item}")
            host = (parsed.hostname or parse_item).lower().strip("[]").rstrip(".")
            if host:
                normalized = f"*.{host}" if wildcard else host
                if normalized not in out:
                    out.append(normalized)
        return out

    @field_validator("allowed_cidrs", "excluded_cidrs", mode="before")
    @classmethod
    def normalize_cidrs(cls, value):
        out: list[str] = []
        for raw in value or []:
            item = str(raw).strip()
            if not item:
                continue
            normalized = str(ipaddress.ip_network(item, strict=False))
            if normalized not in out:
                out.append(normalized)
        return out


class AssessmentRequest(BaseModel):
    name: str
    targets: list[str]
    profile: str = "full"
    mode: AssessmentMode = AssessmentMode.HYBRID
    authorization_reference: str
    scope: ScopePolicy


class Asset(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    kind: str
    value: str
    source: str
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    attributes: dict[str, Any] = Field(default_factory=dict)


class Evidence(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    asset_id: Optional[UUID] = None
    engine: str
    category: str
    summary: str
    raw: dict[str, Any] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    fingerprint: Optional[str] = None


class ValidationState(StrEnum):
    UNVALIDATED = "unvalidated"
    AUTHORIZED = "validation-authorized"
    POC_PREPARED = "poc-prepared"
    EXECUTION_ATTEMPTED = "execution-attempted"
    EXPLOIT_CONFIRMED = "exploit-confirmed"
    ACCESS_CONFIRMED = "access-confirmed"
    PROOF_ACHIEVED = "proof-objective-achieved"
    CLEANUP_CONFIRMED = "cleanup-confirmed"
    VALIDATION_FAILED = "validation-failed"


class ProofObjective(BaseModel):
    description: str
    marker: str
    objective_type: str = "harmless-marker"
    expected_access_level: Optional[str] = None


class PocArtifact(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    artifact_type: str
    title: str
    content: str
    safety_notes: Optional[str] = None
    non_persistent: bool = True
    credential_access: bool = False
    destructive: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidationSession(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    state: ValidationState = ValidationState.UNVALIDATED
    authorization_reference: str
    operator: Optional[str] = None
    technique: str
    expected_effect: Optional[str] = None
    proof_objective: ProofObjective
    safety_constraints: list[str] = Field(default_factory=list)
    poc_artifacts: list[PocArtifact] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    attempt_evidence_ids: list[UUID] = Field(default_factory=list)
    proof_evidence_ids: list[UUID] = Field(default_factory=list)
    access_level_achieved: Optional[str] = None
    proof_marker_observed: Optional[str] = None
    cleanup_confirmed: bool = False
    cleanup_evidence_ids: list[UUID] = Field(default_factory=list)
    verdict: Optional[str] = None
    notes: Optional[str] = None


class RetestRecord(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    status: str = "pending"
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    operator: Optional[str] = None
    notes: Optional[str] = None
    before_evidence_ids: list[UUID] = Field(default_factory=list)
    after_evidence_ids: list[UUID] = Field(default_factory=list)


class Finding(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    title: str
    severity: Severity
    confidence: Confidence
    affected_asset: str
    description: str
    remediation: str
    evidence_ids: list[UUID] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    cwe: Optional[str] = None
    cvss: Optional[float] = None
    cve_ids: list[str] = Field(default_factory=list)
    # Consultancy/reporting enrichment. Defaults preserve backward compatibility with
    # findings produced by individual engines. These fields describe evidence quality
    # and remediation workflow; they do not assert exploitability.
    validation_status: str = "unreviewed"
    evidence_quality: str = "unrated"
    business_impact: Optional[str] = None
    technical_impact: Optional[str] = None
    remediation_priority: Optional[str] = None
    priority_score: Optional[int] = Field(default=None, ge=0, le=100)
    remediation_status: str = "open"
    remediation_owner: Optional[str] = None
    remediation_due_at: Optional[datetime] = None
    remediation_notes: Optional[str] = None
    risk_acceptance_reference: Optional[str] = None
    retest_status: str = "not-retested"
    retest_history: list[RetestRecord] = Field(default_factory=list)
    attack_path: list[str] = Field(default_factory=list)
    related_finding_ids: list[UUID] = Field(default_factory=list)
    validation_sessions: list[ValidationSession] = Field(default_factory=list)


class ModuleStatus(BaseModel):
    name: str
    state: ModuleState = ModuleState.QUEUED
    completed_units: int = 0
    total_units: int = 0
    message: Optional[str] = None


class AssessmentResult(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    engine_version: str = "legacy/unknown"
    name: str
    profile: str
    status: str = "created"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    assets: list[Asset] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    modules: list[ModuleStatus] = Field(default_factory=list)
    graph: dict[str, list[dict[str, Any]]] = Field(default_factory=lambda: {"nodes": [], "edges": []})
    verification: dict[str, Any] = Field(default_factory=dict)
