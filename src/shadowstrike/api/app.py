from __future__ import annotations

import asyncio
import ipaddress
import logging
from datetime import datetime
from collections import Counter
from pathlib import Path
from typing import Optional
from uuid import UUID

from fastapi import FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from shadowstrike import __version__
from shadowstrike.config import settings
from shadowstrike.network.fingerprint import specialist_tool_status
from shadowstrike.models.domain import AssessmentRequest, AssessmentResult, ModuleState
from shadowstrike.core.scope import ScopeViolation
from shadowstrike.network.agent import SensorRegistry
from shadowstrike.network.lan import ShadowLAN
from shadowstrike.network.service import NetworkDiscoveryService
from shadowstrike.internal.posture import InternalPostureService
from shadowstrike.internal.infrastructure import InternalInfrastructureService
from shadowstrike.internal.identity import InternalIdentityService
from shadowstrike.internal.segmentation import InternalSegmentationService
from shadowstrike.internal.exposure import InternalExposureService
from shadowstrike.risk.assessment import AssessmentRiskService
from shadowstrike.reporting.html import HtmlReport
from shadowstrike.reporting.retest import RetestReport
from shadowstrike.reporting.validation import ValidationReport
from shadowstrike.reporting.executive import ExecutiveRiskReport
from shadowstrike.services.delta import DeltaService
from shadowstrike.services.orchestrator import AssessmentOrchestrator
from shadowstrike.services.remediation import RemediationRetestService
from shadowstrike.services.validation import ControlledValidationService
from shadowstrike.web.dashboard import DASHBOARD_HTML
from shadowstrike.physical.dashboard import physical_asset_summary

app = FastAPI(
    title="ShadowStrike",
    version=__version__,
    description="Evidence-driven authorized security assessment platform",
)
orchestrator = AssessmentOrchestrator()
network_service = NetworkDiscoveryService()
sensor_registry = SensorRegistry(Path("shadowstrike-sensors.json"))
remediation_service = RemediationRetestService()
validation_service = ControlledValidationService()


class NetworkScanRequest(BaseModel):
    cidr: str
    ports: list[int] | None = None
    port_profile: str = Field(default="full", pattern="^(discovery|standard|full)$")
    snmp_community: str | None = Field(default=None, max_length=256)


class SensorCreateRequest(BaseModel):
    site: str = Field(default="default", min_length=1, max_length=120)


class SensorHeartbeatRequest(BaseModel):
    status: str = "online"
    capabilities: dict[str, object] = Field(default_factory=dict)
    detected_networks: list[dict[str, object]] = Field(default_factory=list)
    health: dict[str, object] = Field(default_factory=dict)


class SensorNetworkApprovalRequest(BaseModel):
    cidr: str


class RemediationUpdateRequest(BaseModel):
    status: str
    owner: str | None = None
    due_at: datetime | None = None
    notes: str | None = None
    risk_acceptance_reference: str | None = None


class RetestRequestBody(BaseModel):
    operator: str | None = None
    notes: str | None = None
    before_evidence_ids: list[UUID] = Field(default_factory=list)


class RetestCompleteRequest(BaseModel):
    status: str
    after_evidence_ids: list[UUID] = Field(default_factory=list)
    operator: str | None = None
    notes: str | None = None


class ValidationAuthorizeRequest(BaseModel):
    operator: str | None = None
    technique: str
    proof_objective: str
    expected_access_level: str | None = None
    expected_effect: str | None = None
    notes: str | None = None


class ValidationPocRequest(BaseModel):
    artifact_type: str = "reproduction"
    title: str = "Controlled validation PoC"
    content: str
    safety_notes: str | None = None
    non_persistent: bool = True
    credential_access: bool = False
    destructive: bool = False


class ValidationAttemptRequest(BaseModel):
    evidence_ids: list[UUID] = Field(default_factory=list)
    operator: str | None = None
    notes: str | None = None


class ValidationCompleteRequest(BaseModel):
    verdict: str
    proof_evidence_ids: list[UUID] = Field(default_factory=list)
    proof_marker_observed: str | None = None
    access_level_achieved: str | None = None
    operator: str | None = None
    notes: str | None = None


class ValidationCleanupRequest(BaseModel):
    cleanup_evidence_ids: list[UUID] = Field(default_factory=list)
    operator: str | None = None
    notes: str | None = None


class SensorIngestRequest(BaseModel):
    assessment_id: str
    cidr: str
    gateway: str | None = None
    interfaces: list[dict[str, object]] = Field(default_factory=list)
    detected_networks: list[dict[str, object]] = Field(default_factory=list)
    capabilities: dict[str, object] = Field(default_factory=dict)
    devices: list[dict[str, object]] = Field(default_factory=list)
    port_profile: str | None = None
    collected_at: str | None = None

logger = logging.getLogger("shadowstrike.web")
_background_tasks: set[asyncio.Task] = set()
_assessment_tasks: dict[str, asyncio.Task] = {}


def _track(task: asyncio.Task, assessment_id: Optional[str] = None) -> None:
    _background_tasks.add(task)
    if assessment_id:
        _assessment_tasks[assessment_id] = task

    def cleanup(done: asyncio.Task) -> None:
        _background_tasks.discard(done)
        if assessment_id and _assessment_tasks.get(assessment_id) is done:
            _assessment_tasks.pop(assessment_id, None)

    task.add_done_callback(cleanup)


def _record_background_failure(assessment_id: str, exc: Exception) -> None:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        logger.exception("Assessment %s background worker failed", assessment_id, exc_info=exc)
        return
    request, result = loaded
    result.status = "failed"
    module = next((m for m in result.modules if m.state == ModuleState.RUNNING), None)
    if module is None:
        module = next((m for m in result.modules if m.state == ModuleState.QUEUED), None)
    if module is not None:
        module.state = ModuleState.FAILED
        module.message = f"Worker error: {type(exc).__name__}: {exc}"
    orchestrator.repository.save_module_statuses(result.id, result.modules)
    orchestrator.repository.save(request, result)
    logger.error("Assessment %s background worker failed: %s: %s", assessment_id, type(exc).__name__, exc)


async def _run_assessment_background(request: AssessmentRequest, result: AssessmentResult) -> None:
    assessment_id = str(result.id)
    try:
        await orchestrator.run(request, existing=result)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        _record_background_failure(assessment_id, exc)


async def _resume_assessment_background(assessment_id: str) -> None:
    try:
        await orchestrator.resume(assessment_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        _record_background_failure(assessment_id, exc)


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse(DASHBOARD_HTML)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": "shadowstrike", "version": __version__}


@app.get("/system/settings")
async def system_settings() -> dict[str, object]:
    return {
        "runtime": {
            "version": __version__,
            "database": settings.database_path,
            "default_timeout_seconds": settings.default_timeout_seconds,
            "default_concurrency": settings.default_concurrency,
            "maximum_runtime_concurrency": settings.max_concurrency,
            "user_agent": settings.user_agent,
            "bind_host": settings.host,
            "port": settings.port,
            "fingerprint_backends": specialist_tool_status(),
            "sensor_remote_ready": settings.host not in {"127.0.0.1", "localhost", "::1"},
        },
        "safety": {
            "scope_enforcement": settings.enforce_scope,
            "authorization_reference_required": True,
            "load_testing_in_standard_profiles": False,
            "default_bind": settings.host,
            "external_command_bridge": "scope-gated specialist execution; Nmap service/version and OS fingerprint ingestion is supported, with raw OS probes only from a privileged authorized worker",
            "internal_fingerprinting": "adaptive host discovery + DNS-SD/UPnP + MAC/OUI + Nmap service/device/OS fingerprints when installed; arp-scan and raw Nmap OS probing are available from an explicitly privileged sensor worker",
            "distributed_sensor_runtime": "registered sensors initiate outbound heartbeats to a routed/VPN controller, remain alive across transient controller failures, and scan only controller-approved CIDRs",
            "cve_provider": "NVD with exact-version correlation plus adaptive applicability planning; CVE/CWE/CVSS retained as evidence",
            "contact_discovery": "bounded candidate discovery from observed DNS/TLS/HTTP/API evidence; every candidate is ScopeGuard-gated before contact",
            "controlled_validation": "engagement-controlled; requires explicit scope and validation authorization reference; proof and cleanup evidence are preserved",
            "adaptive_assessment": "enabled; evidence-driven branches and candidate scope decisions are recorded",
            "udp_protocol_discovery": "enabled by default for explicitly authorised internal scope; only protocol-valid positive responses are reported; SNMP requires engagement-supplied communities",
            "evidence_fidelity": "TCP connect acceptance, service identity, product/version, CVE applicability, and exploit validation are separate states; conventional port mappings never confirm a protocol",
            "local_network_truth": "direct RFC1918 interface networks are prioritized; broadcast, multicast, loopback and macOS neighbour/host /32 routes are excluded from automatic network approval and device inventory",
            "assessment_provenance": "each assessment records the ShadowStrike engine version that created its evidence semantics; legacy results are warned rather than silently reinterpreted",
        },
    }


@app.get("/physical-assets")
async def physical_assets() -> dict[str, object]:
    """Return physical asset intelligence summary."""
    return physical_asset_summary([])


@app.get("/overview")
async def overview() -> dict[str, object]:
    recent = orchestrator.repository.list_recent(100)
    statuses = Counter(row["status"] for row in recent)
    return {
        "assessments": {
            "total": len(recent),
            "running": sum(statuses.get(s, 0) for s in ("queued", "running", "resuming")),
            "completed": statuses.get("completed", 0),
            "completed_with_errors": statuses.get("completed_with_errors", 0),
            "cancelled": statuses.get("cancelled", 0),
            "failed": statuses.get("failed", 0),
        },
        "active_task_count": len(_assessment_tasks),
    }


@app.get("/assessments")
async def assessments(limit: int = 20) -> list[dict[str, str]]:
    return orchestrator.repository.list_recent(min(max(limit, 1), 100))


@app.get("/assessments/{assessment_id}/executive-risk")
async def assessment_executive_risk(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return AssessmentRiskService.summarize(loaded[1])


@app.get("/assessments/{assessment_id}", response_model=AssessmentResult)
async def get_assessment(assessment_id: str) -> AssessmentResult:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return loaded[1]


@app.get("/assessments/{assessment_id}/telemetry")
async def assessment_telemetry(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    checkpoint = orchestrator.repository.load_engine_checkpoint(assessment_id, "ShadowScan")
    if checkpoint:
        return {"source": "checkpoint", "data": checkpoint}
    result = loaded[1]
    for item in reversed(result.evidence):
        if item.category == "scan-telemetry":
            return {"source": "final", "data": item.raw}
    return {"source": "none", "data": {}}


@app.get("/assessments/{assessment_id}/context")
async def get_assessment_context(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    return {"request": request.model_dump(mode="json"), "result": result.model_dump(mode="json")}


@app.post("/assessments/start")
async def start_assessment(request: AssessmentRequest) -> dict[str, str]:
    if not request.authorization_reference.strip():
        raise HTTPException(status_code=400, detail="authorization_reference is required")
    result = AssessmentResult(name=request.name, profile=request.profile, status="queued", engine_version=__version__)
    try:
        orchestrator._context(request, result.id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    task = asyncio.create_task(_run_assessment_background(request, result))
    _track(task, str(result.id))
    return {"id": str(result.id), "status": result.status}


@app.post("/assessments/run", response_model=AssessmentResult)
async def run_assessment(request: AssessmentRequest) -> AssessmentResult:
    if not request.authorization_reference.strip():
        raise HTTPException(status_code=400, detail="authorization_reference is required")
    try:
        return await orchestrator.run(request)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/assessments/{assessment_id}/resume")
async def resume_assessment(assessment_id: str) -> dict[str, str]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    existing = _assessment_tasks.get(assessment_id)
    if existing and not existing.done():
        raise HTTPException(status_code=409, detail="assessment is already running")
    task = asyncio.create_task(_resume_assessment_background(assessment_id))
    _track(task, assessment_id)
    return {"id": assessment_id, "status": "resuming"}


@app.post("/assessments/{assessment_id}/cancel")
async def cancel_assessment(assessment_id: str) -> dict[str, str]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    task = _assessment_tasks.get(assessment_id)
    if task and not task.done():
        task.cancel()
    result.status = "cancelled"
    for module in result.modules:
        if module.state == ModuleState.RUNNING:
            module.state = ModuleState.SKIPPED
            module.message = "Cancelled by operator"
    orchestrator.repository.save_module_statuses(result.id, result.modules)
    orchestrator.repository.save(request, result)
    return {"id": assessment_id, "status": result.status}


@app.get("/assessments/{assessment_id}/executive-report", response_class=HTMLResponse)
async def assessment_executive_report(assessment_id: str) -> HTMLResponse:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return HTMLResponse(ExecutiveRiskReport().render(loaded[1]))


@app.get("/assessments/{assessment_id}/report", response_class=HTMLResponse)
async def assessment_report(
    assessment_id: str,
    profile: str = Query("technical", pattern="^(technical|bug-bounty)$"),
) -> HTMLResponse:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    try:
        return HTMLResponse(HtmlReport().render(loaded[1], profile=profile))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.post("/assessments/{assessment_id}/findings/{finding_id}/remediation")
async def update_finding_remediation(assessment_id: str, finding_id: str, body: RemediationUpdateRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        finding = remediation_service.find(result.findings, finding_id)
        remediation_service.update_remediation(
            finding, status=body.status, owner=body.owner, due_at=body.due_at, notes=body.notes,
            risk_acceptance_reference=body.risk_acceptance_reference,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return finding.model_dump(mode="json")


@app.post("/assessments/{assessment_id}/findings/{finding_id}/retest/request")
async def request_finding_retest(assessment_id: str, finding_id: str, body: RetestRequestBody) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        finding = remediation_service.find(result.findings, finding_id)
        record = remediation_service.request_retest(
            finding, operator=body.operator, notes=body.notes,
            before_evidence_ids=body.before_evidence_ids or None,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return record.model_dump(mode="json")


@app.post("/assessments/{assessment_id}/findings/{finding_id}/retest/complete")
async def complete_finding_retest(assessment_id: str, finding_id: str, body: RetestCompleteRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    evidence_ids = {item.id for item in result.evidence}
    missing = [item for item in body.after_evidence_ids if item not in evidence_ids]
    if missing:
        raise HTTPException(status_code=400, detail="after_evidence_ids must reference evidence stored in this assessment")
    try:
        finding = remediation_service.find(result.findings, finding_id)
        record = remediation_service.complete_retest(
            finding, status=body.status, after_evidence_ids=body.after_evidence_ids,
            operator=body.operator, notes=body.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return record.model_dump(mode="json")


@app.get("/assessments/{assessment_id}/retest-report", response_class=HTMLResponse)
async def assessment_retest_report(assessment_id: str) -> HTMLResponse:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return HTMLResponse(RetestReport().render(loaded[1]))


@app.post("/assessments/{assessment_id}/findings/{finding_id}/validation/authorize")
async def authorize_finding_validation(assessment_id: str, finding_id: str, body: ValidationAuthorizeRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    if not request.scope.allow_controlled_validation:
        raise HTTPException(status_code=403, detail="controlled validation is not authorized by this engagement scope")
    validation_ref = (request.scope.validation_authorization_reference or "").strip()
    if not validation_ref:
        raise HTTPException(status_code=403, detail="validation_authorization_reference is required before controlled validation")
    try:
        finding = validation_service.find(result.findings, finding_id)
        session = validation_service.authorize(
            finding,
            assessment_authorization_reference=request.authorization_reference,
            validation_authorization_reference=validation_ref,
            operator=body.operator, technique=body.technique, objective_description=body.proof_objective,
            expected_access_level=body.expected_access_level, expected_effect=body.expected_effect, notes=body.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return session.model_dump(mode="json")


@app.post("/assessments/{assessment_id}/findings/{finding_id}/validation/{session_id}/poc")
async def add_validation_poc(assessment_id: str, finding_id: str, session_id: str, body: ValidationPocRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        finding = validation_service.find(result.findings, finding_id)
        session = validation_service.find_session(finding, session_id)
        artifact = validation_service.add_poc(
            finding, session, artifact_type=body.artifact_type, title=body.title, content=body.content,
            safety_notes=body.safety_notes, non_persistent=body.non_persistent,
            credential_access=body.credential_access, destructive=body.destructive,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return artifact.model_dump(mode="json")


@app.post("/assessments/{assessment_id}/findings/{finding_id}/validation/{session_id}/attempt")
async def record_validation_attempt(assessment_id: str, finding_id: str, session_id: str, body: ValidationAttemptRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        finding = validation_service.find(result.findings, finding_id)
        session = validation_service.find_session(finding, session_id)
        validation_service.record_attempt(
            finding, session, evidence_ids=body.evidence_ids, available_evidence_ids={str(e.id) for e in result.evidence},
            operator=body.operator, notes=body.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return session.model_dump(mode="json")


@app.post("/assessments/{assessment_id}/findings/{finding_id}/validation/{session_id}/complete")
async def complete_validation(assessment_id: str, finding_id: str, session_id: str, body: ValidationCompleteRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        finding = validation_service.find(result.findings, finding_id)
        session = validation_service.find_session(finding, session_id)
        validation_service.complete(
            finding, session, verdict=body.verdict, proof_evidence_ids=body.proof_evidence_ids,
            available_evidence_ids={str(e.id) for e in result.evidence}, proof_marker_observed=body.proof_marker_observed,
            access_level_achieved=body.access_level_achieved, operator=body.operator, notes=body.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return session.model_dump(mode="json")


@app.post("/assessments/{assessment_id}/findings/{finding_id}/validation/{session_id}/cleanup")
async def confirm_validation_cleanup(assessment_id: str, finding_id: str, session_id: str, body: ValidationCleanupRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        finding = validation_service.find(result.findings, finding_id)
        session = validation_service.find_session(finding, session_id)
        validation_service.confirm_cleanup(
            finding, session, cleanup_evidence_ids=body.cleanup_evidence_ids,
            available_evidence_ids={str(e.id) for e in result.evidence}, operator=body.operator, notes=body.notes,
        )
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator.repository.save(request, result)
    return session.model_dump(mode="json")


@app.get("/assessments/{assessment_id}/validation-report", response_class=HTMLResponse)
async def assessment_validation_report(assessment_id: str) -> HTMLResponse:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return HTMLResponse(ValidationReport().render(loaded[1]))


@app.get("/assessments/{previous_id}/delta/{current_id}")
async def compare_assessments(previous_id: str, current_id: str) -> dict[str, object]:
    previous = orchestrator.repository.load(previous_id)
    current = orchestrator.repository.load(current_id)
    if previous is None or current is None:
        raise HTTPException(status_code=404, detail="one or both assessments were not found")
    return DeltaService().compare(previous[1], current[1])


@app.get("/network/local")
async def local_network_context() -> dict[str, object]:
    return {
        "interfaces": [vars(x) for x in ShadowLAN.local_interfaces()],
        "gateway": ShadowLAN.default_gateway(),
        "detected_networks": [x.as_dict() for x in ShadowLAN.detected_networks()],
        "note": "Only usable RFC1918 interface/routed networks are returned. Broadcast addresses and macOS neighbour/host /32 routes are excluded. Active discovery still requires explicit approval.",
    }


@app.post("/assessments/{assessment_id}/network/approve-local")
async def approve_local_network(assessment_id: str, body: SensorNetworkApprovalRequest) -> dict[str, object]:
    try:
        candidate = str(ipaddress.ip_network(body.cidr, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid CIDR") from exc
    reported = {x.cidr for x in ShadowLAN.detected_networks() if x.approval_recommended}
    if candidate not in reported:
        raise HTTPException(status_code=400, detail="CIDR is not present in this controller's detected routes")
    network = ipaddress.ip_network(candidate)
    if not network.is_private:
        raise HTTPException(status_code=400, detail="automatic local approval is limited to private networks")
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    excluded = [ipaddress.ip_network(x, strict=False) for x in request.scope.excluded_cidrs]
    if any(network.overlaps(x) for x in excluded if network.version == x.version):
        raise HTTPException(status_code=400, detail="CIDR overlaps excluded scope")
    if candidate not in request.scope.allowed_cidrs:
        request.scope.allowed_cidrs.append(candidate)
        orchestrator.repository.save(request, result)
    return {"approved": True, "cidr": candidate, "allowed_cidrs": request.scope.allowed_cidrs}


@app.post("/assessments/{assessment_id}/network/scan")
async def scan_internal_network(assessment_id: str, body: NetworkScanRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        data = await network_service.scan(
            request, result, body.cidr, ports=body.ports, snmp_community=body.snmp_community,
            port_profile=body.port_profile,
        )
    except (ScopeViolation, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    orchestrator._finalize(result)
    orchestrator.repository.save(request, result)
    return {**data, "risk": network_service.summary(result)}


@app.get("/assessments/{assessment_id}/network")
async def network_summary(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return network_service.summary(loaded[1])


@app.get("/assessments/{assessment_id}/internal-posture")
async def internal_posture(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    result = loaded[1]
    return InternalPostureService.summarize(result.assets, result.evidence)


@app.get("/assessments/{assessment_id}/internal-infrastructure")
async def internal_infrastructure(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    result = loaded[1]
    return InternalInfrastructureService.summarize(result.assets, result.evidence)


@app.get("/assessments/{assessment_id}/internal-identity")
async def internal_identity(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    result = loaded[1]
    return InternalIdentityService.summarize(result.assets, result.evidence)


@app.get("/assessments/{assessment_id}/internal-trust")
async def internal_trust(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    result = loaded[1]
    return InternalSegmentationService.summarize(result.assets, result.evidence)

@app.get("/assessments/{assessment_id}/internal-exposure-paths")
async def internal_exposure_paths(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    result = loaded[1]
    return InternalExposureService.summarize(result.assets, result.evidence, result.findings)


@app.get("/assessments/{assessment_id}/network/devices")
async def network_devices(assessment_id: str) -> list[dict[str, object]]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return network_service.summary(loaded[1])["devices"]


@app.get("/assessments/{assessment_id}/network/topology")
async def network_topology(assessment_id: str) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return network_service.summary(loaded[1])["topology"]


@app.post("/assessments/{assessment_id}/sensors/register")
async def register_sensor(assessment_id: str, body: SensorCreateRequest) -> dict[str, object]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    record, token = sensor_registry.create(body.site, assessment_id)
    return {**record, "token": token, "token_note": "Shown once. Store it on the authorized sensor host."}


@app.get("/assessments/{assessment_id}/sensors")
async def list_sensors(assessment_id: str) -> list[dict[str, object]]:
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    return sensor_registry.list(assessment_id)


def _require_sensor_token(agent_id: str, token: str | None) -> dict[str, object]:
    from shadowstrike.network.agent import ShadowAgent
    record = sensor_registry.get(agent_id)
    if record is None:
        raise HTTPException(status_code=404, detail="sensor not found")
    if not token or not ShadowAgent.verify_token(token, record.get("token_hash")):
        raise HTTPException(status_code=401, detail="invalid sensor token")
    return record


@app.get("/sensors/{agent_id}/assignment")
async def sensor_assignment(
    agent_id: str,
    x_shadowstrike_sensor_token: str | None = Header(default=None),
) -> dict[str, object]:
    record = _require_sensor_token(agent_id, x_shadowstrike_sensor_token)
    loaded = orchestrator.repository.load(str(record.get("assessment_id")))
    if loaded is None:
        raise HTTPException(status_code=404, detail="assigned assessment not found")
    request, _ = loaded
    return {
        "agent_id": agent_id,
        "assessment_id": record.get("assessment_id"),
        "allowed_cidrs": request.scope.allowed_cidrs,
        "excluded_cidrs": request.scope.excluded_cidrs,
        "snmp_communities": request.scope.snmp_communities,
        "port_profile": "adaptive",
    }


@app.post("/sensors/{agent_id}/heartbeat")
async def sensor_heartbeat(
    agent_id: str,
    body: SensorHeartbeatRequest,
    x_shadowstrike_sensor_token: str | None = Header(default=None),
) -> dict[str, object]:
    _require_sensor_token(agent_id, x_shadowstrike_sensor_token)
    updated = sensor_registry.heartbeat(
        agent_id, status=body.status, capabilities=body.capabilities,
        detected_networks=body.detected_networks, health=body.health,
    )
    return updated or {}


@app.post("/assessments/{assessment_id}/sensors/{agent_id}/approve-network")
async def approve_sensor_network(
    assessment_id: str,
    agent_id: str,
    body: SensorNetworkApprovalRequest,
) -> dict[str, object]:
    """Promote a sensor-reported route into the assessment's explicit CIDR scope.

    This is an operator action in the controller UI. Merely detecting a route never authorizes
    it for active discovery.
    """
    record = sensor_registry.get(agent_id)
    if record is None or str(record.get("assessment_id")) != assessment_id:
        raise HTTPException(status_code=404, detail="sensor not found for assessment")
    reported = {str(x.get("cidr", "")) for x in record.get("detected_networks", [])}
    try:
        candidate = str(ipaddress.ip_network(body.cidr, strict=False))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid CIDR") from exc
    if candidate not in reported:
        raise HTTPException(status_code=400, detail="CIDR was not reported by this sensor")
    network = ipaddress.ip_network(candidate)
    if not network.is_private:
        raise HTTPException(status_code=400, detail="automatic sensor approval is limited to private networks")
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    excluded = [ipaddress.ip_network(x, strict=False) for x in request.scope.excluded_cidrs]
    if any(network.overlaps(x) for x in excluded if network.version == x.version):
        raise HTTPException(status_code=400, detail="CIDR overlaps excluded scope")
    normalized = [str(ipaddress.ip_network(x, strict=False)) for x in request.scope.allowed_cidrs]
    if candidate not in normalized:
        request.scope.allowed_cidrs.append(candidate)
        orchestrator.repository.save(request, result)
    return {"approved": True, "cidr": candidate, "allowed_cidrs": request.scope.allowed_cidrs}


@app.post("/sensors/{agent_id}/ingest")
async def sensor_ingest(
    agent_id: str,
    body: SensorIngestRequest,
    x_shadowstrike_sensor_token: str | None = Header(default=None),
) -> dict[str, object]:
    record = _require_sensor_token(agent_id, x_shadowstrike_sensor_token)
    if record.get("assessment_id") != body.assessment_id:
        raise HTTPException(status_code=403, detail="sensor is not assigned to this assessment")
    loaded = orchestrator.repository.load(body.assessment_id)
    if loaded is None:
        raise HTTPException(status_code=404, detail="assessment not found")
    request, result = loaded
    try:
        data = network_service.ingest_payload(request, result, body.model_dump(mode="json"), agent_id)
    except (ScopeViolation, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    sensor_registry.heartbeat(
        agent_id, status="online", capabilities=body.capabilities,
        detected_networks=body.detected_networks,
    )
    orchestrator._finalize(result)
    orchestrator.repository.save(request, result)
    return {"accepted": True, **data}
