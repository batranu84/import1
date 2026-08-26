from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union
from uuid import UUID

from shadowstrike import __version__
from shadowstrike.config import settings
from shadowstrike.core.rate import RateLimiter
from shadowstrike.core.scope import ScopeGuard
from shadowstrike.engines.base import EngineContext
from shadowstrike.engines.crawler import CrawlerEngine
from shadowstrike.engines.dns import DnsEngine
from shadowstrike.engines.http import HttpEngine
from shadowstrike.engines.js import JavaScriptEngine
from shadowstrike.engines.api import ApiDiscoveryEngine
from shadowstrike.engines.contacts import ContactDiscoveryEngine
from shadowstrike.engines.cve import CveIntelligenceEngine
from shadowstrike.engines.wildcard import WildcardDnsEngine
from shadowstrike.engines.recon import ReconEngine
from shadowstrike.engines.tcp import TcpDiscoveryEngine
from shadowstrike.engines.network import InternalNetworkEngine
from shadowstrike.engines.tls import TlsIntelligenceEngine
from shadowstrike.engines.certificates import CertificateIntelligenceEngine
from shadowstrike.engines.udp import UdpProtocolDiscoveryEngine
from shadowstrike.external.posture import ExternalPostureEngine
from shadowstrike.external.validation import ExternalValidationEngine
from shadowstrike.internal.posture import InternalPostureEngine
from shadowstrike.internal.infrastructure import InternalInfrastructureEngine
from shadowstrike.internal.identity import InternalIdentityEngine
from shadowstrike.internal.segmentation import InternalSegmentationEngine
from shadowstrike.internal.exposure import InternalExposureEngine
from shadowstrike.graph.evidence_graph import EvidenceGraph
from shadowstrike.models.domain import AssessmentMode, AssessmentRequest, AssessmentResult, ModuleState, ModuleStatus
from shadowstrike.services.correlation import CorrelationEngine
from shadowstrike.services.findings import CORRELATED_TAG, FindingsEngine
from shadowstrike.services.finding_intelligence import FindingIntelligenceService
from shadowstrike.services.verification import VerificationService
from shadowstrike.services.deep_discovery import DeepDiscoveryEngine
from shadowstrike.services.adaptive_assessment import AdaptiveAssessmentEngine
from shadowstrike.services.tool_bridge import SpecialistToolBridgeEngine
from shadowstrike.services.intelligence_graph import IntelligenceGraphEngine
from shadowstrike.storage.repository import AssessmentRepository
from shadowstrike.physical.discovery_pipeline import DiscoveryPhysicalPipeline
from shadowstrike.physical.assessment_inventory import PhysicalInventory


class AssessmentOrchestrator:
    def __init__(self, repository: Optional[AssessmentRepository] = None) -> None:
        self.external_discovery_engines = [ReconEngine(), WildcardDnsEngine(), DnsEngine(), TcpDiscoveryEngine(), HttpEngine(), CrawlerEngine(), ContactDiscoveryEngine(), JavaScriptEngine(), ApiDiscoveryEngine()]
        self.internal_discovery_engines = [InternalNetworkEngine(), UdpProtocolDiscoveryEngine()]
        self.shared_enrichment_engines = [TlsIntelligenceEngine(), CertificateIntelligenceEngine(), DeepDiscoveryEngine(), AdaptiveAssessmentEngine(), SpecialistToolBridgeEngine(), IntelligenceGraphEngine(), CveIntelligenceEngine()]
        self.external_post_engines = [ExternalPostureEngine(), ExternalValidationEngine()]
        self.internal_post_engines = [InternalPostureEngine(), InternalInfrastructureEngine(), InternalIdentityEngine(), InternalSegmentationEngine(), InternalExposureEngine()]
        self.external_engines = self.external_discovery_engines + self.shared_enrichment_engines + self.external_post_engines
        self.internal_engines = self.internal_discovery_engines + self.shared_enrichment_engines + self.internal_post_engines
        self.engines = self.external_discovery_engines + self.internal_discovery_engines + self.shared_enrichment_engines + self.external_post_engines + self.internal_post_engines
        self.correlation = CorrelationEngine()
        self.findings_engine = FindingsEngine()
        self.finding_intelligence = FindingIntelligenceService()
        self.verification = VerificationService()
        self.repository = repository or AssessmentRepository(Path(settings.database_path))
        self.physical_pipeline = DiscoveryPhysicalPipeline()
        self.physical_inventory = PhysicalInventory()

    def _engines_for(self, request: AssessmentRequest):
        if request.mode == AssessmentMode.EXTERNAL:
            return self.external_engines
        if request.mode == AssessmentMode.INTERNAL:
            return self.internal_engines
        return self.engines

    def _context(self, request: AssessmentRequest, assessment_id: Union[UUID, str]) -> EngineContext:
        guard = ScopeGuard(request.scope)
        for target in request.targets:
            guard.require(target)
        aid = str(assessment_id)
        return EngineContext(
            scope=guard,
            limiter=RateLimiter(request.scope.max_requests_per_second),
            timeout=settings.default_timeout_seconds,
            user_agent=settings.user_agent,
            profile=request.profile,
            assessment_id=aid,
            load_checkpoint=lambda name: self.repository.load_engine_checkpoint(aid, name),
            save_checkpoint=lambda name, state: self.repository.save_engine_checkpoint(aid, name, state),
            clear_checkpoint=lambda name: self.repository.clear_engine_checkpoint(aid, name),
        )

    def _finalize(self, result: AssessmentResult) -> None:
        result.evidence = self.correlation.normalize_evidence(result.evidence)
        native_findings = [f for f in result.findings if CORRELATED_TAG not in f.tags]
        correlated = self.findings_engine.analyze(result.evidence)
        result.findings = self.correlation.dedupe_findings(native_findings + correlated)
        result.findings = self.finding_intelligence.enrich(result.findings, result.evidence)
        result.graph = EvidenceGraph.from_results(
            result.assets, result.evidence, result.findings
        ).export()
        result.verification = self.verification.summarize(result.findings)
        result.updated_at = datetime.now(timezone.utc)

    async def run(
        self, request: AssessmentRequest, *, existing: Optional[AssessmentResult] = None
    ) -> AssessmentResult:
        result = existing or AssessmentResult(name=request.name, profile=request.profile, status="running", engine_version=__version__)
        context = self._context(request, result.id)
        result.status = "running"

        engines = self._engines_for(request)
        previous = {m.name: m for m in result.modules}
        result.modules = [previous.get(e.name, ModuleStatus(name=e.name)) for e in engines]
        self.repository.save(request, result)

        for engine, status in zip(engines, result.modules):
            if status.state == ModuleState.COMPLETED:
                continue
            context.engine_name = engine.name
            context.assets = result.assets
            context.evidence = result.evidence
            context.findings = result.findings
            status.state = ModuleState.RUNNING
            status.message = None
            self.repository.save_module_statuses(result.id, result.modules)
            self.repository.save(request, result)
            try:
                output = await engine.run(request.targets, context)
            except Exception as exc:
                status.state = ModuleState.FAILED
                status.message = f"{type(exc).__name__}: {exc}"
                self._finalize(result)
                self.repository.save_module_statuses(result.id, result.modules)
                self.repository.save(request, result)
                continue

            result.assets.extend(output.assets)
            result.evidence.extend(output.evidence)

            if request.mode != AssessmentMode.EXTERNAL:
                physical_inputs = []
                for asset in output.assets:
                    physical_inputs.append({
                        "ip": asset.value,
                        "kind": asset.kind,
                        "attributes": asset.attributes,
                    })
                physical_assets = self.physical_pipeline.process(physical_inputs)
                if output.assets:
                    result.assets.extend([type(output.assets[0])(**{
                        "kind": physical["category"],
                        "value": physical["ip"],
                        "source": "physical_pipeline",
                        "attributes": physical,
                    }) for physical in physical_assets])
            result.findings.extend(output.findings)
            status.state = ModuleState.COMPLETED
            context.checkpoint_clear()
            status.completed_units = len(output.evidence)
            status.total_units = len(output.evidence)
            self._finalize(result)
            self.repository.save_module_statuses(result.id, result.modules)
            self.repository.save(request, result)

        failed = any(m.state == ModuleState.FAILED for m in result.modules)
        result.status = "completed_with_errors" if failed else "completed"
        self._finalize(result)
        self.repository.save(request, result)
        return result

    async def resume(self, assessment_id: Union[UUID, str]) -> AssessmentResult:
        loaded = self.repository.load(assessment_id)
        if loaded is None:
            raise KeyError(f"Assessment {assessment_id} was not found")
        request, result = loaded
        for status in result.modules:
            if status.state in {ModuleState.RUNNING, ModuleState.FAILED}:
                status.state = ModuleState.QUEUED
                status.message = None
        return await self.run(request, existing=result)
