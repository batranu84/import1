from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from shadowstrike.models.domain import AssessmentRequest
from shadowstrike.services.orchestrator import AssessmentOrchestrator
from shadowstrike.reporting.html import HtmlReport
from shadowstrike.services.delta import DeltaService
from shadowstrike.lab.benchmark import run_local_tcp_benchmark
from shadowstrike.lab.accuracy import run_accuracy_fixtures
from shadowstrike.network.agent import ShadowAgent

app = typer.Typer(help="ShadowStrike authorized security assessment platform")
console = Console()


def _print_result(result) -> None:
    table = Table(title=f"ShadowStrike — {result.name}")
    table.add_column("Module")
    table.add_column("State")
    table.add_column("Evidence", justify="right")
    table.add_column("Message")
    for module in result.modules:
        table.add_row(
            module.name, module.state.value, str(module.completed_units), module.message or ""
        )
    console.print(table)
    console.print(
        f"Assessment ID: {result.id}\n"
        f"Assets: {len(result.assets)} | Evidence: {len(result.evidence)} | "
        f"Findings: {len(result.findings)} | Graph nodes: {len(result.graph.get('nodes', []))}"
    )


@app.command()
def assess(config: Path = typer.Argument(..., exists=True, readable=True)) -> None:
    """Run an assessment from a JSON engagement configuration."""
    request = AssessmentRequest.model_validate_json(config.read_text())
    result = asyncio.run(AssessmentOrchestrator().run(request))
    _print_result(result)
    out = config.with_name(config.stem + ".result.json")
    out.write_text(json.dumps(result.model_dump(mode="json"), indent=2))
    console.print(f"Result written to: {out}")


@app.command()
def resume(assessment_id: str) -> None:
    """Resume failed or interrupted modules from a persisted assessment."""
    try:
        result = asyncio.run(AssessmentOrchestrator().resume(assessment_id))
    except KeyError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code=2) from exc
    _print_result(result)


@app.command("list")
def list_assessments(limit: int = typer.Option(20, min=1, max=100)) -> None:
    """Show recently persisted assessments."""
    orchestrator = AssessmentOrchestrator()
    table = Table(title="Recent ShadowStrike Assessments")
    for heading in ("ID", "Name", "Profile", "Status", "Updated"):
        table.add_column(heading)
    for row in orchestrator.repository.list_recent(limit):
        table.add_row(row["id"], row["name"], row["profile"], row["status"], row["updated_at"])
    console.print(table)


@app.command()
def report(assessment_id: str, output: Optional[Path] = None, profile: str = typer.Option("technical", help="technical or bug-bounty")) -> None:
    """Generate a standalone HTML report from a persisted assessment."""
    orchestrator = AssessmentOrchestrator()
    loaded = orchestrator.repository.load(assessment_id)
    if loaded is None:
        console.print("[red]Assessment not found[/red]")
        raise typer.Exit(code=2)
    result = loaded[1]
    destination = output or Path(f"shadowstrike-{assessment_id}.html")
    HtmlReport().write(result, destination, profile=profile)
    console.print(f"HTML report written to: {destination}")


@app.command()
def delta(previous_id: str, current_id: str, output: Optional[Path] = None) -> None:
    """Compare two persisted assessment snapshots."""
    orchestrator = AssessmentOrchestrator()
    previous = orchestrator.repository.load(previous_id)
    current = orchestrator.repository.load(current_id)
    if previous is None or current is None:
        console.print("[red]One or both assessment IDs were not found[/red]")
        raise typer.Exit(code=2)
    data = DeltaService().compare(previous[1], current[1])
    rendered = json.dumps(data, indent=2)
    if output:
        output.write_text(rendered)
        console.print(f"Delta written to: {output}")
    else:
        console.print(rendered)


@app.command()
def lab(iterations: int = typer.Option(64, min=8, max=512)) -> None:
    """Run the controlled localhost ShadowLab TCP benchmark."""
    data = asyncio.run(run_local_tcp_benchmark(iterations))
    console.print(json.dumps(data.as_dict(), indent=2))


@app.command("lab-accuracy")
def lab_accuracy() -> None:
    """Run deterministic ShadowLab accuracy fixtures."""
    console.print(json.dumps(run_accuracy_fixtures().as_dict(), indent=2))


@app.command()
def sensor(
    controller: str = typer.Option(..., help="ShadowStrike controller URL reachable from the authorized sensor host"),
    assessment_id: str = typer.Option(..., help="Assessment ID assigned to this sensor"),
    agent_id: str = typer.Option(..., help="Sensor ID returned by the controller"),
    token: str = typer.Option(..., help="One-time-issued sensor token"),
    site: str = typer.Option("remote", help="Human-readable site name"),
    cidr: Optional[str] = typer.Option(None, help="Optional explicit approved CIDR; normally auto-selected from controller scope"),
    snmp_community: Optional[str] = typer.Option(None, help="Optional authorized SNMP v2c read community"),
    port_profile: str = typer.Option("adaptive", help="automatic port profile: discovery, standard, adaptive, or exhaustive"),
    interval: int = typer.Option(60, min=0, max=3600, help="Seconds between sensor cycles; 0 performs one cycle"),
) -> None:
    """Run an authenticated internal-network sensor.

    The sensor reports interfaces/routes automatically, then scans only CIDRs that the
    controller has explicitly approved for the assigned assessment. No CIDR argument is
    required in normal operation.
    """
    if port_profile not in {"discovery", "standard", "adaptive", "full", "exhaustive"}:
        console.print("[red]port-profile must be discovery, standard, adaptive, full, or exhaustive[/red]")
        raise typer.Exit(code=2)
    agent = ShadowAgent(agent_id=agent_id, site=site, assigned_assessment=assessment_id, status="online")

    async def run_cycle() -> dict:
        import ipaddress
        import httpx

        heartbeat = await agent.send_heartbeat(controller, token)
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(
                controller.rstrip("/") + f"/sensors/{agent_id}/assignment",
                headers={"X-ShadowStrike-Sensor-Token": token},
            )
            response.raise_for_status()
            assignment = response.json()

        allowed = [ipaddress.ip_network(x, strict=False) for x in assignment.get("allowed_cidrs", [])]
        excluded = [ipaddress.ip_network(x, strict=False) for x in assignment.get("excluded_cidrs", [])]
        detected = [ipaddress.ip_network(x["cidr"], strict=False) for x in agent.detected_networks() if x.get("cidr")]

        candidates = []
        if cidr:
            candidates = [ipaddress.ip_network(cidr, strict=False)]
        else:
            for approved in allowed:
                if any(approved.subnet_of(route) or route.subnet_of(approved) for route in detected if approved.version == route.version):
                    candidates.append(approved)

        assigned_communities = [str(x) for x in assignment.get("snmp_communities", []) if str(x).strip()]
        effective_snmp = snmp_community or (assigned_communities[0] if assigned_communities else None)
        assigned_profile = str(assignment.get("port_profile") or port_profile)
        effective_profile = port_profile or assigned_profile

        scanned = []
        for candidate in candidates:
            if not any(candidate.subnet_of(net) for net in allowed if candidate.version == net.version):
                raise ValueError(f"Sensor CIDR is outside the controller-approved scope: {candidate}")
            if any(candidate.overlaps(net) for net in excluded if candidate.version == net.version):
                raise ValueError(f"Sensor CIDR overlaps excluded scope: {candidate}")
            payload = await agent.collect(str(candidate), snmp_community=effective_snmp, port_profile=effective_profile)
            scanned.append(await agent.submit(controller, token, payload))
        return {
            "heartbeat": heartbeat,
            "detected_networks": agent.detected_networks(),
            "approved_networks": [str(x) for x in allowed],
            "scanned": scanned,
            "state": "scanned" if scanned else "waiting-for-approved-network",
        }

    async def run_sensor_loop() -> None:
        failures = 0
        while True:
            try:
                result = await run_cycle()
                failures = 0
                console.print(json.dumps(result, indent=2))
                if interval <= 0:
                    return
                await asyncio.sleep(interval)
            except Exception as exc:
                if interval <= 0:
                    raise
                failures += 1
                delay = min(300, max(5, min(interval, 60)) * min(failures, 5))
                console.print(
                    f"[yellow]Sensor cycle failed: {type(exc).__name__}: {exc}. "
                    f"Worker remains active and will retry in {delay}s.[/yellow]"
                )
                await asyncio.sleep(delay)

    try:
        asyncio.run(run_sensor_loop())
    except KeyboardInterrupt:
        console.print("Sensor stopped.")
    except Exception as exc:
        console.print(f"[red]Sensor failed: {type(exc).__name__}: {exc}[/red]")
        raise typer.Exit(code=2) from exc


@app.command("tool-doctor")
def tool_doctor() -> None:
    """Show deep-discovery/fingerprinting backends available on this host."""
    import os
    from shadowstrike.network.fingerprint import specialist_tool_status

    rows = specialist_tool_status()
    table = Table(title="ShadowStrike fingerprint backends")
    for heading in ("Tool", "Available", "Privileged", "Purpose", "Path"):
        table.add_column(heading)
    for row in rows:
        table.add_row(
            str(row.get("name")),
            "yes" if row.get("available") else "no",
            "yes" if row.get("privileged") else "no",
            str(row.get("purpose") or ""),
            str(row.get("path") or "—"),
        )
    console.print(table)
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        console.print("[yellow]Raw TCP/IP OS fingerprinting requires a privileged sensor/helper. Service/version fingerprinting remains available unprivileged when Nmap is installed.[/yellow]")


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    """Start the ShadowStrike API."""
    import uvicorn

    uvicorn.run("shadowstrike.api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    app()
