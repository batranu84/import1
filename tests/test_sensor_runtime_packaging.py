from pathlib import Path


def test_deep_fingerprint_dependencies_and_scripts_are_packaged() -> None:
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements.txt").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    start_command = (root / "start.command").read_text()
    sensor_command = (root / "sensor.command").read_text()

    assert "zeroconf>=0.150,<0.151" in requirements
    assert "mac-vendor-lookup>=0.1.15,<0.2" in requirements
    assert '"zeroconf>=0.150,<0.151"' in pyproject
    assert '"mac-vendor-lookup>=0.1.15,<0.2"' in pyproject
    assert "zeroconf" in start_command and "mac_vendor_lookup" in start_command
    assert "--privileged" in sensor_command
    assert 'sudo env PATH="$PATH" PYTHONPATH="$PYTHONPATH"' in sensor_command
    for name in (
        "sensor.command",
        "start-remote-controller.command",
        "install-discovery-tools.command",
        "SENSOR_DEPLOYMENT.md",
        "TOOL_SOURCES.md",
    ):
        assert (root / name).exists(), name


def test_sensor_ui_uses_reachable_controller_origin_and_runtime_state() -> None:
    root = Path(__file__).resolve().parents[1]
    dashboard = (root / "src/shadowstrike/web/dashboard.py").read_text()
    assert "window.location.origin" in dashboard
    assert "runtime_state" in dashboard
    assert "./sensor.command --privileged" in dashboard
    assert "start-remote-controller.command" in dashboard
