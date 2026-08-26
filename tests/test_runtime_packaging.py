from pathlib import Path


def test_tls_runtime_dependency_declared_and_preflighted():
    root = Path(__file__).resolve().parents[1]
    requirements = (root / "requirements.txt").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    start_command = (root / "start.command").read_text()
    start_sh = (root / "start.sh").read_text()

    assert "cryptography>=45,<47" in requirements
    assert '"cryptography>=45,<47"' in pyproject
    assert "cryptography" in start_command
    assert "from shadowstrike.engines.tls import TlsIntelligenceEngine" in start_command
    assert "cryptography" in start_sh
    assert "from shadowstrike.engines.tls import TlsIntelligenceEngine" in start_sh
