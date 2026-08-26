from pathlib import Path


def test_launchers_avoid_editable_project_install() -> None:
    root = Path(__file__).resolve().parents[1]
    command = (root / "start.command").read_text()
    shell = (root / "start.sh").read_text()
    assert "pip install --disable-pip-version-check -e ." not in command
    assert "pip install --disable-pip-version-check -e ." not in shell
    assert "requirements.txt" in command
    assert "requirements.txt" in shell
    assert "PYTHONPATH" in command
    assert "PYTHONPATH" in shell
    assert (root / "requirements.txt").exists()


def test_launchers_require_supported_python_range() -> None:
    root = Path(__file__).resolve().parents[1]
    command = (root / "start.command").read_text()
    shell = (root / "start.sh").read_text()
    assert "(3,11) <= sys.version_info < (3,15)" in command
    assert "(3,11) <= sys.version_info < (3,15)" in shell
    assert "python3.9" not in command
    assert "python3.9" not in shell


def test_launchers_prefer_binary_and_upgrade_runtime_dependencies() -> None:
    root = Path(__file__).resolve().parents[1]
    command = (root / "start.command").read_text()
    shell = (root / "start.sh").read_text()
    assert "--prefer-binary --upgrade" in command
    assert "--prefer-binary --upgrade" in shell
    assert "python3.14" in command
    assert "python3.14" in shell
