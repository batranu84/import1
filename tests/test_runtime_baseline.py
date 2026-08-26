from pathlib import Path


def test_project_declares_python311_floor() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "pyproject.toml").read_text()
    assert 'requires-python = ">=3.11,<3.15"' in text


def test_no_python39_specific_requirement_file() -> None:
    root = Path(__file__).resolve().parents[1]
    assert not (root / "requirements-py39.txt").exists()
    assert (root / "requirements.txt").exists()
