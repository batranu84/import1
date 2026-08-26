from pathlib import Path


def test_python314_capable_dependency_baseline() -> None:
    root = Path(__file__).resolve().parents[1]
    req = (root / "requirements.txt").read_text()
    assert "pydantic>=2.13,<2.14" in req
    assert "pydantic-settings>=2.14,<2.16" in req
    assert "fastapi>=0.128,<0.142" in req
