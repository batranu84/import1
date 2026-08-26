import pytest

from shadowstrike.lab.benchmark import run_local_tcp_benchmark


@pytest.mark.asyncio
async def test_local_lab_detects_fixture():
    result = await run_local_tcp_benchmark(8)
    assert result.attempts == 8
    assert result.expected_open_detected
    assert result.open_detected >= 1
