from shadowstrike.lab.accuracy import run_accuracy_fixtures


def test_accuracy_fixtures_are_clean():
    result = run_accuracy_fixtures()
    assert result.detected == result.known_conditions
    assert result.false_positives == 0
