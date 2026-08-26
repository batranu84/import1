from shadowstrike.core.adaptive import AdaptiveConcurrency


def test_adaptive_controller_respects_ceiling_and_reduces_on_errors():
    controller = AdaptiveConcurrency(max_limit=20, initial=8, window=8)
    for _ in range(8):
        controller.observe(True, 10)
    assert 8 < controller.current <= 20
    raised = controller.current
    for _ in range(8):
        controller.observe(False, 2000)
    assert controller.current < raised
    assert controller.current >= 1
