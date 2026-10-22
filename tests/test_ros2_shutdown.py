from types import SimpleNamespace

import pytest

from guardian_core import amr_simulator, dashboard, guardian_node, recovery_observer


@pytest.mark.parametrize(
    ("module", "node_name", "destroy_after_external_shutdown"),
    [
        (guardian_node, "GuardianNode", False),
        (amr_simulator, "AmrSimulatorNode", False),
        (dashboard, "DashboardNode", True),
        (recovery_observer, "RecoveryObserverNode", False),
    ],
)
def test_main_does_not_destroy_or_shutdown_after_ros_context_is_closed(
    monkeypatch, module, node_name, destroy_after_external_shutdown
):
    calls = []

    class FakeRclpy:
        def init(self, args=None):
            calls.append("init")

        def spin(self, node):
            raise KeyboardInterrupt

        def ok(self):
            return False

        def shutdown(self):
            calls.append("shutdown")

    class FakeNode:
        def destroy_node(self):
            calls.append("destroy")

    monkeypatch.setattr(module, "rclpy", FakeRclpy())
    monkeypatch.setattr(module, node_name, lambda: FakeNode())

    module.main()

    expected = ["init", "destroy"] if destroy_after_external_shutdown else ["init"]
    assert calls == expected


@pytest.mark.parametrize(
    ("module", "node_name", "destroy_after_external_shutdown"),
    [
        (guardian_node, "GuardianNode", False),
        (amr_simulator, "AmrSimulatorNode", False),
        (dashboard, "DashboardNode", True),
        (recovery_observer, "RecoveryObserverNode", False),
    ],
)
def test_main_treats_ros_external_shutdown_as_normal(
    monkeypatch, module, node_name, destroy_after_external_shutdown
):
    calls = []

    class ExternalShutdown(Exception):
        pass

    class FakeRclpy:
        def init(self, args=None):
            calls.append("init")

        def spin(self, node):
            raise ExternalShutdown

        def ok(self):
            return False

        def shutdown(self):
            calls.append("shutdown")

    class FakeNode:
        def destroy_node(self):
            calls.append("destroy")

    monkeypatch.setattr(module, "ExternalShutdownException", ExternalShutdown, raising=False)
    monkeypatch.setattr(module, "rclpy", FakeRclpy())
    monkeypatch.setattr(module, node_name, lambda: FakeNode())

    module.main()

    expected = ["init", "destroy"] if destroy_after_external_shutdown else ["init"]
    assert calls == expected


@pytest.mark.parametrize("context_open", [False, True])
@pytest.mark.parametrize(("module", "node_name"), [
    (recovery_observer, "RecoveryObserverNode"), (guardian_node, "GuardianNode"),
    (amr_simulator, "AmrSimulatorNode")])
def test_main_only_treats_runtime_error_as_shutdown_when_context_is_closed(monkeypatch, context_open, module, node_name):
    class FakeRclpy:
        def init(self, args=None):
            pass
        def spin(self, node):
            raise RuntimeError("take_message conversion interrupted")
        def ok(self):
            return context_open
        def shutdown(self):
            pass
        def try_shutdown(self):
            pass
    class FakeNode:
        def destroy_node(self):
            pass
    monkeypatch.setattr(module, "rclpy", FakeRclpy())
    monkeypatch.setattr(module, node_name, FakeNode)
    if context_open:
        with pytest.raises(RuntimeError):
            module.main()
    else:
        module.main()


@pytest.mark.parametrize(("module", "node_name"), [
    (recovery_observer, "RecoveryObserverNode"), (guardian_node, "GuardianNode"),
    (amr_simulator, "AmrSimulatorNode")])
def test_node_shutdown_is_idempotent_when_signal_closes_context_during_cleanup(monkeypatch, module, node_name):
    calls = []
    class FakeRclpy:
        def init(self, args=None):
            pass
        def spin(self, node):
            raise KeyboardInterrupt
        def ok(self):
            return True
        def shutdown(self):
            raise RuntimeError("rcl_shutdown already called")
        def try_shutdown(self):
            calls.append("idempotent_shutdown")
    class FakeNode:
        def destroy_node(self):
            calls.append("destroy_context_closed_by_signal")
    monkeypatch.setattr(module, "rclpy", FakeRclpy())
    monkeypatch.setattr(module, node_name, FakeNode)
    module.main()
    assert calls == ["destroy_context_closed_by_signal", "idempotent_shutdown"]
