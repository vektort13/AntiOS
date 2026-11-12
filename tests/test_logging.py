from antios.logging_utils import configure_logging


def test_logging_can_be_disabled():
    logger = configure_logging("INFO", "")
    assert logger.handlers
    assert logger.propagate is False


def test_elevated_windows_logging_does_not_touch_user_configured_file(tmp_path, monkeypatch):
    import logging
    import antios.logging_utils as module

    target = tmp_path / "untrusted" / "protected.log"
    monkeypatch.setattr(module, "_privileged_windows_context", lambda: True)
    logger = module.configure_logging("INFO", str(target))
    logger.warning("should not touch this path")
    assert not target.exists()
    assert not target.parent.exists()
    assert any(isinstance(handler, logging.NullHandler) for handler in logger.handlers)


def test_unprivileged_file_handlers_are_closed_when_reconfigured(tmp_path, monkeypatch):
    import logging
    import antios.logging_utils as module

    monkeypatch.setattr(module, "_privileged_windows_context", lambda: False)
    path = tmp_path / "antios.log"
    logger = module.configure_logging("DEBUG", str(path))
    handler = next(h for h in logger.handlers if isinstance(h, logging.FileHandler))
    logger.info("first")
    assert handler.stream is not None
    module.configure_logging("INFO", "")
    assert handler.stream is None
    assert "first" in path.read_text(encoding="utf-8")
