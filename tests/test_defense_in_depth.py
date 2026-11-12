from pathlib import Path


def test_first_run_guard_includes_high_risk_user_roots():
    script = Path("scripts/protection-first-run.ps1").read_text(encoding="utf-8")
    assert "LocalApplicationData" in script
    assert "ApplicationData" in script
    assert "Join-Path $localAppData 'Temp'" in script
    assert "Microsoft\\Windows\\Start Menu\\Programs\\Startup" in script
    assert "Select-Object -Unique" in script
