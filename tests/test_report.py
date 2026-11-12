from antios.report import render_doctor_human, render_operations_human


def test_operation_table_marks_restart_and_dry_run():
    operations = [
        {
            "target": r"HKLM\\SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName::ComputerName",
            "before": "OLD-PC",
            "after": "NEW-PC",
            "changed": True,
            "requires_reboot": True,
            "dry_run": True,
        },
        {
            "target": r"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion::RegisteredOwner",
            "before": "Old",
            "after": "New",
            "changed": True,
            "requires_reboot": False,
            "dry_run": True,
        },
    ]

    report = render_operations_human(
        operations,
        title="Apply",
        dry_run=True,
        color=False,
    )

    assert "DRY RUN" in report
    assert "OLD-PC" in report
    assert "NEW-PC" in report
    assert "requires a Windows restart" in report
    assert "\x1b[" not in report


def test_doctor_report_has_summary():
    report = render_doctor_human(
        {
            "checks": [
                {"level": "ok", "title": "Python", "detail": "Supported."},
                {"level": "advisory", "title": "Secure Boot", "detail": "Disabled."},
            ],
            "summary": {"ok": 1, "advisory": 1, "info": 0, "warn": 0},
        },
        color=False,
    )

    assert "[OK  ]" in report
    assert "[NOTE]" in report
    assert "Warnings: 0" in report
