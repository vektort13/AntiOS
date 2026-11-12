from antios.consumer import evaluate_health, render_quick_check


def _scan(secure_boot=True, tpm_present=True, tpm_ready=True):
    return {
        "system": {
            "security": {
                "secure_boot": {"enabled": secure_boot},
                "tpm": {
                    "present": tpm_present,
                    "ready": tpm_ready,
                },
            }
        }
    }


def _health(
    *,
    free_percent=50.0,
    free_bytes=100 * 1024**3,
    defender=True,
    bitlocker="On",
    pending=False,
    startup_count=5,
):
    return {
        "storage": {
            "available": True,
            "percent_free": free_percent,
            "free_bytes": free_bytes,
        },
        "defender": {
            "available": True,
            "antivirus_enabled": defender,
            "real_time_protection": defender,
            "signature_age_days": 0,
        },
        "bitlocker": {
            "available": True,
            "protection_status": bitlocker,
        },
        "pending_reboot": {
            "available": True,
            "pending": pending,
        },
        "startup": {
            "available": True,
            "count": startup_count,
            "entries": [],
        },
    }


def test_healthy_pc_gets_good_summary():
    result = evaluate_health(_scan(), _health())

    assert result["overall"] == "good"
    assert result["summary"]["warn"] == 0
    assert result["summary"]["advisory"] == 0


def test_disabled_defender_is_warning():
    result = evaluate_health(_scan(), _health(defender=False))

    assert result["overall"] == "needs-attention"
    assert any(
        item["id"] == "defender" and item["level"] == "warn"
        for item in result["checks"]
    )


def test_low_storage_is_warning():
    result = evaluate_health(
        _scan(),
        _health(
            free_percent=5.0,
            free_bytes=5 * 1024**3,
        ),
    )

    assert any(
        item["id"] == "storage" and item["level"] == "warn"
        for item in result["checks"]
    )


def test_pending_reboot_is_review_not_failure():
    result = evaluate_health(_scan(), _health(pending=True))

    assert result["overall"] == "review"
    assert result["summary"]["warn"] == 0


def test_quick_check_is_human_readable():
    result = evaluate_health(_scan(), _health())
    report = render_quick_check(result)

    assert "AntiOS quick check" in report
    assert "[OK]" in report
    assert "Your PC looks good" in report


def test_russian_health_output_is_localized():
    result = evaluate_health(_scan(), _health(), language="ru")
    report = render_quick_check(result, language="ru")

    assert "Быстрая проверка AntiOS" in report
    assert "С компьютером всё выглядит хорошо" in report
    assert any(item["title"] == "Свободное место" for item in result["checks"])


def test_spanish_health_output_is_localized():
    result = evaluate_health(_scan(), _health(), language="es")

    assert result["headline"] == "Tu PC parece estar bien"
    assert any(item["title"] == "Espacio de almacenamiento" for item in result["checks"])


def test_chinese_health_output_is_localized():
    result = evaluate_health(_scan(), _health(), language="zh-CN")

    assert result["headline"] == "电脑状态看起来不错"
    assert any(item["title"] == "存储空间" for item in result["checks"])
