"""Local, evidence-based incident explanations. No probability or malware inference."""
from __future__ import annotations


_RULES = {
    "document-spawns-interpreter": (
        "Приложение для документов запустило командный интерпретатор. Так могут работать макросы и автоматизация; проверьте источник документа.",
        "A document application started a command interpreter. Macros and automation can do this; check the document's source."),
    "browser-spawns-interpreter": (
        "Браузер запустил командный интерпретатор. Проверьте, запускали ли вы установку или внешнюю программу.",
        "A browser started a command interpreter. Check whether you intended to start an installer or an external application."),
    "user-writable-execution": (
        "Программа запущена из загрузок или временной папки. Само расположение файла не подтверждает угрозу.",
        "A program ran from Downloads or a temporary folder. Its location alone does not confirm a threat."),
    "changed-then-executed": (
        "Файл запустился вскоре после изменения. Это бывает при обновлении программы; проверьте, ожидали ли вы это действие.",
        "A file ran soon after changing. Software updates can do this; check whether the action was expected."),
    "mass-file-changes": (
        "За короткое время изменилось много файлов. Причиной могут быть синхронизация, распаковка или нежелательная активность.",
        "Many files changed in a short period. Sync, extraction or unwanted activity can cause this."),
    "interpreter-with-mass-file-changes": (
        "Работа интерпретатора совпала с массовыми изменениями файлов. Совпадение по времени не доказывает, что именно он изменил файлы.",
        "An interpreter was active during many file changes. Timing alone does not prove that it changed those files."),
    "network.private-pe-public-peer": (
        "У одного процесса обнаружены PE-заголовок в исполняемой приватной памяти и активное TCP-соединение с публичным адресом.",
        "The same process had a PE header in private executable memory and an established TCP connection to a public address."),
}


def explain_incident(incident: dict, language="ru") -> dict:
    ru = language == "ru"
    def text(a, b):
        return a if ru else b
    incident = incident if isinstance(incident, dict) else {}
    nodes = incident.get("nodes") if isinstance(incident.get("nodes"), list) else []
    reasons, seen = [], set()
    incomplete = False
    for node in nodes[:256]:
        if not isinstance(node, dict):
            continue
        data = node.get("data") if isinstance(node.get("data"), dict) else {}
        rule = data.get("rule")
        if node.get("kind") == "evidence" and data.get("source") == "signature:network.private-pe-public-peer":
            rule = "network.private-pe-public-peer"
        if isinstance(rule, str) and rule not in seen:
            seen.add(rule)
            phrase = _RULES.get(rule)
            reasons.append({"node_id": str(node.get("id", ""))[:160], "code": rule[:100],
                            "text": phrase[0 if ru else 1] if phrase else text(
                                "В журнале есть дополнительный поведенческий сигнал. Посмотрите его подробности перед решением.",
                                "The journal contains an additional behavior signal. Inspect its details before deciding.")})
        if node.get("kind") == "risk" and data.get("scanner_complete") is False:
            incomplete = True
    confirmed = incident.get("confirmed_threat") is True
    title = text("Есть подтверждённое обнаружение", "A confirmed detection was recorded") if confirmed else text(
        "Активность требует проверки" if reasons else "Недостаточно данных для вывода",
        "Activity needs review" if reasons else "Not enough evidence for a conclusion")
    summary = text(
        "В этом событии сохранено обнаружение сканера. Перед изоляцией AntiOS повторно проверяет файл.",
        "This incident contains a scanner detection. AntiOS scans the file again before isolation.") if confirmed else text(
        "Поведенческие сигналы помогают выбрать, что проверить. Они сами по себе не подтверждают заражение.",
        "Behavior signals help prioritize investigation. They do not by themselves confirm an infection.")
    actions = [text("Повторно проверьте связанные файлы кнопкой «Перепроверить».",
                    "Rescan the linked files using the rescan action.")]
    if confirmed:
        actions.append(text("Изолируйте только подтверждённые повторной проверкой обнаружения.",
                            "Isolate only detections confirmed by the fresh scan."))
    if seen & {"mass-file-changes", "interpreter-with-mass-file-changes", "changed-then-executed"}:
        actions.append(text("Сравните важные файлы с сохранённым снимком перед восстановлением.",
                            "Compare important files with a saved snapshot before recovery."))
    if incomplete:
        actions.insert(0, text("Проверка файлов была неполной. Запустите самопроверку защиты и повторите сканирование.",
                               "File scanning was incomplete. Run the protection self-check and scan again."))
    return {"title": title, "summary": summary, "confirmed": confirmed,
            "incomplete_scan": incomplete, "reasons": reasons[:8], "actions": actions[:3],
            "note": text("Оценка риска — приоритет проверки, а не вероятность заражения.",
                         "The risk score is an investigation priority, not an infection probability.")}


def format_explanation(incident: dict, language="ru") -> str:
    report = explain_incident(incident, language)
    return "\n\n".join([report["title"], report["summary"],
        "\n".join("• " + item["text"] for item in report["reasons"]),
        "Что сделать" if language == "ru" else "Next steps",
        "\n".join(f"{index}. {value}" for index, value in enumerate(report["actions"], 1)), report["note"]])
