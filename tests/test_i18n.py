from antios.i18n import (
    LANGUAGE_NAMES,
    SUPPORTED_LANGUAGES,
    TRANSLATIONS,
    Translator,
    normalize_language,
)


def test_seven_supported_languages_are_exposed():
    assert SUPPORTED_LANGUAGES == (
        "en",
        "ru",
        "es",
        "zh-CN",
        "fi",
        "pl",
        "mn",
    )
    assert set(LANGUAGE_NAMES) == set(SUPPORTED_LANGUAGES)


def test_locale_normalization():
    assert normalize_language("en-US") == "en"
    assert normalize_language("ru-RU") == "ru"
    assert normalize_language("es-MX") == "es"
    assert normalize_language("zh_CN") == "zh-CN"
    assert normalize_language("fi-FI") == "fi"
    assert normalize_language("pl-PL") == "pl"
    assert normalize_language("mn-MN") == "mn"
    assert normalize_language("fr-FR") == "en"


def test_all_languages_cover_the_english_catalog():
    english_keys = set(TRANSLATIONS["en"])
    for language in SUPPORTED_LANGUAGES:
        missing = english_keys - set(TRANSLATIONS[language])
        assert not missing, f"{language} is missing: {sorted(missing)}"


def test_translation_formats_dynamic_values():
    assert "12.5" in Translator("ru").t(
        "health.storage.ok",
        pct=12.5,
    )
    assert "7" in Translator("es").t(
        "health.startup.count",
        count=7,
    )
    assert "3" in Translator("zh-CN").t(
        "overview.completed",
        count=3,
    )
    assert "12.5" in Translator("fi").t(
        "health.storage.ok",
        pct=12.5,
    )
    assert "7" in Translator("pl").t(
        "health.startup.count",
        count=7,
    )
    assert "3" in Translator("mn").t(
        "overview.completed",
        count=3,
    )


def test_new_locales_translate_core_ui_strings():
    assert Translator("fi").t("nav.overview") == "Yleiskatsaus"
    assert Translator("pl").t("nav.security") == "Bezpieczeństwo"
    assert Translator("mn").t("language.label") == "Хэл"


def test_unknown_key_falls_back_to_key_name():
    assert Translator("ru").t("missing.key") == "missing.key"



def test_settings_catalog_is_complete_in_every_language():
    keys = {
        key
        for key in TRANSLATIONS["en"]
        if key.startswith("settings.") or key == "nav.settings"
    }
    assert keys
    for language in SUPPORTED_LANGUAGES:
        assert keys <= set(TRANSLATIONS[language])
