import pytest

from antios.cli import build_parser


def test_virus_scan_defaults_to_owned_antios_engine():
    args = build_parser().parse_args(["virus-scan", "fixture"])
    assert args.engine == "antios"


def test_quarantine_defaults_to_owned_antios_engine():
    args = build_parser().parse_args(["quarantine", "add", "fixture"])
    assert args.engine == "antios"


@pytest.mark.parametrize("obsolete", ["clamav", "amsi"])
def test_external_scan_engine_choices_are_no_longer_accepted(obsolete):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["virus-scan", "fixture", "--engine", obsolete])
