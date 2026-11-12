import pytest

from antios.system_name import MemoryComputerNameBackend, validate_computer_name


@pytest.mark.parametrize("name", ["LAB-PC", "PC1", "A", "A-B-C"])
def test_valid_computer_names(name):
    assert validate_computer_name(name) == name


@pytest.mark.parametrize(
    "name",
    ["", "12345", "-PC", "PC-", "PC NAME", "PC.NAME", "0123456789ABCDEF"],
)
def test_invalid_computer_names(name):
    with pytest.raises(ValueError):
        validate_computer_name(name)


def test_memory_backend_uses_same_validation():
    backend = MemoryComputerNameBackend("OLD-PC")
    backend.set_name("NEW-PC")
    assert backend.current_name() == "NEW-PC"

    with pytest.raises(ValueError):
        backend.set_name("BAD NAME")
