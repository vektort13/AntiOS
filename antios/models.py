from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RegistryTarget:
    hive: str
    path: str
    name: str
    kind: str = "string"
    mutable: bool = False
    description: str = ""

    @property
    def key(self) -> str:
        return f"{self.hive}\\{self.path}::{self.name}"


@dataclass
class RegistryValue:
    target: RegistryTarget
    exists: bool
    value: Any = None
    reg_type: int | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": asdict(self.target),
            "exists": self.exists,
            "value": self.value,
            "reg_type": self.reg_type,
            "error": self.error,
        }


@dataclass
class IdentityPlan:
    computer_name: str | None = None
    registered_owner: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return asdict(self)
