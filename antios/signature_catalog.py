"""Authenticated local catalog updates shared by all AntiOS scan entry points."""
from __future__ import annotations

from contextlib import closing
from dataclasses import dataclass, replace
from datetime import date
from functools import lru_cache
import json
import os
from pathlib import Path
import re
import sqlite3
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .signature_bootstrap import BUNDLED_PACKAGE, PUBLIC_KEY

MAX_PACKAGE_BYTES = 8 * 1024 * 1024
_SIGNING_CONTEXT = b"AntiOS.SignatureCatalog.v1\0"


def default_catalog_path() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData/Local")
        return (root / "AntiOS" / "signatures.sqlite3").absolute()
    root = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    return (root / "antios" / "signatures.sqlite3").absolute()


def _object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate signature package field")
        value[key] = item
    return value


def _json(data: bytes) -> dict:
    try:
        result = json.loads(data, object_pairs_hook=_object)
    except (ValueError, RecursionError) as exc:
        raise ValueError("Invalid signature package JSON") from exc
    if not isinstance(result, dict):
        raise ValueError("Invalid signature package object")
    return result


def signed_bytes(catalog: dict) -> bytes:
    """Canonical byte representation used by the verifier and offline signer."""
    return _SIGNING_CONTEXT + json.dumps(
        catalog, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(",", ":"),
    ).encode("ascii")


def _date(value) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("Invalid signature catalog date")
    date.fromisoformat(value)
    return value


@dataclass(frozen=True)
class Catalog:
    version: int
    published: str
    rules: Mapping[str, str]
    source: str = "bundled"
    warning: str = ""

    def metadata(self) -> dict:
        result = {
            "signature_catalog_version": self.version,
            "signature_catalog_published": self.published,
            "signature_catalog_status": "fallback" if self.warning else self.source,
            "signature_catalog_entries": len(self.rules),
        }
        if self.warning:
            result["signature_catalog_warning"] = self.warning
        return result


def verify_catalog(package: bytes, public_key: bytes | None = None) -> Catalog:
    if not isinstance(package, bytes) or len(package) > MAX_PACKAGE_BYTES:
        raise ValueError("Invalid signature package size")
    envelope = _json(package)
    if set(envelope) != {"catalog", "signature"} or not isinstance(envelope["catalog"], dict):
        raise ValueError("Invalid signature package envelope")
    catalog, signature = envelope["catalog"], envelope["signature"]
    if not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{128}", signature):
        raise ValueError("Invalid catalog signature format")
    try:
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY if public_key is None else public_key).verify(
            bytes.fromhex(signature), signed_bytes(catalog),
        )
    except (InvalidSignature, RecursionError) as exc:
        raise ValueError("Signature catalog authentication failed") from exc
    if set(catalog) != {"schema", "version", "published", "sha256"} or (
            type(catalog["schema"]) is not int or catalog["schema"] != 1):
        raise ValueError("Unsupported signature catalog schema")
    version = catalog["version"]
    if type(version) is not int or not 1 <= version <= 2_147_483_647:
        raise ValueError("Invalid signature catalog version")
    published = _date(catalog["published"])
    entries = catalog["sha256"]
    if not isinstance(entries, dict) or len(entries) > 50_000:
        raise ValueError("Invalid signature catalog entry count")
    rules = {}
    for digest, entry in entries.items():
        if not re.fullmatch(r"[a-f0-9]{64}", digest) or not isinstance(entry, dict) or (
                set(entry) != {"label", "source", "source_date"}):
            raise ValueError("Invalid catalog entry")
        label, source = entry["label"], entry["source"]
        if (not isinstance(label, str) or not label.strip() or not label.isprintable()
                or len(label) > 200 or not isinstance(source, str)
                or not source.isascii() or not source.isprintable() or len(source) > 500):
            raise ValueError("Invalid catalog label or source")
        url = urlsplit(source)
        if url.scheme != "https" or not url.hostname or url.username or url.password:
            raise ValueError("Invalid catalog source URL")
        if _date(entry["source_date"]) > published:
            raise ValueError("Catalog source postdates publication")
        rules[digest] = label
    return Catalog(version, published, MappingProxyType(rules))


@lru_cache(maxsize=1)
def bundled_catalog() -> Catalog:
    return verify_catalog(BUNDLED_PACKAGE)


def _versions(db):
    return db.execute(
        """SELECT version, CASE WHEN length(package) <= ? THEN package END
           FROM catalogs ORDER BY version DESC LIMIT 2""",
        (MAX_PACKAGE_BYTES,),
    ).fetchall()


def load_active_catalog() -> Catalog:
    from .antivirus import checked_path

    baseline = bundled_catalog()
    try:
        path = checked_path(default_catalog_path())
    except FileNotFoundError:
        return baseline
    except (OSError, ValueError):
        return replace(baseline, warning="Installed signature catalog cannot be read")
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            versions = _versions(db)
    except sqlite3.Error:
        return replace(baseline, warning="Installed signature catalog cannot be read")

    warning = "" if versions else "Installed signature catalog is empty"
    for version, package in versions:
        if type(version) is not int:
            warning = "Installed signature catalog failed validation"
            continue
        if version <= baseline.version:
            break
        try:
            catalog = verify_catalog(package)
            if catalog.version != version:
                raise ValueError("Catalog version mismatch")
        except ValueError:
            warning = "Installed signature catalog failed validation"
            continue
        return replace(catalog, source="installed", warning=warning)
    return replace(baseline, warning=warning)


def install_catalog(path: str | Path) -> Catalog:
    from .antivirus import checked_path, read_regular

    package, _ = read_regular(Path(path), MAX_PACKAGE_BYTES)
    catalog = verify_catalog(package)
    baseline = bundled_catalog()
    if catalog.version <= baseline.version:
        raise ValueError("Update must be newer than the bundled signature catalog")

    target = default_catalog_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    checked_path(target.parent)
    try:
        checked_path(target)
    except FileNotFoundError:
        pass
    try:
        with closing(sqlite3.connect(target, timeout=5)) as db, db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("BEGIN IMMEDIATE")
            db.execute("CREATE TABLE IF NOT EXISTS catalogs (version INTEGER PRIMARY KEY, package BLOB NOT NULL)")
            versions = _versions(db)
            if any(type(version) is not int for version, _ in versions):
                raise ValueError("Installed signature catalog versions are invalid")
            if versions and catalog.version <= versions[0][0]:
                if (catalog.version, package) == versions[0]:
                    return replace(catalog, source="installed")
                raise ValueError("Update must be newer than the installed signature catalog")
            db.execute("INSERT INTO catalogs VALUES (?, ?)", (catalog.version, package))
            # Keep the latest older *verified* package as a fallback.
            keep = baseline.version
            for version, previous in versions:
                if version <= baseline.version:
                    break
                try:
                    if verify_catalog(previous).version == version:
                        keep = version
                        break
                except ValueError:
                    continue
            db.execute("DELETE FROM catalogs WHERE version NOT IN (?, ?)", (catalog.version, keep))
    except sqlite3.Error as exc:
        raise OSError("Signature catalog update could not be committed") from exc
    return replace(catalog, source="installed")
