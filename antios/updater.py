"""Release discovery and signature-gated AntiOS update downloads."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from urllib.request import Request, urlopen

from . import __version__
from .windows_process import hidden_process_kwargs, system_executable

RELEASES_API = "https://api.github.com/repos/Dargon777/AntiOS/releases"
MAX_RELEASE_RESPONSE = 2 * 1024 * 1024
MAX_SETUP_BYTES = 512 * 1024 * 1024
MAX_CHECKSUM_BYTES = 4096


def _version_key(version: str) -> tuple[int, int, int, int]:
    """Return comparable major/minor/patch/alpha components."""
    match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)a(\d+)", version)
    if not match:
        raise ValueError(f"Unsupported AntiOS version format: {version}")
    return tuple(map(int, match.groups()))


def _tag_key(tag: str) -> tuple[int, int, int, int] | None:
    """Support legacy v2 tags and the V.3.0.01-Alpha release naming."""
    match = re.fullmatch(
        r"v\.?(\d+)\.(\d+)\.(\d+)-alpha(?:\.(\d+))?",
        tag, flags=re.IGNORECASE,
    )
    if not match:
        return None
    major, minor, patch, alpha = match.groups()
    return int(major), int(minor), int(patch), int(alpha or "1")


def _request_json(url: str) -> object:
    request = Request(url, headers={"User-Agent": f"AntiOS/{__version__}", "Accept": "application/vnd.github+json"})
    with urlopen(request, timeout=20) as response:
        content = response.read(MAX_RELEASE_RESPONSE + 1)
    if len(content) > MAX_RELEASE_RESPONSE:
        raise RuntimeError("GitHub release response is too large")
    return json.loads(content)


def latest_alpha() -> dict:
    data = _request_json(RELEASES_API)
    if not isinstance(data, list):
        raise RuntimeError("Unexpected GitHub releases response")
    candidates = []
    for release in data:
        if not isinstance(release, dict) or release.get("draft"):
            continue
        key = _tag_key(str(release.get("tag_name", "")))
        if key is not None:
            candidates.append((key, release))
    if not candidates:
        raise RuntimeError("No AntiOS alpha releases found")
    key, release = max(candidates, key=lambda item: item[0])
    assets = {}
    for asset in release.get("assets") or []:
        if isinstance(asset, dict) and isinstance(asset.get("name"), str):
            assets[asset["name"]] = {
                "url": asset.get("browser_download_url"),
                "size": asset.get("size"),
                "digest": asset.get("digest"),
            }
    current = _version_key(__version__)
    major, minor, patch, alpha = key
    return {
        "current_version": __version__,
        "current_alpha": current[3],
        "latest_alpha": alpha,
        "latest_version": f"{major}.{minor}.{patch}a{alpha}",
        "tag": release.get("tag_name"),
        "published_at": release.get("published_at"),
        "html_url": release.get("html_url"),
        "update_available": key > current,
        "assets": assets,
    }


def _download(url: str, destination: Path, limit: int) -> None:
    if not isinstance(url, str) or not url.startswith(
        "https://github.com/Dargon777/AntiOS/releases/download/"
    ):
        raise RuntimeError("Refusing an unexpected update download URL")
    request = Request(url, headers={"User-Agent": f"AntiOS/{__version__}"})
    with urlopen(request, timeout=60) as response, destination.open("xb") as stream:
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise RuntimeError("Update download exceeds the safety limit")
            stream.write(block)
        stream.flush()
        os.fsync(stream.fileno())


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            block = stream.read(1024 * 1024)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _parse_checksum(content: bytes) -> str:
    if len(content) > MAX_CHECKSUM_BYTES:
        raise RuntimeError("Update checksum file is too large")
    text = content.decode("ascii", errors="strict").strip()
    match = re.fullmatch(r"([a-f0-9]{64})\s+\*?AntiOS-Setup\.exe", text)
    if not match:
        raise RuntimeError("Update checksum file has an unexpected format")
    return match.group(1)


def _authenticode(path: Path) -> dict:
    if os.name != "nt":
        raise OSError("Authenticode verification requires Windows")
    powershell = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    escaped = str(path).replace("'", "''")
    command = (
        "$ErrorActionPreference='Stop';"
        "Import-Module Microsoft.PowerShell.Security -ErrorAction Stop;"
        f"$p='{escaped}';"
        "$s=Get-AuthenticodeSignature -LiteralPath $p;"
        "[pscustomobject]@{Status=[string]$s.Status;"
        "Subject=if($s.SignerCertificate){$s.SignerCertificate.Subject}else{$null};"
        "Thumbprint=if($s.SignerCertificate){$s.SignerCertificate.Thumbprint}else{$null}}"
        "|ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        [str(powershell), "-NoProfile", "-NonInteractive", "-Command", command],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
        **hidden_process_kwargs(),
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or "Authenticode verification failed").strip())
    payload = json.loads(result.stdout)
    return payload if isinstance(payload, dict) else {}


def _signature_thumbprint(signature: dict, *, label: str) -> str:
    """Accept only valid Authenticode with a concrete certificate identity."""
    if not isinstance(signature, dict) or signature.get("Status") != "Valid":
        raise RuntimeError(f"{label} has no valid Authenticode signature")
    thumbprint = str(signature.get("Thumbprint") or "").upper()
    if not re.fullmatch(r"[A-F0-9]{40}", thumbprint):
        raise RuntimeError(f"{label} has no usable signing-certificate thumbprint")
    return thumbprint


def _installed_signer_thumbprint() -> str:
    """Pin the current machine-installed, signed AntiOS CLI certificate.

    Until publisher certificate rollover is implemented as an authenticated
    explicit migration, new Setup must use the same leaf certificate. Never
    trust an arbitrary globally valid Authenticode signer for an AntiOS update.
    """
    from .elevation import managed_cli_path

    reference = managed_cli_path()
    return _signature_thumbprint(_authenticode(reference), label="Installed AntiOS CLI")


def _matches_installed_signer(signature: dict, trusted_thumbprint: str) -> bool:
    try:
        signer = _signature_thumbprint(signature, label="Downloaded AntiOS Setup")
    except RuntimeError:
        return False
    return hmac.compare_digest(signer, trusted_thumbprint)


def default_update_directory(tag: str | None = None) -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        root = base / "AntiOS" / "Updates"
    else:
        root = Path(tempfile.gettempdir()) / "AntiOS-Updates"
    if tag:
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", tag)
        root = root / safe
    return root


def download_update(
    directory: str | Path | None = None,
    *,
    require_signature: bool = True,
    replace_existing: bool = False,
) -> dict:
    release = latest_alpha()
    if not release["update_available"]:
        return dict(release, downloaded=False)

    setup = release["assets"].get("AntiOS-Setup.exe")
    checksum = release["assets"].get("AntiOS-Setup.exe.sha256")
    if not setup or not checksum:
        raise RuntimeError("Latest AntiOS release does not contain Setup/checksum assets")

    target_dir = Path(directory) if directory else Path(tempfile.mkdtemp(prefix="AntiOS-Update-"))
    target_dir.mkdir(parents=True, exist_ok=True)
    setup_path = target_dir / "AntiOS-Setup.exe"
    checksum_path = target_dir / "AntiOS-Setup.exe.sha256"
    if setup_path.exists() or checksum_path.exists():
        if not replace_existing:
            raise FileExistsError("Update destination already contains AntiOS update files")
        setup_path.unlink(missing_ok=True)
        checksum_path.unlink(missing_ok=True)

    try:
        _download(str(checksum["url"]), checksum_path, MAX_CHECKSUM_BYTES)
        _download(str(setup["url"]), setup_path, MAX_SETUP_BYTES)
        expected = _parse_checksum(checksum_path.read_bytes())
        actual = _sha256_file(setup_path)
        if actual != expected:
            raise RuntimeError("Downloaded AntiOS Setup failed SHA-256 verification")
        api_digest = setup.get("digest")
        if api_digest and api_digest != f"sha256:{actual}":
            raise RuntimeError("GitHub asset digest does not match downloaded Setup")

        signature = None
        publisher_verified = False
        publisher_error = (
            "Authenticode publisher verification requires Windows"
            if os.name != "nt" else None
        )
        if require_signature or os.name == "nt":
            try:
                signature = _authenticode(setup_path)
                trusted_thumbprint = _installed_signer_thumbprint()
                publisher_verified = _matches_installed_signer(signature, trusted_thumbprint)
                if not publisher_verified:
                    raise RuntimeError(
                        "AntiOS Setup signer does not match the signed installed AntiOS CLI"
                    )
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                if require_signature:
                    raise RuntimeError(
                        "Automatic AntiOS update refused: publisher identity could not be verified"
                    ) from exc
                publisher_error = str(exc)[:1000]
        return dict(
            release,
            downloaded=True,
            setup_path=str(setup_path),
            sha256=actual,
            signature=signature,
            publisher_verified=publisher_verified,
            publisher_error=publisher_error,
            signature_required_for_install=True,
            install_ready=publisher_verified,
            download_directory=str(target_dir),
        )
    except Exception:
        setup_path.unlink(missing_ok=True)
        checksum_path.unlink(missing_ok=True)
        raise


def _update_handoff_script(
    setup: Path, expected_sha256: str, parent_pid: int, trusted_thumbprint: str,
) -> str:
    """Generate a fixed handoff, pinned to the installed AntiOS certificate."""
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256):
        raise ValueError("Invalid expected update digest")
    if not isinstance(parent_pid, int) or parent_pid <= 0:
        raise ValueError("Invalid parent process")
    if not re.fullmatch(r"[A-F0-9]{40}", trusted_thumbprint):
        raise ValueError("Invalid trusted AntiOS publisher thumbprint")
    escaped = str(setup).replace("'", "''")
    return (
        "$ErrorActionPreference='Stop';"
        f"$waitPid={parent_pid};$setup='{escaped}';$expected='{expected_sha256}';"
        f"$trustedThumbprint='{trusted_thumbprint}';"
        "$deadline=(Get-Date).AddSeconds(120);"
        "while(Get-Process -Id $waitPid -ErrorAction SilentlyContinue){"
        "if((Get-Date) -ge $deadline){throw 'AntiOS did not exit; update cancelled.'};"
        "Start-Sleep -Milliseconds 500};"
        "Start-Sleep -Milliseconds 750;"
        # An exclusive-write-denying read handle prevents a same-user attacker
        # from swapping the downloaded Setup between verification and launch.
        "$file=[IO.File]::Open($setup,[IO.FileMode]::Open,"
        "[IO.FileAccess]::Read,[IO.FileShare]::Read);"
        "try{"
        "$actual=(Get-FileHash -InputStream $file -Algorithm SHA256).Hash.ToLowerInvariant();"
        "if($actual -ne $expected){throw 'AntiOS update digest changed before install.'};"
        "$sig=Get-AuthenticodeSignature -LiteralPath $setup;"
        "if($sig.Status -ne 'Valid' -or -not $sig.SignerCertificate)"
        "{throw 'AntiOS update signature is no longer valid.'};"
        "$thumb=$sig.SignerCertificate.Thumbprint.ToUpperInvariant();"
        "if($thumb -cne $trustedThumbprint)"
        "{throw 'AntiOS update publisher certificate changed.'};"
        "$installer=Start-Process -FilePath $setup -ArgumentList '/S'"
        " -Verb RunAs -Wait -PassThru;"
        "if($installer.ExitCode -ne 0){throw ('AntiOS Setup exited with '+$installer.ExitCode)};"
        "}finally{$file.Dispose()}"
    )


def schedule_install(setup_path: str | Path, expected_sha256: str) -> dict:
    """Run verified Setup after AntiOS exits, with bounded waiting.

    Do not stage an executable PowerShell script in the writable update cache.
    Re-check both the digest and the Authenticode signature before install.
    """
    if os.name != "nt":
        raise OSError("Automatic AntiOS installation requires Windows")
    setup = Path(setup_path).resolve()
    if not setup.is_file():
        raise FileNotFoundError(setup)
    if setup.name != "AntiOS-Setup.exe":
        raise ValueError("Expected an AntiOS-Setup.exe installer")
    # Recheck in the launching process, then pin the same trusted certificate
    # in the handoff so neither a different signer nor replaced bytes can run.
    if _sha256_file(setup) != expected_sha256:
        raise RuntimeError("AntiOS installer digest changed before scheduling")
    trusted_thumbprint = _installed_signer_thumbprint()
    if not _matches_installed_signer(_authenticode(setup), trusted_thumbprint):
        raise RuntimeError("Automatic install refused: AntiOS publisher certificate differs")
    command = _update_handoff_script(
        setup, expected_sha256, os.getpid(), trusted_thumbprint,
    )
    powershell = system_executable("WindowsPowerShell/v1.0/powershell.exe")
    process = subprocess.Popen(
        [
            str(powershell), "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-Command", command,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        **hidden_process_kwargs(
            extra_creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        ),
    )
    return {
        "scheduled": True,
        "helper_pid": process.pid,
        "setup_path": str(setup),
        "sha256": expected_sha256,
    }
