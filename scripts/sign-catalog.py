"""Sign a reviewed AntiOS catalog with the Windows publisher's protected key."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from antios.antivirus import read_regular
from antios.quarantine import DPAPIProtector
from antios.signature_bootstrap import PUBLIC_KEY
from antios.signature_catalog import MAX_PACKAGE_BYTES, signed_bytes, verify_catalog


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--dpapi-key", type=Path, required=True)
    args = parser.parse_args()

    protected, _ = read_regular(args.dpapi_key, 4096)
    key = Ed25519PrivateKey.from_private_bytes(DPAPIProtector().unprotect(protected))
    if key.public_key().public_bytes_raw() != PUBLIC_KEY:
        parser.error("Publisher key does not match the public key bundled with AntiOS")
    source, _ = read_regular(args.catalog, MAX_PACKAGE_BYTES)
    catalog = json.loads(source)
    signature = key.sign(signed_bytes(catalog))
    package = (json.dumps({"catalog": catalog, "signature": signature.hex()},
                          indent=2, sort_keys=True) + "\n").encode("utf-8")
    result = verify_catalog(package)
    with args.output.open("xb") as stream:
        stream.write(package)
    print(f"Signed AntiOS catalog v{result.version} with {len(result.rules)} hashes")


if __name__ == "__main__":
    main()
