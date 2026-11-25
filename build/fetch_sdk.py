#!/usr/bin/env python3
"""Fetch the Envoy dynamic modules SDK for the pinned release and verify every
file against a recorded SHA-256.

Runs in the `sdk` build stage. Python's urllib and hashlib are used on purpose:
the stage then needs no apt, no package manager, and no repository metadata, so
the SDK download is reproducible and fails closed on a changed upstream file.
"""

import hashlib
import os
import urllib.request

ROOT = "/sdk/source/extensions/dynamic_modules"
FILES = {
    "abi/abi.h": "5c004204a634b5a07c3f2af63d3b4117a5bb8ce5a53bca4a98fb41cf86a1f0a7",
    "sdk/cpp/sdk.h": "ff0c4b53ce37aa1f67c42b17c9c051f1df4b95e8a4d16795a5c31ed011919372",
    "sdk/cpp/sdk_common.h": "b2b80a7fe9fa8b7f061cf6ffcf82b5b9865a81b3904c2bf3d6fd6b2c61bc73a8",
    "sdk/cpp/sdk_internal_common.h": "eb09f6b18ab5ba33035b429c3c4132bca6743e1f58abf522eeb1ba2787667d48",
    "sdk/cpp/sdk.cc": "c7673c017e46688fbf1e306dacf51a685b1269a3d35103e4b6f0bb322bd38b1a",
    "sdk/cpp/sdk_internal.cc": "acef0362b151a1a7dad877a8b37828a45980eb03897db6250509c69eb63fa5c9",
}


def main() -> int:
    version = os.environ["ENVOY_VERSION"]
    base = ("https://raw.githubusercontent.com/envoyproxy/envoy/v"
            + version + "/source/extensions/dynamic_modules")
    for path, expected in FILES.items():
        with urllib.request.urlopen(base + "/" + path, timeout=60) as response:
            data = response.read()
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise SystemExit(f"checksum mismatch for {path}: {actual}")
        destination = os.path.join(ROOT, path)
        os.makedirs(os.path.dirname(destination), exist_ok=True)
        with open(destination, "wb") as handle:
            handle.write(data)
    print(f"SDK v{version} verified: {len(FILES)} files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
