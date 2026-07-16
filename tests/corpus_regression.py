#!/usr/bin/env python3
"""Hash-pinned, optional end-to-end regression for local APK fixtures."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path


FIXTURES = (
    {
        "label": "protected-positive",
        "filename": "app-release.apk",
        "sha256": "F2065478741B4142229AD69BA63B33F62ADB0158F0DC6B0CFC65F274B2C2D741",
        "likely": {"liboutput64.so", "libflare.so"},
        "outcomes": {},
    },
    {
        "label": "large-mixed-corpus",
        "filename": "taobao.apk",
        "sha256": "4DFA3F1B337B24E0B5C5BB722B4111813E5DE59C816D5643317FEFA848F47A4A",
        "likely": {"libsgmainso-6.8.260404.so"},
        "outcomes": {
            "libquickjs.so": "VM_LIKE_INTERPRETER",
            "libtbffmpeg.so": "VM_LIKE_INTERPRETER",
            "libnano_compose.so": "VM_LIKE_INTERPRETER",
            "libunicorn.so": "VM_LIKE_INTERPRETER",
            "libtaobaoplayer.so": "SUSPICIOUS_VM_STRUCTURE",
        },
    },
    {
        "label": "unicode-path",
        "filename": None,
        "sha256": "27C9C93BCF9154D1E072A079F08A8BA67B0E1FCA41A4526066B85E91566C776F",
        "likely": {"libflare.so", "libyaqcore_gdtadv.so"},
        "outcomes": {},
    },
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest().upper()


def locate_fixture(root: Path, fixture: dict) -> Path | None:
    filename = fixture["filename"]
    if filename:
        candidate = root / filename
        return candidate if candidate.is_file() else None
    for candidate in root.glob("*.apk"):
        if sha256(candidate) == fixture["sha256"]:
            return candidate
    return None


def so_basename(value: str) -> str:
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def run_fixture(scanner: Path, apk: Path, fixture: dict) -> list[str]:
    actual_hash = sha256(apk)
    if actual_hash != fixture["sha256"]:
        return [f"hash mismatch: expected {fixture['sha256']}, got {actual_hash}"]

    process = subprocess.run(
        [str(scanner), str(apk), "--en"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=180,
        check=False,
    )
    if process.returncode != 0:
        stderr = process.stderr.decode("utf-8", "replace").strip()
        return [f"scanner exit={process.returncode}: {stderr}"]
    try:
        payload = json.loads(process.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        return [f"invalid UTF-8 JSON: {error}"]

    results = {
        so_basename(item.get("so_file", "")): item
        for item in payload.get("results", [])
    }
    actual_likely = {
        name for name, item in results.items()
        if item.get("vmp_outcome") == "LIKELY_VMP"
    }
    failures: list[str] = []
    if actual_likely != fixture["likely"]:
        failures.append(
            f"LIKELY_VMP drift: expected {sorted(fixture['likely'])}, "
            f"got {sorted(actual_likely)}"
        )
    for name, expected in fixture["outcomes"].items():
        actual = results.get(name, {}).get("vmp_outcome")
        if actual != expected:
            failures.append(f"{name}: expected {expected}, got {actual}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scanner", type=Path,
                        default=Path("cmake-build-release/ObfuScan.exe"))
    parser.add_argument("--fixtures", type=Path, default=Path("."))
    parser.add_argument("--require-all", action="store_true")
    args = parser.parse_args()

    scanner = args.scanner.resolve()
    root = args.fixtures.resolve()
    if not scanner.is_file():
        print(f"[FAIL] scanner not found: {scanner}", file=sys.stderr)
        return 2

    failed = False
    executed = 0
    for fixture in FIXTURES:
        path = locate_fixture(root, fixture)
        if path is None:
            message = f"[SKIP] {fixture['label']}: hash-pinned APK not found"
            print(message)
            failed = failed or args.require_all
            continue
        executed += 1
        failures = run_fixture(scanner, path, fixture)
        if failures:
            failed = True
            print(f"[FAIL] {fixture['label']} ({path.name})")
            for failure in failures:
                print(f"  - {failure}")
        else:
            print(f"[PASS] {fixture['label']} ({path.name})")

    print(f"executed={executed} total={len(FIXTURES)}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
