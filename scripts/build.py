#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_FILTER_URL = "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt"
DEFAULT_OUT_DIR = "dist"
DEFAULT_OUT_NAME = "adguard-sdns"
DEFAULT_MATCH_DOMAIN = "doubleclick.net"
DEFAULT_CONTROL_DOMAIN = "example.com"


@dataclass(frozen=True)
class BuildConfig:
    filter_url: str
    out_dir: Path
    out_name: str
    sing_box_bin: str
    match_domain: str
    control_domain: str


def env_config() -> BuildConfig:
    return BuildConfig(
        filter_url=os.environ.get("FILTER_URL", DEFAULT_FILTER_URL),
        out_dir=Path(os.environ.get("OUT_DIR", DEFAULT_OUT_DIR)),
        out_name=os.environ.get("OUT_NAME", DEFAULT_OUT_NAME),
        sing_box_bin=os.environ.get("SING_BOX_BIN", "sing-box"),
        match_domain=os.environ.get("MATCH_DOMAIN", DEFAULT_MATCH_DOMAIN),
        control_domain=os.environ.get("CONTROL_DOMAIN", DEFAULT_CONTROL_DOMAIN),
    )


def download(url: str, destination: Path, retries: int = 5) -> None:
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "adguard-sdns-srs/1.0",
            "Accept": "text/plain,*/*",
        },
    )
    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise RuntimeError(f"unexpected HTTP status {status}")
                with destination.open("wb") as output:
                    shutil.copyfileobj(response, output)
            return
        except (OSError, urllib.error.URLError, RuntimeError) as exc:
            last_error = exc
            if attempt == retries:
                break
            time.sleep(min(2**attempt, 20))
    raise RuntimeError(f"failed to download {url}: {last_error}") from last_error


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def validate_filter(path: Path) -> str:
    data = read_text(path)
    header = data[:4096]
    size = path.stat().st_size
    lines = data.splitlines()

    if size < 1_000_000:
        raise RuntimeError(f"filter is unexpectedly small: {size} bytes")
    if len(lines) < 10_000:
        raise RuntimeError(f"filter has unexpectedly few lines: {len(lines)}")
    if "Title: AdGuard DNS filter" not in header:
        raise RuntimeError("filter title check failed")
    if "adguardsdnsfilter" not in header.lower():
        raise RuntimeError("filter homepage/source check failed")
    return data


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, capture_output=True, text=True)
    if check and completed.returncode != 0:
        if completed.stdout:
            print(completed.stdout, file=sys.stderr, end="")
        if completed.stderr:
            print(completed.stderr, file=sys.stderr, end="")
        raise RuntimeError(f"command failed: {' '.join(command)}")
    return completed


def sing_box_command(config: BuildConfig) -> list[str]:
    return [config.sing_box_bin, "--disable-color"]


def sing_box_version(config: BuildConfig) -> str:
    completed = run([*sing_box_command(config), "version"])
    return completed.stdout.splitlines()[0].strip()


def convert_rule_set(config: BuildConfig, source: Path, output: Path) -> str:
    completed = run(
        [
            *sing_box_command(config),
            "rule-set",
            "convert",
            "--type",
            "adguard",
            "--output",
            str(output),
            str(source),
        ]
    )
    log = completed.stdout + completed.stderr
    for line in log.splitlines():
        if "parsed rules:" in line:
            print(line)
    if not output.is_file() or output.stat().st_size == 0:
        raise RuntimeError("converted rule-set is empty")
    if output.stat().st_size < 500_000:
        raise RuntimeError(f"converted rule-set is unexpectedly small: {output.stat().st_size} bytes")
    return log


def rule_set_match(config: BuildConfig, rule_set: Path, domain: str) -> str:
    completed = run(
        [
            *sing_box_command(config),
            "rule-set",
            "match",
            "-f",
            "binary",
            str(rule_set),
            domain,
        ]
    )
    return completed.stdout + completed.stderr


def validate_rule_set(config: BuildConfig, rule_set: Path) -> dict[str, str | bool]:
    match_output = rule_set_match(config, rule_set, config.match_domain)
    if "match" not in match_output:
        raise RuntimeError(f"converted rule-set did not match {config.match_domain}")

    control_output = rule_set_match(config, rule_set, config.control_domain)
    if "match" in control_output:
        raise RuntimeError(f"converted rule-set unexpectedly matched {config.control_domain}")

    return {
        "match_domain": config.match_domain,
        "match_domain_matched": True,
        "control_domain": config.control_domain,
        "control_domain_matched": False,
    }


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def header_value(source_text: str, prefix: str) -> str | None:
    needle = f"! {prefix}: "
    for line in source_text.splitlines()[:80]:
        if line.startswith(needle):
            return line[len(needle) :].strip()
    return None


def write_outputs(
    config: BuildConfig,
    filter_path: Path,
    source_text: str,
    rule_set_path: Path,
    validation: dict[str, str | bool],
    version: str,
) -> None:
    config.out_dir.mkdir(parents=True, exist_ok=True)
    filter_out = config.out_dir / f"{config.out_name}.txt"
    rule_set_out = config.out_dir / f"{config.out_name}.srs"

    shutil.copyfile(filter_path, filter_out)
    shutil.copyfile(rule_set_path, rule_set_out)

    filter_hash = sha256(filter_out)
    rule_set_hash = sha256(rule_set_out)

    (config.out_dir / f"{config.out_name}.txt.sha256").write_text(
        f"{filter_hash}  {config.out_name}.txt\n",
        encoding="utf-8",
    )
    (config.out_dir / f"{config.out_name}.srs.sha256").write_text(
        f"{rule_set_hash}  {config.out_name}.srs\n",
        encoding="utf-8",
    )

    metadata = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "source": {
            "url": config.filter_url,
            "title": header_value(source_text, "Title"),
            "description": header_value(source_text, "Description"),
            "homepage": header_value(source_text, "Homepage"),
            "license": header_value(source_text, "License"),
            "last_modified": header_value(source_text, "Last modified"),
        },
        "converter": {
            "command": "sing-box rule-set convert --type adguard",
            "sing_box_version": version,
        },
        "validation": validation,
        "artifacts": {
            f"{config.out_name}.txt": {
                "bytes": filter_out.stat().st_size,
                "sha256": filter_hash,
                "lines": len(source_text.splitlines()),
            },
            f"{config.out_name}.srs": {
                "bytes": rule_set_out.stat().st_size,
                "sha256": rule_set_hash,
            },
        },
    }

    (config.out_dir / "metadata.json").write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def build() -> None:
    config = env_config()
    version = sing_box_version(config)

    with tempfile.TemporaryDirectory() as temp:
        temp_dir = Path(temp)
        filter_path = temp_dir / f"{config.out_name}.txt"
        rule_set_path = temp_dir / f"{config.out_name}.srs"

        download(config.filter_url, filter_path)
        source_text = validate_filter(filter_path)
        convert_rule_set(config, filter_path, rule_set_path)
        validation = validate_rule_set(config, rule_set_path)
        write_outputs(config, filter_path, source_text, rule_set_path, validation, version)

    print(f"Built {config.out_dir / (config.out_name + '.srs')}")


if __name__ == "__main__":
    try:
        build()
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc

