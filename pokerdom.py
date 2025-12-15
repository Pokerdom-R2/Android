#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Requirements:
- Python 3.8+
- Optional: androguard (for AndroidManifest parsing)
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

import zipfile


DEFAULT_APK_NAME = "pokerdom.apk"
DEFAULT_REPORT_NAME = "pokerdom_report.txt"
READ_CHUNK_SIZE = 8 * 1024 * 1024  # 8 MiB


@dataclass
class FileInfo:
    name: str
    path: str
    size_bytes: int
    size_mib: float
    mtime_local: str
    sha256: str
    md5: str


@dataclass
class ZipInfoSummary:
    file_count: int
    total_uncompressed_bytes: int
    has_android_manifest: bool
    has_resources_arsc: bool
    has_meta_inf: bool
    dex_files: List[str]
    abis: List[str]
    native_libs: List[str]
    top_largest: List[Tuple[str, int]]


@dataclass
class ManifestInfo:
    available: bool
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    debuggable: Optional[str] = None
    permissions: Optional[List[str]] = None
    error: Optional[str] = None
    install_hint: Optional[str] = None


def human_mib(size_bytes: int) -> float:
    return round(size_bytes / (1024 * 1024), 2)


def format_local_dt(ts: float) -> str:
    # Local time string
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def iter_file_chunks(path: Path, chunk_size: int = READ_CHUNK_SIZE) -> Iterable[bytes]:
    with path.open("rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def compute_hashes(path: Path) -> Tuple[str, str]:
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()
    for chunk in iter_file_chunks(path):
        sha256.update(chunk)
        md5.update(chunk)
    return sha256.hexdigest(), md5.hexdigest()


def collect_file_info(apk_path: Path) -> FileInfo:
    st = apk_path.stat()
    sha256_hex, md5_hex = compute_hashes(apk_path)
    return FileInfo(
        name=apk_path.name,
        path=str(apk_path.resolve()),
        size_bytes=st.st_size,
        size_mib=human_mib(st.st_size),
        mtime_local=format_local_dt(st.st_mtime),
        sha256=sha256_hex,
        md5=md5_hex,
    )


def collect_zip_info(apk_path: Path, top_n: int = 10, max_native_list: int = 200) -> ZipInfoSummary:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            infos = zf.infolist()
            names = [i.filename for i in infos]

            total_uncompressed = sum(i.file_size for i in infos)
            file_count = len(infos)

            has_android_manifest = "AndroidManifest.xml" in names
            has_resources_arsc = "resources.arsc" in names
            has_meta_inf = any(n.startswith("META-INF/") for n in names)

            # DEX files
            dex_files = sorted([n for n in names if n.startswith("classes") and n.endswith(".dex")])

            # ABIs and .so libs
            abis_set = set()
            native_libs = []
            for n in names:
                if n.startswith("lib/"):
                    # lib/<abi>/something.so
                    parts = n.split("/")
                    if len(parts) >= 3:
                        abis_set.add(parts[1])
                    if n.endswith(".so"):
                        native_libs.append(n)

            abis = sorted(abis_set)
            native_libs_sorted = sorted(native_libs)

            if len(native_libs_sorted) > max_native_list:
                native_libs_sorted = native_libs_sorted[:max_native_list]

            # Top largest entries
            largest = sorted(((i.filename, i.file_size) for i in infos), key=lambda x: x[1], reverse=True)
            top_largest = largest[:top_n]

            return ZipInfoSummary(
                file_count=file_count,
                total_uncompressed_bytes=total_uncompressed,
                has_android_manifest=has_android_manifest,
                has_resources_arsc=has_resources_arsc,
                has_meta_inf=has_meta_inf,
                dex_files=dex_files,
                abis=abis,
                native_libs=native_libs_sorted,
                top_largest=top_largest,
            )
    except zipfile.BadZipFile as e:
        raise ValueError("APK is not a valid ZIP archive or it is corrupted") from e


def try_parse_manifest_with_androguard(apk_path: Path, max_permissions: int = 200) -> ManifestInfo:
    """
    Use androguard to parse binary AndroidManifest.xml.
    Returns ManifestInfo; never raises for missing dependency, but may raise for unexpected runtime errors.
    """
    try:
        # Lazy import
        from androguard.core.bytecodes.apk import APK  # type: ignore
    except Exception:
        return ManifestInfo(
            available=False,
            error="androguard is not installed, AndroidManifest parsing skipped.",
            install_hint="Install: pip install androguard",
        )

    try:
        a = APK(str(apk_path))
        pkg = a.get_package()
        vname = a.get_androidversion_name()
        vcode = a.get_androidversion_code()

        min_sdk = a.get_min_sdk_version()
        target_sdk = a.get_target_sdk_version()

        # Debuggable: best-effort (may return None)
        debuggable = None
        try:
            # get_element returns string values sometimes
            debuggable = a.get_element("application", "debuggable")
        except Exception:
            debuggable = None

        perms = []
        try:
            perms = sorted(set(a.get_permissions() or []))
        except Exception:
            perms = []

        if len(perms) > max_permissions:
            perms = perms[:max_permissions]

        return ManifestInfo(
            available=True,
            package_name=pkg,
            version_name=vname,
            version_code=str(vcode) if vcode is not None else None,
            min_sdk=str(min_sdk) if min_sdk is not None else None,
            target_sdk=str(target_sdk) if target_sdk is not None else None,
            debuggable=str(debuggable) if debuggable is not None else None,
            permissions=perms,
        )
    except Exception as e:
        # androguard installed, but manifest parsing failed
        return ManifestInfo(
            available=False,
            error=f"Failed to parse AndroidManifest via androguard: {e}",
            install_hint="Make sure the APK is valid and androguard is up to date: pip install -U androguard",
        )


def fmt_bool(v: bool) -> str:
    return "yes" if v else "no"


def render_report(
    file_info: FileInfo,
    zip_summary: ZipInfoSummary,
    manifest_info: ManifestInfo,
    report_generated_at: datetime,
) -> str:
    lines: List[str] = []

    lines.append(f"Report generated at: {report_generated_at.strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("Environment")
    lines.append(f"  OS: {platform.platform()}")
    lines.append(f"  Python: {sys.version.split()[0]}")
    lines.append("")

    lines.append("File info")
    lines.append(f"  Name: {file_info.name}")
    lines.append(f"  Path: {file_info.path}")
    lines.append(f"  Size: {file_info.size_bytes} bytes ({file_info.size_mib} MiB)")
    lines.append(f"  Modified: {file_info.mtime_local}")
    lines.append(f"  SHA256: {file_info.sha256}")
    lines.append(f"  MD5: {file_info.md5}")
    lines.append("")

    lines.append("APK summary (AndroidManifest)")
    if manifest_info.available:
        lines.append(f"  Package name: {manifest_info.package_name or 'n/a'}")
        lines.append(f"  Version name: {manifest_info.version_name or 'n/a'}")
        lines.append(f"  Version code: {manifest_info.version_code or 'n/a'}")
        lines.append(f"  minSdkVersion: {manifest_info.min_sdk or 'n/a'}")
        lines.append(f"  targetSdkVersion: {manifest_info.target_sdk or 'n/a'}")
        lines.append(f"  Debuggable: {manifest_info.debuggable or 'n/a'}")
        if manifest_info.permissions is not None:
            lines.append(f"  Permissions count: {len(manifest_info.permissions)}")
        lines.append("")
    else:
        lines.append("  AndroidManifest info: not extracted")
        if manifest_info.error:
            lines.append(f"  Reason: {manifest_info.error}")
        if manifest_info.install_hint:
            lines.append(f"  Hint: {manifest_info.install_hint}")
        lines.append("")

    lines.append("ZIP structure")
    lines.append(f"  Files in APK: {zip_summary.file_count}")
    lines.append(f"  Total uncompressed size: {zip_summary.total_uncompressed_bytes} bytes ({human_mib(zip_summary.total_uncompressed_bytes)} MiB)")
    lines.append(f"  Has AndroidManifest.xml: {fmt_bool(zip_summary.has_android_manifest)}")
    lines.append(f"  Has resources.arsc: {fmt_bool(zip_summary.has_resources_arsc)}")
    lines.append(f"  Has META-INF signature (v1 indicator): {fmt_bool(zip_summary.has_meta_inf)}")
    lines.append(f"  DEX files count: {len(zip_summary.dex_files)}")
    if zip_summary.dex_files:
        lines.append(f"  DEX files: {', '.join(zip_summary.dex_files)}")
    lines.append("")

    lines.append("Native libraries")
    lines.append(f"  ABIs detected: {', '.join(zip_summary.abis) if zip_summary.abis else 'n/a'}")
    lines.append(f"  Native .so count (listed): {len(zip_summary.native_libs)}")
    if zip_summary.native_libs:
        for n in zip_summary.native_libs[:50]:
            lines.append(f"    {n}")
        if len(zip_summary.native_libs) > 50:
            lines.append(f"    ... shown first 50 of {len(zip_summary.native_libs)}")
    lines.append("")

    lines.append("Top largest files inside APK")
    if zip_summary.top_largest:
        for name, sz in zip_summary.top_largest:
            lines.append(f"  {sz} bytes  {name}")
    else:
        lines.append("  n/a")
    lines.append("")

    if manifest_info.available and manifest_info.permissions:
        lines.append("Permissions (listed)")
        for p in manifest_info.permissions[:100]:
            lines.append(f"  {p}")
        if len(manifest_info.permissions) > 100:
            lines.append(f"  ... shown first 100 of {len(manifest_info.permissions)}")
        lines.append("")

    lines.append("Notes")
    lines.append("  - APK is treated as a ZIP archive for structural analysis.")
    lines.append("  - AndroidManifest fields require androguard for reliable parsing (binary XML).")
    lines.append("")

    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="pokerdom.py",
        description="Generate a basic technical report for pokerdom.apk and save it as a .txt file.",
    )
    parser.add_argument("--apk", type=str, default=None, help="Path to APK file (default: ./pokerdom.apk next to script)")
    parser.add_argument("--out", type=str, default=None, help="Output report path (default: ./pokerdom_report.txt)")
    parser.add_argument("--verbose", action="store_true", help="Print extra info to console")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    script_dir = Path(__file__).resolve().parent
    apk_path = Path(args.apk).expanduser().resolve() if args.apk else (script_dir / DEFAULT_APK_NAME)
    out_path = Path(args.out).expanduser().resolve() if args.out else (script_dir / DEFAULT_REPORT_NAME)

    if not apk_path.exists():
        print(f"ERROR: APK file not found: {apk_path}")
        print("Put pokerdom.apk in the same directory as pokerdom.py or use --apk /path/to/file.apk")
        return 2

    try:
        file_info = collect_file_info(apk_path)
    except Exception as e:
        print(f"ERROR: Failed to read APK file: {e}")
        return 3

    try:
        zip_summary = collect_zip_info(apk_path)
    except ValueError as e:
        print(f"ERROR: {e}")
        return 3
    except Exception as e:
        print(f"ERROR: Failed to analyze APK as ZIP: {e}")
        return 3

    manifest_info = try_parse_manifest_with_androguard(apk_path)

    report_text = render_report(
        file_info=file_info,
        zip_summary=zip_summary,
        manifest_info=manifest_info,
        report_generated_at=datetime.now(),
    )

    try:
        out_path.write_text(report_text, encoding="utf-8")
    except Exception as e:
        print(f"ERROR: Failed to write report: {e}")
        return 3

    print(f"OK: Report saved to: {out_path}")
    if args.verbose:
        print("")
        print(report_text)

    # If androguard installed but manifest parsing failed, return code 4
    if (not manifest_info.available) and manifest_info.error and "androguard" not in (manifest_info.error.lower()):
        # e.g. "Failed to parse AndroidManifest via androguard ..."
        return 4

    return 0


if __name__ == "__main__":
    sys.exit(main())