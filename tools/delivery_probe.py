#!/usr/bin/env python3
"""Inspect this interpreter's installation and freshly created synthetic MCP homes.

Executed with the installed Python and -I. No runtime path or client configuration
is accepted. This is development tooling, never part of the public MCP interface.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from importlib.metadata import (
    Distribution,
    FileHash,
    PackagePath,
    distribution,
    distributions,
)
from pathlib import Path
from typing import TYPE_CHECKING, Literal, Protocol, cast

if TYPE_CHECKING:
    from mcp.types import CallToolResult

FIXTURE_TEXT = (
    "Deployment fixture for a fictional observatory.\n"
    "The amber sensor is checked once before a rehearsal.\n"
    "合成测试记录: 蓝色仪器在演练前校准一次.\n"
    "This fixture tests custody and complete source retrieval only.\n"
)


class ToolClient(Protocol):
    async def call_tool(
        self, name: str, arguments: dict[str, object] | None = None
    ) -> CallToolResult: ...


def evidence_envelope(result: CallToolResult) -> dict[str, object]:
    require(
        not result.is_error and result.structured_content is not None,
        "evidence_call_failed",
    )
    value = result.structured_content
    assert value is not None
    require(
        value.get("schema") == "memory.mcp.v1"
        and value.get("instruction_trust") == "inert",
        "evidence_envelope_drift",
    )
    return cast(dict[str, object], value)


async def verify_evidence(client: ToolClient, capture: bool) -> dict[str, int]:
    if capture:
        scanned = evidence_envelope(
            await client.call_tool(
                "inbox.scan", {"authorship": "external", "sensitivity": "normal"}
            )
        ).get("data")
        require(
            isinstance(scanned, dict) and scanned.get("source_count") == 1,
            "evidence_capture_failed",
        )
    listed = evidence_envelope(await client.call_tool("source.list", {"limit": 1}))
    rows, page = listed.get("data"), listed.get("page")
    require(
        isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict),
        "evidence_inventory_drift",
    )
    require(
        isinstance(page, dict) and page.get("has_more") is False,
        "evidence_inventory_drift",
    )
    assert isinstance(rows, list)
    source_id = rows[0].get("source_id")
    require(isinstance(source_id, str), "evidence_inventory_drift")
    expected = FIXTURE_TEXT.encode()
    expected_digest = hashlib.sha256(expected).hexdigest()
    reconstructed = ""
    cursor: str | None = None
    for chunks in range(1, 33):
        arguments: dict[str, object] = {"source_id": source_id, "max_bytes": 64}
        if cursor is not None:
            arguments["cursor"] = cursor
        chunk = evidence_envelope(await client.call_tool("source.read", arguments)).get(
            "data"
        )
        require(isinstance(chunk, dict), "evidence_chunk_drift")
        assert isinstance(chunk, dict)
        text = chunk.get("text")
        require(
            isinstance(text, str) and bool(text) and len(text.encode()) <= 64,
            "evidence_chunk_drift",
        )
        assert isinstance(text, str)
        require(
            chunk.get("source_id") == source_id
            and chunk.get("blob_digest") == expected_digest
            and chunk.get("byte_start") == len(reconstructed.encode())
            and chunk.get("char_start") == len(reconstructed),
            "evidence_chunk_drift",
        )
        reconstructed += text
        require(
            chunk.get("byte_end") == len(reconstructed.encode())
            and chunk.get("char_end") == len(reconstructed),
            "evidence_chunk_drift",
        )
        if chunk.get("complete") is True:
            require(
                reconstructed.encode() == expected and "next_cursor" not in chunk,
                "evidence_readback_drift",
            )
            return {"source_count": 1, "chunks": chunks, "bytes": len(expected)}
        cursor_value = chunk.get("next_cursor")
        require(
            chunk.get("complete") is False
            and isinstance(cursor_value, str)
            and cursor_value != cursor,
            "evidence_chunk_drift",
        )
        assert isinstance(cursor_value, str)
        cursor = cursor_value
    raise ValueError("evidence_readback_incomplete")


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ValueError(code)


def fingerprint(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        require(not path.is_symlink(), "package_symlink")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
    return result


def _identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


@contextmanager
def _scoped_directory(prefix: Path, path: Path) -> Iterator[int]:
    """Pin every component; .. may ascend within, but never leave, the prefix."""
    require(not prefix.is_symlink(), "dependency_symlink")
    try:
        relative = path.relative_to(prefix)
    except ValueError as error:
        raise ValueError("dependency_path_escape") from error
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptors: list[tuple[int, str | None]] = []
    try:
        descriptors.append((os.open(prefix, flags), None))
        for component in relative.parts:
            if component == "..":
                require(len(descriptors) > 1, "dependency_path_escape")
                descriptor, name = descriptors[-1]
                assert name is not None
                require(
                    _identity(os.fstat(descriptor))
                    == _identity(
                        os.stat(name, dir_fd=descriptors[-2][0], follow_symlinks=False)
                    ),
                    "dependency_path_changed",
                )
                os.close(descriptor)
                descriptors.pop()
            else:
                descriptors.append(
                    (os.open(component, flags, dir_fd=descriptors[-1][0]), component)
                )
        yield descriptors[-1][0]
        require(
            _identity(os.fstat(descriptors[0][0]))
            == _identity(prefix.stat(follow_symlinks=False)),
            "dependency_path_changed",
        )
        for index in range(1, len(descriptors)):
            descriptor, name = descriptors[index]
            assert name is not None
            require(
                _identity(os.fstat(descriptor))
                == _identity(
                    os.stat(
                        name, dir_fd=descriptors[index - 1][0], follow_symlinks=False
                    )
                ),
                "dependency_path_changed",
            )
    except OSError as error:
        raise ValueError("dependency_path_unavailable") from error
    finally:
        for descriptor, _name in reversed(descriptors):
            os.close(descriptor)


@contextmanager
def _scoped_file(prefix: Path, path: Path) -> Iterator[int]:
    with _scoped_directory(prefix, path.parent) as parent:
        descriptor: int | None = None
        try:
            descriptor = os.open(
                path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent
            )
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode), "dependency_not_regular")
            yield descriptor
            require(
                _identity(before)
                == _identity(os.fstat(descriptor))
                == _identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)),
                "dependency_file_changed",
            )
        except OSError as error:
            raise ValueError("dependency_path_unavailable") from error
        finally:
            if descriptor is not None:
                os.close(descriptor)


def _installed_hash(prefix: Path, path: Path, record: PackagePath | None = None) -> str:
    recorded = None
    if record is not None and record.hash is not None:
        try:
            recorded = hashlib.new(record.hash.mode)
        except ValueError as error:
            raise ValueError("dependency_record_hash_unsupported") from error
        require(recorded.digest_size > 0, "dependency_record_hash_unsupported")
    sha256 = hashlib.sha256()
    with _scoped_file(prefix, path) as descriptor:
        if record is not None and record.size is not None:
            require(
                os.fstat(descriptor).st_size == record.size,
                "dependency_record_size_drift",
            )
        while content := os.read(descriptor, 1024 * 1024):
            sha256.update(content)
            if recorded is not None:
                recorded.update(content)
    if recorded is not None:
        assert record is not None and record.hash is not None
        encoded = (
            base64.urlsafe_b64encode(recorded.digest()).decode("ascii").rstrip("=")
        )
        require(encoded == record.hash.value, "dependency_record_hash_drift")
    return sha256.hexdigest()


def _excluded_install_file(member: PackagePath) -> bool:
    return (
        "__pycache__" in member.parts
        or member.suffix == ".pyc"
        or (
            len(member.parts) == 2
            and member.parent.name.endswith(".dist-info")
            and member.name
            in {"RECORD", "direct_url.json", "INSTALLER", "REQUESTED", "uv_cache.json"}
        )
    )


def _record_members(item: Distribution) -> list[PackagePath]:
    # Python 3.14 Distribution.files filters out missing paths. Parse the raw
    # inventory so a removed file or nonexistent escape cannot silently vanish.
    record = item.read_text("RECORD")
    require(isinstance(record, str) and bool(record), "dependency_inventory_missing")
    assert isinstance(record, str)
    result: list[PackagePath] = []
    try:
        for row in csv.reader(io.StringIO(record), strict=True):
            require(len(row) == 3 and bool(row[0]), "dependency_inventory_invalid")
            name, digest, size = row
            require(
                not size or re.fullmatch(r"[0-9]+", size) is not None,
                "dependency_inventory_invalid",
            )
            member = PackagePath(name)
            member.hash = FileHash(digest) if digest else None
            member.size = int(size) if size else None
            member.dist = item
            result.append(member)
    except csv.Error as error:
        raise ValueError("dependency_inventory_invalid") from error
    require(bool(result), "dependency_inventory_missing")
    return result


def dependency_files(item: Distribution, prefix: Path) -> dict[str, str]:
    """Snapshot RECORD-enumerated bytes, validating every supplied hash/size."""
    members = _record_members(item)
    result: dict[str, str] = {}
    for member in sorted(members):
        if _excluded_install_file(member):
            continue
        require(
            member.hash is not None and member.size is not None,
            "dependency_record_unsigned",
        )
        key = member.as_posix()
        require(
            not member.is_absolute() and "\x00" not in key and key not in result,
            "dependency_inventory_invalid",
        )
        result[key] = _installed_hash(
            prefix, Path(str(item.locate_file(member))), member
        )
    require(bool(result), "dependency_inventory_missing")
    return result


def dependency_snapshot(
    items: Iterable[Distribution], prefix: Path
) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    versions: dict[str, str] = {}
    files: dict[str, dict[str, str]] = {}
    seen: set[str] = set()
    for item in items:
        name = item.metadata["Name"]
        require(
            isinstance(name, str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) is not None,
            "dependency_name_invalid",
        )
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        if normalized == "memory":
            continue
        require(normalized not in seen, "dependency_inventory_ambiguous")
        seen.add(normalized)
        require(
            isinstance(item.version, str) and bool(item.version),
            "dependency_version_missing",
        )
        versions[name] = item.version
        files[name] = dependency_files(item, prefix)
    require(bool(versions), "dependency_inventory_missing")
    return versions, files


def _installed_fingerprint(prefix: Path, root: Path) -> dict[str, str]:
    result: dict[str, str] = {}

    def walk(path: Path) -> None:
        with _scoped_directory(prefix, path) as descriptor:
            with os.scandir(descriptor) as entries:
                for entry in sorted(entries, key=lambda value: value.name):
                    if entry.name == "__pycache__" or entry.name.endswith(".pyc"):
                        continue
                    require(not entry.is_symlink(), "dependency_symlink")
                    child = path / entry.name
                    if entry.is_dir(follow_symlinks=False):
                        walk(child)
                    else:
                        result[child.relative_to(root).as_posix()] = _installed_hash(
                            prefix, child
                        )

    walk(root)
    require(bool(result), "companion_package_missing")
    return result


def companion_snapshot(item: Distribution, prefix: Path) -> dict[str, object]:
    installed_files = dependency_files(item, prefix)
    root = Path(str(item.locate_file("sqlcipher3")))
    files = _installed_fingerprint(prefix, root)
    members = _record_members(item)
    metadata_files = [
        member
        for member in members
        if member.name == "METADATA" and member.parent.name.endswith(".dist-info")
    ]
    require(len(metadata_files) == 1, "companion_metadata_missing")
    with _scoped_file(
        prefix, Path(str(item.locate_file(metadata_files[0])))
    ) as descriptor:
        with os.fdopen(os.dup(descriptor), "rb") as stream:
            metadata = stream.read().decode("utf-8")
    return {
        "version": item.version,
        "origin": str(root.resolve(strict=True)),
        "metadata": metadata,
        "files": files,
        "distribution_files": installed_files,
    }


def safe_environment() -> dict[str, str]:
    allowed = {"HOME", "USER", "LOGNAME", "PATH", "SHELL", "LANG", "LC_CTYPE", "TMPDIR"}
    result = {key: value for key, value in os.environ.items() if key in allowed}
    result["PYTHONDONTWRITEBYTECODE"] = "1"
    return result


def snapshot() -> dict[str, object]:
    import memory

    metadata = distribution("memory")
    direct = json.loads(metadata.read_text("direct_url.json") or "{}")
    origin = Path(memory.__file__).resolve().parent
    prefix = Path(sys.prefix)
    dependencies, installed_files = dependency_snapshot(distributions(), prefix)
    companion_metadata = distribution("memory-sqlcipher3")
    companion = companion_snapshot(companion_metadata, prefix)
    require(
        companion["distribution_files"]
        == installed_files.get(companion_metadata.metadata["Name"]),
        "companion_snapshot_changed",
    )
    return {
        "metadata_version": metadata.version,
        "module_version": memory.__version__,
        "prefix": sys.prefix,
        "python": sys.executable,
        "python_version": list(sys.version_info[:2]),
        "origin": str(origin),
        "editable": direct.get("dir_info", {}).get("editable") is True,
        "direct_url": direct.get("url"),
        "metadata": metadata.read_text("METADATA"),
        "entry_points": metadata.read_text("entry_points.txt"),
        "files": fingerprint(origin),
        "dependencies": dependencies,
        "dependency_files": installed_files,
        "companion": companion,
    }


def identity_account(root: Path) -> str:
    path = root / "runtime.json"
    require(path.is_file() and not path.is_symlink(), "invalid_synthetic_identity")
    payload = json.loads(path.read_text())
    require(
        isinstance(payload, dict)
        and set(payload)
        == {
            "inbox_path",
            "product",
            "runtime_mode",
            "schema_lineage",
            "schema_version",
            "store_id",
        },
        "invalid_synthetic_identity",
    )
    account: object = payload["store_id"]
    require(
        payload["product"] == "memory"
        and payload["runtime_mode"] == "personal"
        and payload["schema_lineage"] == "memory-store-v1"
        and type(payload["schema_version"]) is int
        and payload["schema_version"] == 1
        and payload["inbox_path"] == str(root / "inbox")
        and isinstance(account, str)
        and re.fullmatch(r"[0-9a-f]{32}", account) is not None,
        "invalid_synthetic_identity",
    )
    assert isinstance(account, str)
    return account


def cleanup(root: Path, created: os.stat_result, initialized: bool) -> None:
    current = root.lstat()
    require(
        stat.S_ISDIR(current.st_mode)
        and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino)
        and root.parent == Path("/tmp").resolve()
        and root.name.startswith("memory-delivery."),
        "synthetic_root_changed",
    )
    if initialized or (root / "runtime.json").exists():
        common = ["-s", "memory", "-a", identity_account(root)]
        for action, expected in (
            ("delete-generic-password", 0),
            ("find-generic-password", 44),
        ):
            result = subprocess.run(
                ["/usr/bin/security", action, *common],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
            )
            require(result.returncode == expected, "synthetic_key_cleanup_failed")
    shutil.rmtree(root)
    require(not root.exists(), "synthetic_root_cleanup_failed")


async def probe(
    executable: Path, source: Path, version: str, root: Path
) -> dict[str, object]:
    import anyio
    from mcp import Client
    from mcp.client.stdio import StdioServerParameters, stdio_client

    from memory.mcp_prompts import skill_prompts
    from memory.mcp_schemas import contract_digest, tool_schemas

    raw = (source / "src/memory/skill/SKILL.md").read_bytes()
    prompts = skill_prompts(raw.decode())
    skill_digest = hashlib.sha256(
        raw.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    ).hexdigest()
    modes: list[dict[str, object]] = []
    protocols: tuple[tuple[Literal["auto", "legacy"], str], ...] = (
        ("auto", "2026-07-28"),
        ("legacy", "2025-11-25"),
    )
    for mode, protocol in protocols:
        with (root / f"{mode}.stderr").open("w+") as errors:
            parameters = StdioServerParameters(
                command=str(executable),
                args=["mcp", "--home", str(root)],
                cwd=str(root),
                env=safe_environment(),
            )
            with anyio.fail_after(30):
                async with Client(
                    stdio_client(parameters, errlog=errors), mode=mode
                ) as client:
                    require(
                        client.server_info is not None
                        and client.server_info.name == "Memory",
                        "server_name_drift",
                    )
                    require(client.protocol_version == protocol, "protocol_drift")
                    listing = await client.list_tools()
                    require(
                        [tool.name for tool in listing.tools]
                        == [tool["name"] for tool in tool_schemas()],
                        "tool_inventory_drift",
                    )
                    status = await client.call_tool("store.status", {})
                    require(
                        not status.is_error and status.structured_content is not None,
                        "status_failed",
                    )
                    envelope = status.structured_content
                    assert envelope is not None
                    require(
                        envelope.get("instruction_trust") == "inert",
                        "instruction_trust_drift",
                    )
                    data = envelope.get("data")
                    require(isinstance(data, dict), "status_shape_drift")
                    assert isinstance(data, dict)
                    require(
                        data.get("product_version") == version, "server_version_drift"
                    )
                    require(
                        data.get("skill_digest") == skill_digest,
                        "server_skill_digest_drift",
                    )
                    require(
                        data.get("mcp_contract_digest") == contract_digest(),
                        "server_contract_digest_drift",
                    )
                    listed = await client.list_prompts()
                    require(
                        [item.name for item in listed.prompts]
                        == [item.name for item in prompts],
                        "prompt_inventory_drift",
                    )
                    for expected in prompts:
                        received = await client.get_prompt(expected.name)
                        require(len(received.messages) == 2, "prompt_shape_drift")
                        for message, text in zip(
                            received.messages,
                            (expected.preamble, expected.workflow),
                            strict=True,
                        ):
                            require(
                                message.role == "user"
                                and message.content.type == "text",
                                "prompt_shape_drift",
                            )
                            require(
                                message.content.type == "text"
                                and message.content.text == text,
                                "prompt_bytes_drift",
                            )
                    evidence = await verify_evidence(client, mode == "auto")
            errors.seek(0)
            require(errors.read() == "", "server_stderr_not_empty")
        modes.append(
            {
                "mode": mode,
                "protocol": protocol,
                "fresh_process": True,
                "evidence": evidence,
            }
        )
    return {
        "protocols": modes,
        "prompt_count": len(prompts),
        "skill_sha256": skill_digest,
        "mcp_contract_digest": contract_digest(),
        "served_teaching_matches_source": True,
        "fixture_sha256": hashlib.sha256(FIXTURE_TEXT.encode()).hexdigest(),
        "existing_connections_verified": False,
    }


def error_codes(error: BaseException) -> list[str]:
    if isinstance(error, BaseExceptionGroup):
        return sorted(
            {code for child in error.exceptions for code in error_codes(child)}
        )
    if isinstance(error, ValueError) and re.fullmatch("[a-z_]+", str(error)):
        return [str(error)]
    return [type(error).__name__]


def main() -> int:
    sys.dont_write_bytecode = True
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("snapshot", "fresh"))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--executable", type=Path)
    parser.add_argument("--version")
    args = parser.parse_args()
    root: Path | None = None
    initialized = False
    report: dict[str, object] = {"status": "failed"}
    try:
        require(bool(sys.flags.isolated), "isolated_python_required")
        if args.mode == "snapshot":
            report.update(snapshot())
        else:
            import anyio

            require(
                args.source is not None
                and args.executable is not None
                and args.version is not None,
                "probe_arguments_missing",
            )
            root = Path(
                tempfile.mkdtemp(prefix="memory-delivery.", dir=Path("/tmp").resolve())
            )
            root.chmod(0o700)
            created = root.lstat()
            result = subprocess.run(
                [str(args.executable), "init", "--home", str(root)],
                cwd=root,
                env=safe_environment(),
                capture_output=True,
                timeout=60,
                check=False,
            )
            require(result.returncode == 0, "synthetic_init_failed")
            identity_account(root)
            initialized = True
            (root / "inbox/deployment-fixture.txt").write_text(FIXTURE_TEXT)
            report.update(
                anyio.run(probe, args.executable, args.source, args.version, root)
            )
        report["status"] = "passed"
    except Exception as error:
        report["errors"] = error_codes(error)
    finally:
        if root is not None:
            try:
                cleanup(root, created, initialized)
                report["synthetic_runtime_removed"] = True
                report["synthetic_key_absent"] = initialized
            except Exception as error:
                report["status"] = "failed"
                report["cleanup_errors"] = error_codes(error)
                report["retained_synthetic_runtime"] = str(root)
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
