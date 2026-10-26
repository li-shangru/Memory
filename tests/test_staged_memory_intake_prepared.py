"""Exact Prepared parsing and body-free promotion manifest tests."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import cast

import pytest
from staged_memory_intake.model import (
    DirectoryIdentity,
    IntakeConfig,
    IntakeError,
    MemoryMetadata,
)
from staged_memory_intake.prepared import (
    build_preview,
    parse_guard_spec,
    parse_prepared,
    preview_json,
)
from staged_memory_intake.securefs import directory_identity


def _prepared_bytes(
    source_name: str,
    staged_bytes: bytes,
    statement: str,
    *,
    kind: str = "fact",
    sensitivity: str = "normal",
    occurred_on: str = "",
    valid_from: str = "",
    valid_to: str = "",
    tags: str = '["synthetic","fixture"]',
    terminal_lf: bool = True,
) -> bytes:
    body = (
        "---\n"
        "memory_intake_version: 1\n"
        f"source_note: {source_name}\n"
        f"source_sha256: {hashlib.sha256(staged_bytes).hexdigest()}\n"
        f"kind: {kind}\n"
        f"sensitivity: {sensitivity}\n"
        f"occurred_on: {occurred_on}\n"
        f"valid_from: {valid_from}\n"
        f"valid_to: {valid_to}\n"
        f"tags: {tags}\n"
        "---\n"
        f"{statement}"
    )
    if terminal_lf:
        body += "\n"
    return body.encode("utf-8")


def _assert_error(
    prepared_name: str,
    prepared_bytes: bytes,
    staged_bytes: bytes,
    code: str = "invalid_prepared",
) -> None:
    with pytest.raises(IntakeError) as caught:
        parse_prepared(prepared_name, prepared_bytes, staged_bytes)
    assert caught.value.code == code
    assert caught.value.category == "state"


@pytest.mark.parametrize("terminal_lf", [False, True])
def test_exact_statement_and_hashes_preserve_internal_bytes(
    terminal_lf: bool,
) -> None:
    statement = "First paragraph.\n\nSecond paragraph."
    staged_bytes = b"Synthetic source binding only."
    prepared_bytes = _prepared_bytes(
        "source.md",
        staged_bytes,
        statement,
        terminal_lf=terminal_lf,
    )

    parsed = parse_prepared("candidate.md", prepared_bytes, staged_bytes)

    assert parsed.statement == "First paragraph.\n\nSecond paragraph."
    assert parsed.statement_utf8_bytes == len(parsed.statement.encode("utf-8"))
    assert parsed.source_sha256 == hashlib.sha256(staged_bytes).hexdigest()
    assert parsed.prepared_sha256 == hashlib.sha256(prepared_bytes).hexdigest()
    assert parsed.evidence_excerpt == statement
    prepared_text = prepared_bytes.decode()
    assert prepared_text.count(parsed.evidence_excerpt) == 1
    assert (
        prepared_text[parsed.evidence_char_start : parsed.evidence_char_end]
        == parsed.evidence_excerpt
    )
    assert parsed.evidence_char_start == prepared_text.index("---\n", 4) + 4
    assert parsed.evidence_sha256 == hashlib.sha256(statement.encode()).hexdigest()
    assert parsed.requested_metadata == MemoryMetadata(
        kind="fact",
        sensitivity="normal",
        occurred_on=None,
        valid_from=None,
        valid_to=None,
        tags=("synthetic", "fixture"),
    )


@pytest.mark.parametrize(
    ("source_name", "statement"),
    [
        ("合成-温室.md", "合成记录：溪桐说：“保留原文。”"),
        ("synthetic-δοκιμή.md", "Synthetic quotation: «Κρατήστε το κείμενο.»"),
        (
            "synthetic-تجربة.md",
            "Synthetic mixed note: «احتفظ بالنص»; 原文 stays unchanged.",
        ),
    ],
)
def test_multilingual_preview_preserves_names_quotes_and_evidence(
    tmp_path: Path, source_name: str, statement: str
) -> None:
    """The transport preserves authored text; it does not select a language."""
    notes_root = tmp_path / "synthetic-notes"
    notes_root.mkdir(mode=0o700)
    staged_root = notes_root / "02_Staged"
    prepared_root = notes_root / "03_Prepared"
    inbox = tmp_path / "synthetic-inbox"
    for path in (staged_root, prepared_root, inbox):
        path.mkdir(mode=0o700)
    staged = statement.encode("utf-8")
    prepared = _prepared_bytes(source_name, staged, statement)
    (staged_root / source_name).write_bytes(staged)
    (prepared_root / source_name).write_bytes(prepared)
    config = IntakeConfig(
        notes_root=notes_root,
        notes_identity=directory_identity(notes_root),
        memory_home=None,
        memory_inbox=inbox,
        inbox_identity=directory_identity(inbox),
    )

    preview = build_preview(config, [source_name], [])
    (candidate,) = preview.candidates
    parsed = candidate.parsed
    assert parsed.source_name == source_name
    assert parsed.source_sha256 == hashlib.sha256(staged).hexdigest()
    assert parsed.prepared_sha256 == hashlib.sha256(prepared).hexdigest()
    assert parsed.statement == parsed.evidence_excerpt == statement
    assert parsed.statement_utf8_bytes == len(staged)
    assert (
        prepared.decode()[parsed.evidence_char_start : parsed.evidence_char_end]
        == statement
    )
    assert parsed.evidence_sha256 == hashlib.sha256(staged).hexdigest()
    assert preview.manifest_digest


@pytest.mark.parametrize(
    "mutate",
    [
        lambda raw: raw + b"\n",
        lambda raw: b"\xef\xbb\xbf" + raw,
        lambda raw: raw.replace(b"\n", b"\r\n"),
        lambda raw: raw.replace(b"\n", b"\r", 1),
        lambda raw: raw.replace(b"First", b"First\0", 1),
        lambda raw: b"\xff" + raw,
    ],
    ids=["two-terminal-lfs", "bom", "crlf", "cr", "nul", "invalid-utf8"],
)
def test_prepared_encoding_and_terminal_shape_are_exact(
    mutate: Callable[[bytes], bytes],
) -> None:
    staged = b"First synthetic statement."
    valid = _prepared_bytes("source.md", staged, staged.decode())
    _assert_error("candidate.md", mutate(valid), staged)


@pytest.mark.parametrize(
    "statement",
    ["", " leading", "trailing ", "\tleading", "trailing\t"],
)
def test_statement_must_be_nonempty_and_trim_stable(statement: str) -> None:
    staged = statement.encode()
    _assert_error(
        "candidate.md", _prepared_bytes("source.md", staged, statement), staged
    )


@pytest.mark.parametrize(
    "replace",
    [
        ("memory_intake_version: 1\n", "memory_intake_version: 1\nkind: fact\n"),
        ("kind: fact\n", "unexpected: value\n"),
        (
            "source_note: source.md\n",
            "source_note: source.md\nsource_note: source.md\n",
        ),
        ("kind: fact\n", "sensitivity: normal\nkind: fact\n"),
    ],
    ids=["duplicate-key", "unknown-key", "duplicate-source-note", "wrong-order"],
)
def test_front_matter_requires_each_known_key_once_in_order(
    replace: tuple[str, str],
) -> None:
    staged = b"Synthetic statement."
    raw = _prepared_bytes("source.md", staged, staged.decode()).decode()
    invalid = raw.replace(*replace).encode()

    _assert_error("candidate.md", invalid, staged)


@pytest.mark.parametrize(
    "tags",
    [
        '"not-an-array"',
        '["valid",1]',
        '["duplicate","duplicate"]',
        '[" leading"]',
        '["trailing "]',
        '[""]',
        '["not", "compact"]',
    ],
)
def test_tags_are_compact_trim_stable_unique_nonempty_strings(tags: str) -> None:
    staged = b"Synthetic statement."
    _assert_error(
        "candidate.md",
        _prepared_bytes("source.md", staged, staged.decode(), tags=tags),
        staged,
    )


def test_tag_count_and_utf8_byte_limits_are_exact() -> None:
    staged = b"Synthetic statement."
    sixty_four = json.dumps(
        [f"tag-{index}" for index in range(64)], separators=(",", ":")
    )
    assert (
        parse_prepared(
            "candidate.md",
            _prepared_bytes("source.md", staged, staged.decode(), tags=sixty_four),
            staged,
        ).requested_metadata.tags[-1]
        == "tag-63"
    )
    sixty_five = json.dumps(
        [f"tag-{index}" for index in range(65)], separators=(",", ":")
    )
    _assert_error(
        "candidate.md",
        _prepared_bytes("source.md", staged, staged.decode(), tags=sixty_five),
        staged,
    )
    tag_256 = "界" * 85 + "x"
    assert len(tag_256.encode()) == 256
    assert parse_prepared(
        "candidate.md",
        _prepared_bytes(
            "source.md",
            staged,
            staged.decode(),
            tags=json.dumps([tag_256], ensure_ascii=False, separators=(",", ":")),
        ),
        staged,
    ).requested_metadata.tags == (tag_256,)
    tag_257 = tag_256 + "y"
    _assert_error(
        "candidate.md",
        _prepared_bytes(
            "source.md",
            staged,
            staged.decode(),
            tags=json.dumps([tag_257], ensure_ascii=False, separators=(",", ":")),
        ),
        staged,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("kind", "observation"),
        ("sensitivity", "private"),
        ("occurred_on", "2026-02-30"),
        ("occurred_on", "26"),
        ("valid_from", "2026-13"),
        ("valid_to", "2026-01-01T12:00:00"),
    ],
)
def test_metadata_enums_and_partial_dates_are_validated(
    field: str,
    value: str,
) -> None:
    staged = b"Synthetic statement."
    originals = {
        "kind": "fact",
        "sensitivity": "normal",
        "occurred_on": "",
        "valid_from": "",
        "valid_to": "",
    }
    valid = _prepared_bytes("source.md", staged, staged.decode()).decode()
    invalid = valid.replace(
        f"{field}: {originals[field]}\n",
        f"{field}: {value}\n",
    ).encode()
    _assert_error(
        "candidate.md",
        invalid,
        staged,
    )


def test_reversed_validity_interval_is_rejected() -> None:
    staged = b"Synthetic statement."
    _assert_error(
        "candidate.md",
        _prepared_bytes(
            "source.md",
            staged,
            staged.decode(),
            valid_from="2026-02",
            valid_to="2025-12-31",
        ),
        staged,
    )


@pytest.mark.parametrize(
    ("prepared_name", "source_name"),
    [
        ("candidate.txt", "source.md"),
        ("candidate.md", "/absolute.md"),
        ("candidate.md", "nested/source.md"),
        ("candidate.md", "source.txt"),
    ],
)
def test_candidate_and_source_are_root_level_markdown_names(
    prepared_name: str,
    source_name: str,
) -> None:
    staged = b"Synthetic statement."
    _assert_error(
        prepared_name,
        _prepared_bytes(source_name, staged, staged.decode()),
        staged,
    )


def test_staged_hash_mismatch_is_rejected() -> None:
    declared = b"Declared synthetic note."
    actual = b"Changed synthetic note."
    _assert_error(
        "candidate.md",
        _prepared_bytes("source.md", declared, "Declared synthetic note."),
        actual,
        "source_hash_mismatch",
    )


def _boundary_statement(*, multibyte: bool) -> str:
    prefix = "Unique synthetic boundary marker.\n\n"
    if not multibyte:
        return prefix + "a" * (16_384 - len(prefix.encode()))
    remaining = 16_384 - len(prefix.encode())
    return prefix + "界" * (remaining // 3) + "x" * (remaining % 3)


@pytest.mark.parametrize("multibyte", [False, True])
def test_16384_byte_statement_remains_one_deterministic_candidate(
    tmp_path: Path,
    multibyte: bool,
) -> None:
    statement = _boundary_statement(multibyte=multibyte)
    staged = statement.encode()
    prepared = _prepared_bytes("source.md", staged, statement)
    assert len(staged) == 16_384

    first = parse_prepared("candidate.md", prepared, staged)
    second = parse_prepared("candidate.md", prepared, staged)

    assert first == second
    assert first.statement_utf8_bytes == 16_384
    assert len(first.evidence_excerpt.encode()) <= 4_096
    config, prepared_root, staged_root, _ = _configured_roots(tmp_path)
    (prepared_root / "candidate.md").write_bytes(prepared)
    (staged_root / "source.md").write_bytes(staged)
    first_preview = build_preview(config, ["candidate.md"], [])
    second_preview = build_preview(config, ["candidate.md"], [])
    assert len(first_preview.candidates) == 1
    assert first_preview.candidates[0].client_item_id == (
        second_preview.candidates[0].client_item_id
    )


def test_16385_byte_statement_is_rejected_without_splitting() -> None:
    statement = "x" * 16_385
    staged = statement.encode()
    _assert_error(
        "candidate.md",
        _prepared_bytes("source.md", staged, statement),
        staged,
        "statement_too_large",
    )


def test_long_evidence_uses_first_unique_maximum_byte_bounded_window() -> None:
    statement = "x" * 4_097 + "界" + "Unique suffix."
    staged = b"Synthetic source binding without candidate evidence."
    prepared_bytes = _prepared_bytes("source.md", staged, statement)
    parsed = parse_prepared(
        "candidate.md",
        prepared_bytes,
        staged,
    )

    prepared_text = prepared_bytes.decode()
    assert len(parsed.evidence_excerpt.encode()) <= 4_096
    assert parsed.evidence_excerpt == "x" * 4_093 + "界"
    assert prepared_text.count(parsed.evidence_excerpt) == 1
    assert parsed.evidence_char_start == prepared_text.index(statement) + 4
    assert parsed.evidence_char_end == parsed.evidence_char_start + len(
        parsed.evidence_excerpt
    )
    assert (
        prepared_text[parsed.evidence_char_start : parsed.evidence_char_end]
        == parsed.evidence_excerpt
    )


def test_evidence_uniqueness_uses_prepared_text_not_staged_text() -> None:
    short = "Repeated synthetic statement."
    staged_short = f"{short}\n{short}".encode()
    prepared_short = _prepared_bytes("source.md", staged_short, short)
    parsed = parse_prepared("candidate.md", prepared_short, staged_short)
    prepared_text = prepared_short.decode()

    assert prepared_text.count(parsed.evidence_excerpt) == 1
    assert (
        prepared_text[parsed.evidence_char_start : parsed.evidence_char_end]
        == parsed.evidence_excerpt
    )
    assert parsed.evidence_char_start == prepared_text.index(short)

    duplicated_in_prepared = "Header duplicate"
    staged_unique = duplicated_in_prepared.encode()
    _assert_error(
        "candidate.md",
        _prepared_bytes(
            "source.md",
            staged_unique,
            duplicated_in_prepared,
            tags='["Header duplicate"]',
        ),
        staged_unique,
        "evidence_not_unique",
    )


def test_repeated_maximum_prepared_window_has_no_shorter_fallback() -> None:
    long = "x" * 5_000
    staged_long = b"Synthetic source binding only."
    _assert_error(
        "candidate.md",
        _prepared_bytes("source.md", staged_long, long),
        staged_long,
        "evidence_not_unique",
    )


def _guard_raw(
    guard_key: str,
    guard_value: str,
    governed_key: str,
    governed_value: str,
) -> str:
    return json.dumps(
        {
            "guard": {guard_key: guard_value},
            "governed": {governed_key: governed_value},
        },
        separators=(",", ":"),
    )


def test_guard_spec_accepts_selected_and_existing_typed_endpoints() -> None:
    selected = {"constraint.md", "claim.md"}
    selected_pair = parse_guard_spec(
        _guard_raw(
            "prepared_name",
            "constraint.md",
            "prepared_name",
            "claim.md",
        ),
        selected,
    )
    existing_pair = parse_guard_spec(
        '{ "governed": {"lineage_id": "lin_synthetic_existing"}, '
        '"guard": {"prepared_name": "constraint.md"} }',
        selected,
    )
    reverse_existing_pair = parse_guard_spec(
        '{"guard":{"lineage_id":"lin_synthetic_existing"},'
        '"governed":{"prepared_name":"claim.md"}}',
        selected,
    )

    assert selected_pair.guard.prepared_name == "constraint.md"
    assert selected_pair.governed.prepared_name == "claim.md"
    assert existing_pair.guard.prepared_name == "constraint.md"
    assert existing_pair.governed.lineage_id == "lin_synthetic_existing"
    assert reverse_existing_pair.guard.lineage_id == "lin_synthetic_existing"
    assert reverse_existing_pair.governed.prepared_name == "claim.md"


@pytest.mark.parametrize(
    "raw",
    [
        "not-json",
        "[]",
        "null",
        '{"guard":{"prepared_name":"constraint.md"}}',
        '{"guard":{"prepared_name":"constraint.md"},"governed":'
        '{"prepared_name":"claim.md"},"extra":{}}',
        '{"guard":{"prepared_name":"constraint.md","lineage_id":"lin_x"},'
        '"governed":{"prepared_name":"claim.md"}}',
        '{"guard":{},"governed":{"prepared_name":"claim.md"}}',
        '{"guard":{"prepared_name":"missing.md"},"governed":'
        '{"prepared_name":"claim.md"}}',
        '{"guard":{"lineage_id":" lin_x"},"governed":{"prepared_name":"claim.md"}}',
        '{"guard":{"lineage_id":"lin_x\u0000"},"governed":'
        '{"prepared_name":"claim.md"}}',
        '{"guard":{"prepared_name":"constraint.md"},"governed":'
        '{"prepared_name":"constraint.md"}}',
        '{"guard":{"lineage_id":"lin_x"},"governed":{"lineage_id":"lin_x"}}',
        '{"guard":{"lineage_id":"lin_guard"},"governed":{"lineage_id":"lin_governed"}}',
        '{"guard":{"prepared_name":"constraint.md"},"guard":'
        '{"prepared_name":"claim.md"},"governed":{"lineage_id":"lin_x"}}',
        '{"guard":{"prepared_name":"constraint.md","prepared_name":"claim.md"},'
        '"governed":{"lineage_id":"lin_x"}}',
    ],
)
def test_guard_spec_rejects_malformed_unselected_or_self_endpoints(raw: str) -> None:
    with pytest.raises(IntakeError) as caught:
        parse_guard_spec(raw, {"constraint.md", "claim.md"})
    assert caught.value.code == "invalid_guard_spec"


def _configured_roots(tmp_path: Path) -> tuple[IntakeConfig, Path, Path, Path]:
    notes = tmp_path / "synthetic-notes"
    prepared = notes / "03_Prepared"
    staged = notes / "02_Staged"
    inbox = tmp_path / "synthetic-inbox"
    for path in (notes, prepared, staged, inbox):
        path.mkdir(mode=0o700)
    config = IntakeConfig(
        notes_root=notes,
        notes_identity=directory_identity(notes),
        memory_home=None,
        memory_inbox=inbox,
        inbox_identity=directory_identity(inbox),
    )
    return config, prepared, staged, inbox


def _write_candidate(
    prepared_root: Path,
    staged_root: Path,
    prepared_name: str,
    *,
    sensitivity: str = "normal",
    statement: str | None = None,
) -> None:
    source_name = prepared_name.removesuffix(".md") + "-source.md"
    text = statement or f"Synthetic statement for {prepared_name}."
    staged_bytes = text.encode()
    (staged_root / source_name).write_bytes(staged_bytes)
    (prepared_root / prepared_name).write_bytes(
        _prepared_bytes(
            source_name,
            staged_bytes,
            text,
            sensitivity=sensitivity,
        )
    )


def test_build_preview_preserves_order_and_elevates_batch_sensitivity(
    tmp_path: Path,
) -> None:
    config, prepared, staged, _ = _configured_roots(tmp_path)
    _write_candidate(prepared, staged, "normal.md", sensitivity="normal")
    _write_candidate(prepared, staged, "sensitive.md", sensitivity="sensitive")
    _write_candidate(prepared, staged, "restricted.md", sensitivity="restricted")
    guards = [
        _guard_raw("prepared_name", "normal.md", "prepared_name", "sensitive.md"),
        _guard_raw(
            "prepared_name",
            "restricted.md",
            "lineage_id",
            "lin_synthetic_existing",
        ),
    ]

    preview = build_preview(
        config,
        ["sensitive.md", "normal.md", "restricted.md"],
        guards,
    )
    rendered = preview_json(preview)
    rendered_candidates = cast(list[dict[str, object]], rendered["candidates"])
    rendered_candidate = rendered_candidates[0]
    assert tuple(candidate.ordinal for candidate in preview.candidates) == (0, 1, 2)
    assert tuple(
        candidate.parsed.prepared_name for candidate in preview.candidates
    ) == ("sensitive.md", "normal.md", "restricted.md")
    assert [
        candidate.parsed.requested_metadata.sensitivity
        for candidate in preview.candidates
    ] == ["sensitive", "normal", "restricted"]
    assert {
        candidate.final_metadata.sensitivity for candidate in preview.candidates
    } == {"restricted"}
    assert preview.batch_sensitivity == "restricted"
    assert len(preview.guard_links) == 2
    assert set(rendered_candidate) == {
        "ordinal",
        "prepared_name",
        "source_name",
        "prepared_sha256",
        "source_sha256",
        "requested_sensitivity",
        "verbatim_statement",
    }
    assert rendered_candidate["requested_sensitivity"] == "sensitive"
    assert rendered_candidate["verbatim_statement"] is True
    rendered_line = json.dumps(rendered, ensure_ascii=False)
    assert "Synthetic statement for sensitive.md." not in rendered_line
    assert '"statement"' not in rendered_line
    assert "evidence" not in rendered_line
    assert "tags" not in rendered_line
    assert rendered["candidate_count"] == 3
    assert rendered["guard_link_count"] == 2


def test_parse_prepared_marks_only_unchanged_statements_verbatim() -> None:
    staged_bytes = b"Synthetic staged wording.\n"

    verbatim = parse_prepared(
        "verbatim.md",
        _prepared_bytes("note.md", staged_bytes, "Synthetic staged wording."),
        staged_bytes,
    )
    rewritten = parse_prepared(
        "rewritten.md",
        _prepared_bytes(
            "note.md",
            staged_bytes,
            "A synthetic rewrite of the staged wording.",
        ),
        staged_bytes,
    )
    undecodable_bytes = b"\xff\xfe synthetic-not-utf8"
    undecodable = parse_prepared(
        "binary-source.md",
        _prepared_bytes(
            "binary-note.md",
            undecodable_bytes,
            "Synthetic statement for undecodable staged bytes.",
        ),
        undecodable_bytes,
    )

    assert verbatim.verbatim_statement
    assert not rewritten.verbatim_statement
    assert not undecodable.verbatim_statement


def test_build_preview_rejects_eventual_visible_name_over_255_bytes(
    tmp_path: Path,
) -> None:
    config, prepared, staged, inbox = _configured_roots(tmp_path)
    prepared_name = f"{'x' * 240}.md"
    assert len(prepared_name.encode("utf-8")) == 243
    _write_candidate(prepared, staged, prepared_name)

    with pytest.raises(IntakeError) as caught:
        build_preview(config, [prepared_name], [])

    assert caught.value.code == "published_name_too_long"
    assert tuple(inbox.iterdir()) == ()


def _identity_json(identity: DirectoryIdentity) -> dict[str, int | str]:
    assert identity.volume is not None
    return {"volume": identity.volume, "inode": identity.inode}


def _metadata_json(metadata: MemoryMetadata) -> dict[str, object]:
    return {
        "kind": metadata.kind,
        "sensitivity": metadata.sensitivity,
        "occurred_on": metadata.occurred_on,
        "valid_from": metadata.valid_from,
        "valid_to": metadata.valid_to,
        "tags": list(metadata.tags),
    }


def test_manifest_digest_is_canonical_identity_complete_and_body_free(
    tmp_path: Path,
) -> None:
    config, prepared, staged, _ = _configured_roots(tmp_path)
    _write_candidate(
        prepared,
        staged,
        "candidate.md",
        sensitivity="sensitive",
        statement="Owner-visible synthetic statement.",
    )
    preview = build_preview(config, ["candidate.md"], [])
    candidate = preview.candidates[0]
    parsed = candidate.parsed
    expected_payload = {
        "schema": "staged-memory-intake.promotion-manifest.v2",
        "notes_identity": _identity_json(config.notes_identity),
        "inbox_identity": _identity_json(config.inbox_identity),
        "candidates": [
            {
                "ordinal": 0,
                "prepared_name": parsed.prepared_name,
                "source_name": parsed.source_name,
                "prepared_sha256": parsed.prepared_sha256,
                "source_sha256": parsed.source_sha256,
                "statement_sha256": parsed.statement_sha256,
                "statement_utf8_bytes": parsed.statement_utf8_bytes,
                "evidence_sha256": parsed.evidence_sha256,
                "evidence_char_start": parsed.evidence_char_start,
                "evidence_char_end": parsed.evidence_char_end,
                "requested_metadata": _metadata_json(parsed.requested_metadata),
                "final_metadata": _metadata_json(candidate.final_metadata),
                "client_item_id": candidate.client_item_id,
            }
        ],
        "guard_links": [],
        "batch_sensitivity": "sensitive",
    }
    canonical = json.dumps(
        expected_payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()

    assert preview.manifest_digest == hashlib.sha256(canonical).hexdigest()
    assert parsed.statement.encode() not in canonical
    assert parsed.evidence_excerpt.encode() not in canonical


def test_selection_order_changes_manifest_and_deterministic_item_ids(
    tmp_path: Path,
) -> None:
    config, prepared, staged, _ = _configured_roots(tmp_path)
    for name in ("alpha.md", "beta.md"):
        _write_candidate(prepared, staged, name)

    forward = build_preview(config, ["alpha.md", "beta.md"], [])
    reverse = build_preview(config, ["beta.md", "alpha.md"], [])

    assert forward.manifest_digest != reverse.manifest_digest
    for preview in (forward, reverse):
        for candidate in preview.candidates:
            expected = hashlib.sha256(
                f"{candidate.ordinal}:{candidate.parsed.prepared_sha256}".encode(
                    "ascii"
                )
            ).hexdigest()
            assert candidate.client_item_id == f"itm_{expected[:40]}"


def test_guard_json_whitespace_and_key_order_have_one_manifest_digest(
    tmp_path: Path,
) -> None:
    config, prepared, staged, _ = _configured_roots(tmp_path)
    for name in ("constraint.md", "claim.md"):
        _write_candidate(prepared, staged, name)
    compact = _guard_raw("prepared_name", "constraint.md", "prepared_name", "claim.md")
    reordered = (
        '{ "governed": { "prepared_name": "claim.md" }, '
        '"guard": { "prepared_name": "constraint.md" } }'
    )

    assert (
        build_preview(config, ["constraint.md", "claim.md"], [compact]).manifest_digest
        == build_preview(
            config, ["constraint.md", "claim.md"], [reordered]
        ).manifest_digest
    )


def test_duplicate_candidates_and_guard_links_are_rejected(tmp_path: Path) -> None:
    config, prepared, staged, _ = _configured_roots(tmp_path)
    for name in ("constraint.md", "claim.md"):
        _write_candidate(prepared, staged, name)
    with pytest.raises(IntakeError) as duplicate_candidate:
        build_preview(config, ["claim.md", "claim.md"], [])
    assert duplicate_candidate.value.code == "duplicate_candidate"
    link = _guard_raw("prepared_name", "constraint.md", "prepared_name", "claim.md")
    same_link = (
        '{ "governed": {"prepared_name":"claim.md"},'
        '"guard":{"prepared_name":"constraint.md"} }'
    )
    with pytest.raises(IntakeError) as duplicate_guard:
        build_preview(
            config,
            ["constraint.md", "claim.md"],
            [link, same_link],
        )
    assert duplicate_guard.value.code == "duplicate_guard_link"


def test_candidate_and_total_edit_limits_are_enforced(tmp_path: Path) -> None:
    config, prepared, staged, _ = _configured_roots(tmp_path)
    for index in range(51):
        _write_candidate(prepared, staged, f"candidate-{index:02}.md")
    names = [f"candidate-{index:02}.md" for index in range(51)]
    boundary = build_preview(config, names[:50], [])
    assert len(boundary.candidates) == 50
    with pytest.raises(IntakeError) as candidate_limit:
        build_preview(config, names, [])
    assert candidate_limit.value.code == "too_many_candidates"

    selected = names[:50]
    unique_links = (
        _guard_raw("prepared_name", guard, "prepared_name", governed)
        for guard in selected
        for governed in selected
        if guard != governed
    )
    guards = list(_take(unique_links, 207))
    edit_boundary = build_preview(config, selected, guards[:206])
    assert len(edit_boundary.candidates) + len(edit_boundary.guard_links) == 256
    with pytest.raises(IntakeError) as edit_limit:
        build_preview(config, selected, guards)
    assert edit_limit.value.code == "too_many_edits"


def _take(values: Iterator[str], count: int) -> Iterator[str]:
    for _ in range(count):
        yield next(values)


def test_build_preview_rebinds_both_roots_and_refuses_symlink_entries(
    tmp_path: Path,
) -> None:
    config, prepared, staged, inbox = _configured_roots(tmp_path)
    _write_candidate(prepared, staged, "candidate.md")
    outside = tmp_path / "outside.md"
    outside.write_bytes((prepared / "candidate.md").read_bytes())
    (prepared / "candidate.md").unlink()
    (prepared / "candidate.md").symlink_to(outside)
    with pytest.raises(IntakeError):
        build_preview(config, ["candidate.md"], [])

    (prepared / "candidate.md").unlink()
    _write_candidate(prepared, staged, "candidate.md")
    moved = tmp_path / "moved-inbox"
    inbox.rename(moved)
    inbox.mkdir(mode=0o700)
    with pytest.raises(IntakeError) as changed:
        build_preview(config, ["candidate.md"], [])
    assert changed.value.code == "configured_root_changed"


_DECISION_STATEMENT_EN = (
    "# Decision: workshop dehumidifier\n"
    "\n"
    "## Question\n"
    "Which replacement fits the workshop before the autumn damp?\n"
    "\n"
    "## Options considered\n"
    "A ducted unit needing a weekend install; a compact plug-in unit.\n"
    "\n"
    "## Recommendation\n"
    "The ducted unit, for coverage.\n"
    "\n"
    "## Decision\n"
    "Wren chose the ducted unit on 2026-08-19.\n"
    "\n"
    "## Rationale\n"
    "Coverage outweighs install effort before the damp arrives.\n"
    "\n"
    "## Revisit by\n"
    "2026-10-01 — if the unit is not installed by then."
)


def test_decision_note_maps_to_event_with_horizon_and_loop_tag() -> None:
    staged_bytes = b"Synthetic staged decision note."
    prepared_bytes = _prepared_bytes(
        "decision-dehumidifier.md",
        staged_bytes,
        _DECISION_STATEMENT_EN,
        kind="event",
        sensitivity="restricted",
        occurred_on="2026-08-19",
        valid_to="2026-10-01",
        tags='["aspect:synthetic-workshop","subject:decision-dehumidifier","loop:open"]',
    )

    parsed = parse_prepared("decision-dehumidifier.md", prepared_bytes, staged_bytes)

    assert parsed.statement == _DECISION_STATEMENT_EN
    assert parsed.evidence_excerpt == _DECISION_STATEMENT_EN
    assert parsed.requested_metadata == MemoryMetadata(
        kind="event",
        sensitivity="restricted",
        occurred_on="2026-08-19",
        valid_from=None,
        valid_to="2026-10-01",
        tags=(
            "aspect:synthetic-workshop",
            "subject:decision-dehumidifier",
            "loop:open",
        ),
    )


def test_closed_decision_note_has_no_horizon_and_no_loop_tag() -> None:
    statement = (
        "# Decision: keep the current workbench\n"
        "\n"
        "## Question\n"
        "Replace the workbench this season or keep it?\n"
        "\n"
        "## Options considered\n"
        "A wider bench; keeping the current one.\n"
        "\n"
        "## Recommendation\n"
        "Keep it; nothing blocks current work.\n"
        "\n"
        "## Decision\n"
        "Wren kept the current bench on 2026-08-19.\n"
        "\n"
        "## Rationale\n"
        "No project this season needs the extra width."
    )
    staged_bytes = b"Synthetic staged closed-decision note."
    prepared_bytes = _prepared_bytes(
        "decision-workbench.md",
        staged_bytes,
        statement,
        kind="event",
        sensitivity="restricted",
        occurred_on="2026-08-19",
        tags='["aspect:synthetic-workshop","subject:decision-workbench"]',
    )

    parsed = parse_prepared("decision-workbench.md", prepared_bytes, staged_bytes)

    assert parsed.requested_metadata.kind == "event"
    assert parsed.requested_metadata.valid_to is None
    assert "loop:open" not in parsed.requested_metadata.tags


def test_chinese_decision_note_body_survives_byte_exact() -> None:
    statement = (
        "# 决定：工作室除湿方案\n"
        "\n"
        "## Question\n"
        "秋季返潮前，工作室选哪种除湿方案？\n"
        "\n"
        "## Options considered\n"
        "整体管道式；即插即用的小型机。\n"
        "\n"
        "## Recommendation\n"
        "整体管道式，覆盖更全。\n"
        "\n"
        "## Decision\n"
        "溪桐在 2026-08-19 选了整体管道式。\n"
        "\n"
        "## Rationale\n"
        "覆盖范围比安装省事更重要。\n"
        "\n"
        "## Revisit by\n"
        "2026-10-01——如果届时还未安装完成。"
    )
    staged_bytes = "合成的暂存决定笔记。".encode()
    prepared_bytes = _prepared_bytes(
        "decision-dehumidifier-zh.md",
        staged_bytes,
        statement,
        kind="event",
        sensitivity="restricted",
        occurred_on="2026-08-19",
        valid_to="2026-10-01",
        tags='["aspect:synthetic-workshop","subject:decision-dehumidifier-zh","loop:open"]',
    )

    parsed = parse_prepared("decision-dehumidifier-zh.md", prepared_bytes, staged_bytes)

    assert parsed.statement == statement
    assert parsed.requested_metadata.occurred_on == "2026-08-19"
    assert parsed.requested_metadata.valid_to == "2026-10-01"
    assert parsed.requested_metadata.tags[-1] == "loop:open"


def test_decision_note_preview_carries_the_mapping_to_authorization(
    tmp_path: Path,
) -> None:
    notes_root = tmp_path / "synthetic-notes"
    prepared_root = notes_root / "03_Prepared"
    staged_root = notes_root / "02_Staged"
    inbox = tmp_path / "synthetic-inbox"
    for path in (notes_root, prepared_root, staged_root, inbox):
        path.mkdir(mode=0o700)
    staged_bytes = b"Synthetic staged decision note for preview."
    staged_root.joinpath("decision-dehumidifier.md").write_bytes(staged_bytes)
    prepared_root.joinpath("decision-dehumidifier.md").write_bytes(
        _prepared_bytes(
            "decision-dehumidifier.md",
            staged_bytes,
            _DECISION_STATEMENT_EN,
            kind="event",
            sensitivity="restricted",
            occurred_on="2026-08-19",
            valid_to="2026-10-01",
            tags='["aspect:synthetic-workshop","subject:decision-dehumidifier","loop:open"]',
        )
    )
    config = IntakeConfig(
        notes_root=notes_root,
        notes_identity=directory_identity(notes_root),
        memory_home=None,
        memory_inbox=inbox,
        inbox_identity=directory_identity(inbox),
    )

    preview = build_preview(config, ["decision-dehumidifier.md"], [])

    assert preview.batch_sensitivity == "restricted"
    (candidate,) = preview.candidates
    assert candidate.final_metadata.kind == "event"
    assert candidate.final_metadata.occurred_on == "2026-08-19"
    assert candidate.final_metadata.valid_to == "2026-10-01"
    assert candidate.final_metadata.tags == (
        "aspect:synthetic-workshop",
        "subject:decision-dehumidifier",
        "loop:open",
    )
    assert candidate.parsed.statement == _DECISION_STATEMENT_EN
    assert candidate.parsed.evidence_excerpt == _DECISION_STATEMENT_EN
    assert preview.manifest_digest


@pytest.mark.parametrize(
    ("source", "statement", "occurred_on", "valid_to", "tags"),
    [
        (
            "合成提醒：溪桐还需要检查温室的通风设备，日期未定。",
            "溪桐 still needs to check the greenhouse ventilation; no date is set.",
            "",
            "",
            ("synthetic", "loop:open"),
        ),
        (
            "Synthetic reminder: ten days after 2026-09-20, check the seed trays.",
            "Check the seed trays ten days after 2026-09-20, on 2026-09-30.",
            "",
            "2026-09-30",
            ("synthetic", "loop:open"),
        ),
        (
            "合成计划：每季度复查温室维护清单，下次日期未定。",
            "Review the greenhouse maintenance list quarterly; the next date is unset.",
            "",
            "",
            ("synthetic", "loop:open"),
        ),
        (
            "Synthetic plan: review the seed inventory quarterly, next on 2026-12-20.",
            "Review the seed inventory quarterly, with the next review on 2026-12-20.",
            "",
            "2026-12-20",
            ("synthetic", "loop:open"),
        ),
        (
            "Synthetic quarterly review: the greenhouse review finished on 2026-09-20.",
            "The quarterly greenhouse review finished on 2026-09-20.",
            "2026-09-20",
            "",
            ("synthetic",),
        ),
        (
            "Synthetic follow-ups: check irrigation on 2026-09-25 and lights on 2026-10-02.",
            "Check irrigation on 2026-09-25 and check the lights on 2026-10-02.",
            "",
            "",
            ("synthetic", "loop:open"),
        ),
    ],
    ids=[
        "undated-open-reminder",
        "source-anchored-relative-days",
        "quarterly-without-next-date",
        "quarterly-with-explicit-next-date",
        "retrospective-review",
        "independent-horizons-in-one-statement",
    ],
)
def test_open_item_preview_preserves_authored_metadata_without_scheduling(
    tmp_path: Path,
    source: str,
    statement: str,
    occurred_on: str,
    valid_to: str,
    tags: tuple[str, ...],
) -> None:
    """Prove authored metadata roundtrips, not model semantic extraction."""
    config, prepared_root, staged_root, _ = _configured_roots(tmp_path)
    staged_bytes = source.encode()
    prepared_bytes = _prepared_bytes(
        "source.md",
        staged_bytes,
        statement,
        sensitivity="restricted",
        occurred_on=occurred_on,
        valid_to=valid_to,
        tags=json.dumps(tags, separators=(",", ":")),
    )
    staged_path = staged_root / "source.md"
    prepared_path = prepared_root / "candidate.md"
    staged_path.write_bytes(staged_bytes)
    prepared_path.write_bytes(prepared_bytes)

    first = build_preview(config, ["candidate.md"], [])
    second = build_preview(config, ["candidate.md"], [])

    (candidate,) = first.candidates
    expected = MemoryMetadata(
        kind="fact",
        sensitivity="restricted",
        occurred_on=occurred_on or None,
        valid_from=None,
        valid_to=valid_to or None,
        tags=tags,
    )
    assert candidate.parsed.requested_metadata == expected
    assert candidate.final_metadata == expected
    assert candidate.parsed.statement == statement
    assert candidate.parsed.evidence_excerpt == statement
    assert second.candidates == first.candidates
    assert second.manifest_digest == first.manifest_digest
    assert staged_path.read_bytes() == staged_bytes
    assert prepared_path.read_bytes() == prepared_bytes
    rendered = json.dumps(preview_json(first))
    assert statement not in rendered
    assert '"valid_to"' not in rendered
