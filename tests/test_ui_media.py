"""Image and PDF preview: rendering, refusal, and worker custody.

These are the tests for `memory.ui.media_preview` and `memory.ui.pdf_render` --
the two modules that hand attacker-influenced bytes to a decoder. They run it
in a bounded subprocess and they are mostly about what that subprocess must
refuse: a polyglot PDF pdfium would happily rasterize, an xref table that
points into a literal, a stream whose declared length disagrees with its
bytes. The rest of the file is about the child always being reaped -- on
success, crash, timeout, cancellation, and client disconnect alike.

They lived inside a 4,400-line inspection suite where neither module had a
test file of its own to notice was missing.
"""

import asyncio
import importlib
import io
import os
import signal
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, cast

import httpx2
import pytest
from inspection_support import (
    CANCELLED_WORKER_TIMEOUT_SECONDS,
    EXACT_HOST,
    JPEG_SOURCE_ID,
    MAX_CANCELLED_RETURN_SECONDS,
    PDF_SOURCE_ID,
    PNG_SOURCE_ID,
    PUBLIC_ORIGIN,
    WEBP_SOURCE_ID,
    SyntheticInspectionService,
    _authenticated_ui,
    _hex_from_page,
    _image_bytes,
    _next_content_href,
    _pdf_bytes,
    _source_summary,
    _UnusedFinder,
    _wait_for_pid,
)
from PIL import Image
from pypdf import PdfWriter
from pypdf.generic import (
    DecodedStreamObject,
)
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient
from ui_support import build_test_orchestrator

from memory.model import (
    Sensitivity,
)
from memory.ui.app import OwnerUiService, create_ui_app
from memory.ui.auth import UiSessionStore
from memory.ui.media_preview import ImagePreview, run_media_job
from memory.ui.pdf_render import PdfPageImage


def _classic_table_pdf(
    *,
    entry_ending: bytes = b" \n",
    subsections: tuple[tuple[int, int], ...] = ((0, 5),),
    size: int = 5,
    object_zero_next: int = 0,
    free_entries: dict[int, tuple[int, int]] | None = None,
    padding_bytes: int = 0,
) -> bytes:
    """Build a small hand-checkable one-page classic-xref PDF fixture."""
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] >>",
        b"(synthetic unreferenced object)",
    )
    offsets: list[int] = []
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body + b"\nendobj\n")
    if padding_bytes:
        output.extend(b"%" + (b"p" * padding_bytes) + b"\n")

    entries: dict[int, bytes] = {
        0: f"{object_zero_next:010d} 65535 f".encode("ascii") + entry_ending
    }
    entries.update(
        {
            object_number: f"{offset:010d} 00000 n".encode("ascii") + entry_ending
            for object_number, offset in enumerate(offsets, start=1)
        }
    )
    for object_number, (next_free, generation) in (free_entries or {}).items():
        entries[object_number] = (
            f"{next_free:010d} {generation:05d} f".encode("ascii") + entry_ending
        )

    xref_offset = len(output)
    output.extend(b"xref\n")
    for first_object, count in subsections:
        output.extend(f"{first_object} {count}\n".encode("ascii"))
        for object_number in range(first_object, first_object + count):
            output.extend(entries[object_number])
    output.extend(
        b"trailer\n<< /Size "
        + str(size).encode("ascii")
        + b" /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def _replace_pdf_once(source: bytes, old: bytes, new: bytes) -> bytes:
    assert source.count(old) == 1
    return source.replace(old, new, 1)


def _valid_classic_xref_pdf(variant: str) -> bytes:
    if variant == "pypdf-lf":
        return _pdf_bytes(pages=1)
    if variant == "pypdf-crlf":
        source = _pdf_bytes(pages=1)
        xref_start = source.index(b"xref\n")
        trailer_start = source.index(b"trailer\n", xref_start)
        table = source[xref_start:trailer_start]
        assert table.count(b" n \n") == 4
        assert table.count(b" f \n") == 1
        table = table.replace(b" n \n", b" n\r\n").replace(b" f \n", b" f\r\n")
        return source[:xref_start] + table + source[trailer_start:]
    if variant == "multiple-subsections":
        return _classic_table_pdf(subsections=((0, 2), (2, 3)))
    if variant == "escaped-size":
        return _replace_pdf_once(
            _classic_table_pdf(),
            b"/Size 5",
            b"/S#69ze 5",
        )
    if variant == "size-name-value-plus-key":
        return _replace_pdf_once(
            _classic_table_pdf(),
            b"/Size 5",
            b"/Foo /Size /Size 5",
        )
    if variant == "nested-trailer-values":
        return _replace_pdf_once(
            _classic_table_pdf(),
            b"/Size 5",
            b"/Foo << /Nested /Size >> /Bar [ /Size 7 ] /Size 5",
        )
    if variant == "reserved-name-values":
        return _replace_pdf_once(
            _classic_table_pdf(),
            b"/Size 5",
            b"/Foo /Prev /Bar /XRefStm /Size 5",
        )
    if variant == "free-list":
        return _classic_table_pdf(
            subsections=((0, 6),),
            size=6,
            object_zero_next=5,
            free_entries={5: (0, 0)},
        )
    raise AssertionError(f"unknown valid classic xref variant: {variant}")


def _malformed_classic_xref_pdf(case: str) -> bytes:
    source = _classic_table_pdf()
    object_one_offset = source.index(b"1 0 obj")
    object_two_offset = source.index(b"2 0 obj")
    object_four_offset = source.index(b"4 0 obj")
    object_one_entry = f"{object_one_offset:010d} 00000 n".encode("ascii")
    object_two_entry = f"{object_two_offset:010d} 00000 n".encode("ascii")
    object_four_entry = f"{object_four_offset:010d} 00000 n \n".encode("ascii")

    if case == "zero-subsection-count":
        return _replace_pdf_once(source, b"0 5\n", b"0 0\n")
    if case == "subsection-count-overflow":
        return _replace_pdf_once(source, b"0 5\n", b"0 100001\n")
    if case == "subsection-token-overflow":
        return _replace_pdf_once(
            source,
            b"0 5\n",
            b"0 000000000000000000000\n",
        )
    if case == "subsection-range-overflow":
        return _replace_pdf_once(source, b"0 5\n", b"4 2\n")
    if case == "overlapping-subsections":
        return _classic_table_pdf(subsections=((0, 3), (2, 3)))
    if case == "coverage-gap":
        return _classic_table_pdf(subsections=((0, 2), (3, 2)))
    if case == "nondigit-entry-offset":
        return _replace_pdf_once(
            source,
            object_one_entry,
            b"X" + object_one_entry[1:],
        )
    if case == "nondigit-entry-generation":
        return _replace_pdf_once(
            source,
            object_one_entry,
            object_one_entry[:11] + b"X" + object_one_entry[12:],
        )
    if case == "short-entry-offset":
        return _replace_pdf_once(source, object_one_entry, object_one_entry[1:])
    if case == "short-entry-generation":
        return _replace_pdf_once(
            source,
            object_one_entry,
            object_one_entry[:11] + object_one_entry[12:],
        )
    if case == "invalid-entry-status":
        return _replace_pdf_once(
            source,
            object_one_entry,
            object_one_entry[:-1] + b"x",
        )
    if case == "in-use-offset-out-of-range":
        return _replace_pdf_once(
            source,
            object_one_entry,
            b"9999999999 00000 n",
        )
    if case == "object-number-target-mismatch":
        return _replace_pdf_once(
            source,
            object_one_entry,
            object_two_entry,
        )
    if case == "generation-target-mismatch":
        return _replace_pdf_once(
            source,
            object_one_entry,
            object_one_entry[:11] + b"00001" + object_one_entry[16:],
        )
    if case == "object-zero-generation":
        return _replace_pdf_once(source, b"0000000000 65535 f", b"0000000000 65534 f")
    if case == "object-zero-in-use":
        return _replace_pdf_once(source, b"0000000000 65535 f", b"0000000000 65535 n")
    if case == "free-list-pointer-out-of-range":
        return _classic_table_pdf(
            subsections=((0, 6),),
            size=6,
            object_zero_next=5,
            free_entries={5: (7, 0)},
        )
    if case == "free-list-self-cycle":
        return _classic_table_pdf(
            subsections=((0, 6),),
            size=6,
            object_zero_next=5,
            free_entries={5: (5, 0)},
        )
    if case == "free-list-points-in-use":
        return _classic_table_pdf(
            subsections=((0, 6),),
            size=6,
            object_zero_next=5,
            free_entries={5: (1, 0)},
        )
    if case == "unreachable-free-entry":
        return _classic_table_pdf(
            subsections=((0, 6),),
            size=6,
            free_entries={5: (0, 0)},
        )
    if case == "missing-trailer":
        return _replace_pdf_once(source, b"trailer\n", b"missing\n")
    if case == "duplicate-trailer":
        return _replace_pdf_once(
            source,
            b"trailer\n<<",
            b"trailer\n<< /Size 5 >>\ntrailer\n<<",
        )
    if case == "malformed-trailer":
        return _replace_pdf_once(
            source,
            b"trailer\n<< /Size 5 /Root 1 0 R >>",
            b"trailer\n[ /Size 5 /Root 1 0 R ]",
        )
    if case == "missing-size":
        return _replace_pdf_once(source, b"/Size 5 ", b"")
    if case == "nested-size-only":
        return _replace_pdf_once(source, b"/Size 5", b"/Foo << /Size 5 >>")
    if case == "size-array-value":
        return _replace_pdf_once(source, b"/Size 5", b"/Size [5]")
    if case == "size-string-value":
        return _replace_pdf_once(source, b"/Size 5", b"/Size (5)")
    if case == "size-nested-dictionary-value":
        return _replace_pdf_once(source, b"/Size 5", b"/Size << /Value 5 >>")
    if case == "size-name-value":
        return _replace_pdf_once(source, b"/Size 5", b"/Size /Five")
    if case == "dangling-trailer-key":
        return _replace_pdf_once(source, b"/Root 1 0 R >>", b"/Root 1 0 R /Foo >>")
    if case == "odd-trailer-arity":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 7")
    if case == "size-zero":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 0")
    if case == "size-token-overflow":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 000000000000000000005")
    if case == "size-mismatch":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 4")
    if case == "duplicate-size":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 /Size 5")
    if case == "duplicate-escaped-size":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 /Si#7ae 5")
    if case == "indirect-size":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 0 R")
    if case == "prev":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 /Prev 0")
    if case == "escaped-prev":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 /Pr#65v 0")
    if case == "xref-stm":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 /XRefStm 1")
    if case == "escaped-xref-stm":
        return _replace_pdf_once(source, b"/Size 5", b"/Size 5 /XR#65fStm 1")
    if case == "junk-before-trailer":
        return _replace_pdf_once(source, b"trailer\n", b"synthetic-junk\ntrailer\n")
    if case == "truncated-table":
        return _replace_pdf_once(source, object_four_entry, b"")
    if case == "paginated-malformed-header":
        return _replace_pdf_once(
            _classic_table_pdf(padding_bytes=70_000),
            b"xref\n0 5\n",
            b"xref\nXXX\n",
        )
    raise AssertionError(f"unknown malformed classic xref case: {case}")


def _coherent_incremental_pdf_polyglot() -> bytes:
    base = _pdf_bytes(pages=1)
    payload = b"<script>synthetic-coherent-pdf-polyglot()</script>\n"
    writer = PdfWriter(io.BytesIO(base + payload), incremental=True)
    writer.add_metadata({"/SyntheticIncrement": "true"})
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _pdf_with_literal_eof_in_content_stream() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=96, height=64)
    content = DecodedStreamObject()
    content.set_data(b"q\n% synthetic content stream keeps %%EOF inert\nQ\n")
    # pypdf annotates `replace_contents` for `ContentStream`, which re-serializes
    # from parsed operators and would drop the literal marker this fixture is
    # about; the writer stores any stream object it is handed.
    page.replace_contents(content)  # type: ignore[arg-type]
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def _pdf_with_literal_eof_in_string_and_comment() -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R /Synthetic (literal %%EOF string) >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] >>",
        b"%%EOF\nnull",
    )
    offsets: list[int] = []
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body + b"\nendobj\n")
    output.extend(b"% synthetic ordinary comment contains %%EOF inert\n")
    xref_offset = len(output)
    output.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def _pdf_with_table_xref_increment() -> bytes:
    base = _pdf_bytes(pages=1)
    previous_xref = int(base[base.rfind(b"startxref") + 9 :].splitlines()[1])
    object_offset = len(base)
    appended_object = b"5 0 obj\n(synthetic incremental table revision)\nendobj\n"
    xref_offset = object_offset + len(appended_object)
    return (
        base
        + appended_object
        + b"xref\n5 1\n"
        + f"{object_offset:010d} 00000 n \n".encode("ascii")
        + b"trailer\n<< /Size 6 /Root 3 0 R /Info 1 0 R /Prev "
        + str(previous_xref).encode("ascii")
        + b" >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )


def _pdf_with_mismatched_stream_length() -> bytes:
    writer = PdfWriter()
    page = writer.add_blank_page(width=96, height=64)
    content = DecodedStreamObject()
    content.set_data(b"q\nQ\n")
    # Same as above: the declared union excludes the raw decoded stream this
    # fixture needs to keep the writer's `/Length 4` verbatim.
    page.replace_contents(content)  # type: ignore[arg-type]
    output = io.BytesIO()
    writer.write(output)
    source = output.getvalue()
    assert source.count(b"/Length 4\n") == 1
    return source.replace(b"/Length 4\n", b"/Length 2\n", 1)


def _pdf_with_indirect_stream_length() -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] /Contents 4 0 R >>",
        b"<< /Length 5 0 R >>\nstream\nq\nQ\n\nendstream",
        b"4",
    )
    offsets: list[int] = []
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body + b"\nendobj\n")
    xref_offset = len(output)
    output.extend(b"xref\n0 6\n0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def _pdf_with_terminal_xref_stream_prev() -> bytes:
    base = _pdf_bytes(pages=1)
    writer = PdfWriter(io.BytesIO(base), incremental=True)
    writer.add_metadata({"/SyntheticIncrement": "true"})
    output = io.BytesIO()
    writer.write(output)
    source = output.getvalue()
    first_eof = source.find(b"%%EOF")
    assert first_eof >= 0
    return source[:first_eof] + b"%XEOF" + source[first_eof + len(b"%%EOF") :]


def _pdf_with_inert_startxref_target(
    body: bytes,
    *,
    target: bytes | None,
) -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] >>",
        body,
    )
    offsets: list[int] = []
    claimed_xref_offset = -1
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        if object_number == 4:
            claimed_xref_offset = (
                offsets[-1] if target is None else len(output) + body.index(target)
            )
        output.extend(body + b"\nendobj\n")
    assert claimed_xref_offset >= 0
    real_xref_offset = len(output)
    output.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n"
        + str(claimed_xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    assert output[real_xref_offset : real_xref_offset + 5] == b"xref\n"
    return bytes(output)


def _pdf_with_startxref_into_literal_xref() -> bytes:
    return _pdf_with_inert_startxref_target(
        b"(xref\nsynthetic inert marker)",
        target=b"xref\n",
    )


def _pdf_with_startxref_in_inert_context(context: str) -> bytes:
    if context == "hex":
        return _pdf_with_inert_startxref_target(
            b"<787265660a>",
            target=b"78726566",
        )
    if context == "comment":
        return _pdf_with_inert_startxref_target(
            b"null\n% xref\nsynthetic inert comment",
            target=b"xref\n",
        )
    if context == "stream":
        data = b"xref\nsynthetic inert stream"
        return _pdf_with_inert_startxref_target(
            b"<< /Length "
            + str(len(data)).encode("ascii")
            + b" >>\nstream\n"
            + data
            + b"\nendstream",
            target=b"xref\n",
        )
    if context == "ordinary-object-word":
        return _pdf_with_inert_startxref_target(
            b"xref\n",
            target=b"xref\n",
        )
    if context == "ordinary-object-fake-type":
        return _pdf_with_inert_startxref_target(
            b"(synthetic inert /Type /XRef marker)",
            target=None,
        )
    raise AssertionError(f"unknown synthetic PDF context: {context}")


def _pdf_with_duplicate_structural_xref() -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] >>",
        b"<< /Type /XRef /Length 0 >>\nstream\n\nendstream",
    )
    offsets: list[int] = []
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body + b"\nendobj\n")
    real_xref_offset = len(output)
    output.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n"
        + str(real_xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def _pdf_with_wrong_xref_stream_object_offset() -> bytes:
    source = _pdf_with_escaped_name_xref_stream()
    token_start = source.rfind(b"startxref\n") + len(b"startxref\n")
    token_end = source.index(b"\n", token_start)
    xref_offset = int(source[token_start:token_end])
    wrong_offset = str(xref_offset + 1).encode("ascii")
    assert len(wrong_offset) == token_end - token_start
    return source[:token_start] + wrong_offset + source[token_end:]


def _pdf_with_escaped_name_xref_stream(
    *,
    type_entries: bytes = b"/T#79pe /XR#65f",
) -> bytes:
    output = bytearray(b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] >>",
    )
    offsets: list[int] = []
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body + b"\nendobj\n")
    xref_offset = len(output)
    xref_entries = bytearray(b"\x00\x00\x00\x00\x00\xff\xff")
    for offset in (*offsets, xref_offset):
        xref_entries.extend(b"\x01" + offset.to_bytes(4, "big") + b"\x00\x00")
    output.extend(
        b"4 0 obj\n<< " + type_entries + b" /Size 5 /Root 1 0 R "
        b"/W [1 4 2] /Index [0 5] /Length "
        + str(len(xref_entries)).encode("ascii")
        + b" >>\nstream\n"
        + xref_entries
        + b"\nendstream\nendobj\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def _pdf_with_direct_stream_dictionary(dictionary: bytes) -> bytes:
    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Count 1 /Kids [3 0 R] >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 96 64] /Contents 4 0 R >>",
        dictionary + b"\nstream\nq\nQ\n\nendstream",
    )
    offsets: list[int] = []
    for object_number, body in enumerate(objects, start=1):
        offsets.append(len(output))
        output.extend(f"{object_number} 0 obj\n".encode("ascii"))
        output.extend(body + b"\nendobj\n")
    xref_offset = len(output)
    output.extend(b"xref\n0 5\n0000000000 65535 f \n")
    for offset in offsets:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode("ascii")
        + b"\n%%EOF\n"
    )
    return bytes(output)


def _decode_metadata_free_png(value: bytes) -> Image.Image:
    decoded = Image.open(io.BytesIO(value))
    decoded.load()
    assert decoded.format == "PNG"
    assert getattr(decoded, "n_frames", 1) == 1
    assert decoded.getexif() == {}
    assert not ({"icc_profile", "exif", "xmp", "comment"} & set(decoded.info))
    assert b"eXIf" not in value
    assert b"iCCP" not in value
    assert b"tEXt" not in value
    assert b"zTXt" not in value
    assert b"iTXt" not in value
    return decoded


@pytest.mark.parametrize("image_format", ["PNG", "JPEG", "WEBP"])
def test_image_preview_is_a_new_canonical_metadata_free_png(
    image_format: str,
) -> None:
    """Catch original active media or embedded metadata reaching the browser."""
    media = importlib.import_module("memory.ui.media_preview")
    original = _image_bytes(image_format)

    preview = media.render_image_preview(
        original,
        max_pixels=media.MAX_PREVIEW_PIXELS,
    )
    decoded = _decode_metadata_free_png(preview.png_bytes)

    assert preview.png_bytes != original
    assert decoded.size == (preview.width, preview.height) == (37, 23)
    assert len(preview.png_bytes) <= media.MAX_PREVIEW_PNG_BYTES


def test_pdf_preview_rasterizes_without_following_an_external_action() -> None:
    """Catch PDF open actions causing any network request during rasterization."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(0.15)
    port = int(listener.getsockname()[1])
    source = _pdf_bytes(
        pages=1,
        external_uri=f"http://127.0.0.1:{port}/synthetic-external-action",
    )
    try:
        preview = pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
        with pytest.raises(TimeoutError):
            listener.accept()
    finally:
        listener.close()

    decoded = _decode_metadata_free_png(preview.png_bytes)
    assert preview.page_number == 1
    assert decoded.size == (preview.width, preview.height)
    assert preview.png_bytes != source


def test_pdf_preview_rejects_appended_payloads_but_allows_pdf_whitespace() -> None:
    """Catch PDFium accepting bytes beyond the effective final PDF EOF."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    base = _pdf_bytes(pages=1)
    permitted = base + b"\x00\x09\x0a\x0c\x0d\x20"
    appended = base + b"<script>synthetic-pdf-polyglot()</script>"
    forged_final_eof = appended + b"\nstartxref\n0\n%%EOF\n"

    preview = pdf.render_pdf_page(
        permitted,
        page_number=1,
        max_pixels=16_000_000,
    )
    assert _decode_metadata_free_png(preview.png_bytes).size == (
        preview.width,
        preview.height,
    )
    for source in (appended, forged_final_eof):
        with pytest.raises(pdf.MediaPreviewError) as error:
            pdf.render_pdf_page(
                source,
                page_number=1,
                max_pixels=16_000_000,
            )
        assert error.value.code == "invalid_pdf_framing"

    service = SyntheticInspectionService()
    valid_id = "src_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    invalid_id = "src_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    for source_id, body in ((valid_id, permitted), (invalid_id, appended)):
        service.media[source_id] = (
            "application/pdf",
            body,
            f"synthetic-{source_id[4]}.pdf",
        )
        service.sources[source_id] = _source_summary(
            source_id,
            sensitivity=Sensitivity.RESTRICTED,
            media_type="application/pdf",
            name=f"synthetic-{source_id[4]}.pdf",
            byte_length=len(body),
        )
    ui = _authenticated_ui(service)

    assert ui.client.get(f"/sources/{valid_id}/preview").status_code == 200
    rejected = ui.client.get(f"/sources/{invalid_id}/preview")
    assert rejected.status_code == 422
    assert rejected.text == "Preview unavailable"


def test_pdf_preview_rejects_malformed_classic_xref_subsection_header() -> None:
    """Catch a bare top-level xref token standing in for a real table."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_bytes(pages=1).replace(b"xref\n0 5\n", b"xref\nXXX\n", 1)
    assert b"xref\nXXX\n" in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_10101010101010101010101010101010"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-malformed-xref-header.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-malformed-xref-header.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    preview = ui.client.get(f"/sources/{source_id}/preview")
    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"

    reconstructed = bytearray()
    url: str | None = f"/sources/{source_id}"
    while url is not None:
        detail = ui.client.get(url)
        assert detail.status_code == 200
        reconstructed.extend(_hex_from_page(detail.text))
        url = _next_content_href(detail.text)
    assert bytes(reconstructed) == source


def test_pdf_preview_rejects_invalid_classic_xref_free_entry_offset() -> None:
    """Catch a malformed object-zero free entry accepted through PDF repair."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_bytes(pages=1).replace(
        b"0000000000 65535 f ",
        b"9999999999 65535 f ",
        1,
    )
    assert b"9999999999 65535 f " in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_20202020202020202020202020202020"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-invalid-xref-free-entry.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-invalid-xref-free-entry.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    preview = ui.client.get(f"/sources/{source_id}/preview")
    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"

    reconstructed = bytearray()
    url: str | None = f"/sources/{source_id}"
    while url is not None:
        detail = ui.client.get(url)
        assert detail.status_code == 200
        reconstructed.extend(_hex_from_page(detail.text))
        url = _next_content_href(detail.text)
    assert bytes(reconstructed) == source


def test_pdf_rejects_size_used_only_as_trailer_value_to_exact_hex() -> None:
    """Catch a flattened trailer value masquerading as the direct /Size key."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _replace_pdf_once(
        _classic_table_pdf(padding_bytes=70_000),
        b"/Size 5",
        b"/Foo /Size 5",
    )
    assert b"trailer\n<< /Foo /Size 5 /Root 1 0 R >>" in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    renderer_error: str | None = None
    try:
        rendered = pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    except pdf.MediaPreviewError as error:
        renderer_error = error.code
    else:
        _decode_metadata_free_png(rendered.png_bytes)

    source_id = "src_24242424242424242424242424242424"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-size-value-only.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-size-value-only.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    preview = ui.client.get(f"/sources/{source_id}/preview")
    if preview.status_code == 200:
        _decode_metadata_free_png(preview.content)

    assert (renderer_error, preview.status_code) == ("invalid_pdf_framing", 422)
    assert preview.text == "Preview unavailable"
    assert preview.headers["content-type"].startswith("text/plain")
    assert source not in preview.content

    reconstructed = bytearray()
    page_count = 0
    url: str | None = f"/sources/{source_id}"
    while url is not None:
        detail = ui.client.get(url)
        assert detail.status_code == 200
        assert "<object" not in detail.text
        assert "<embed" not in detail.text
        assert "<iframe" not in detail.text
        reconstructed.extend(_hex_from_page(detail.text))
        page_count += 1
        url = _next_content_href(detail.text)
    assert bytes(reconstructed) == source
    assert page_count > 1


@pytest.mark.parametrize(
    "variant",
    [
        "pypdf-lf",
        "pypdf-crlf",
        "multiple-subsections",
        "escaped-size",
        "size-name-value-plus-key",
        "nested-trailer-values",
        "reserved-name-values",
        "free-list",
    ],
)
def test_pdf_preview_accepts_bounded_classic_xref_table_variants(
    variant: str,
) -> None:
    """Catch the fail-closed table subset excluding valid bounded grammar."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _valid_classic_xref_pdf(variant)

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    preview = pdf.render_pdf_page(
        source,
        page_number=1,
        max_pixels=16_000_000,
    )
    decoded = _decode_metadata_free_png(preview.png_bytes)
    assert decoded.size == (preview.width, preview.height)
    assert preview.png_bytes != source

    source_id = "src_25252525252525252525252525252525"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-valid-classic-xref.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-valid-classic-xref.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    response = ui.client.get(f"/sources/{source_id}/preview")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert "content-disposition" not in response.headers
    assert response.content != source
    _decode_metadata_free_png(response.content)


@pytest.mark.parametrize(
    "case",
    [
        "zero-subsection-count",
        "subsection-count-overflow",
        "subsection-token-overflow",
        "subsection-range-overflow",
        "overlapping-subsections",
        "coverage-gap",
        "nondigit-entry-offset",
        "nondigit-entry-generation",
        "short-entry-offset",
        "short-entry-generation",
        "invalid-entry-status",
        "in-use-offset-out-of-range",
        "object-number-target-mismatch",
        "generation-target-mismatch",
        "object-zero-generation",
        "object-zero-in-use",
        "free-list-pointer-out-of-range",
        "free-list-self-cycle",
        "free-list-points-in-use",
        "unreachable-free-entry",
        "missing-trailer",
        "duplicate-trailer",
        "malformed-trailer",
        "missing-size",
        "nested-size-only",
        "size-array-value",
        "size-string-value",
        "size-nested-dictionary-value",
        "size-name-value",
        "dangling-trailer-key",
        "odd-trailer-arity",
        "size-zero",
        "size-token-overflow",
        "size-mismatch",
        "duplicate-size",
        "duplicate-escaped-size",
        "indirect-size",
        "prev",
        "escaped-prev",
        "xref-stm",
        "escaped-xref-stm",
        "junk-before-trailer",
        "truncated-table",
        "paginated-malformed-header",
    ],
)
def test_pdf_preview_rejects_malformed_classic_xref_tables_to_exact_hex(
    case: str,
) -> None:
    """Catch malformed classic tables reaching tolerant PDFium repair paths."""
    source = _malformed_classic_xref_pdf(case)
    source_id = "src_30303030303030303030303030303030"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-malformed-classic-xref.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-malformed-classic-xref.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)

    preview = ui.client.get(f"/sources/{source_id}/preview")
    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"
    assert preview.headers["content-type"].startswith("text/plain")
    assert source not in preview.content

    reconstructed = bytearray()
    page_count = 0
    url: str | None = f"/sources/{source_id}"
    while url is not None:
        detail = ui.client.get(url)
        assert detail.status_code == 200
        assert "<object" not in detail.text
        assert "<embed" not in detail.text
        assert "<iframe" not in detail.text
        reconstructed.extend(_hex_from_page(detail.text))
        page_count += 1
        url = _next_content_href(detail.text)
    assert bytes(reconstructed) == source
    if case == "paginated-malformed-header":
        assert page_count > 1


def test_pdf_preview_rejects_pdfium_valid_incremental_polyglot_to_exact_hex() -> None:
    """Catch a coherent appended xref making an earlier PDF EOF look safe."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _coherent_incremental_pdf_polyglot()
    assert source.count(b"%%EOF") == 2
    assert b"<script>synthetic-coherent-pdf-polyglot()</script>" in source
    assert b"/Type /XRef" in source
    assert b"/Prev " in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_cccccccccccccccccccccccccccccccc"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-coherent-polyglot.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-coherent-polyglot.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)

    preview = ui.client.get(f"/sources/{source_id}/preview")
    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"
    assert preview.headers["content-type"].startswith("text/plain")
    assert source not in preview.content

    reconstructed = bytearray()
    url: str | None = f"/sources/{source_id}"
    while url is not None:
        detail = ui.client.get(url)
        assert detail.status_code == 200
        assert "<script>" not in detail.text
        assert "<object" not in detail.text
        assert "<embed" not in detail.text
        assert "<iframe" not in detail.text
        reconstructed.extend(_hex_from_page(detail.text))
        url = _next_content_href(detail.text)
    assert bytes(reconstructed) == source


def test_pdf_preview_allows_literal_eof_inside_a_length_bounded_stream() -> None:
    """Catch raw marker counting rejecting inert bytes inside a valid stream."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_literal_eof_in_content_stream()
    assert source.count(b"%%EOF") == 2
    assert b"/Length 49" in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    preview = pdf.render_pdf_page(
        source,
        page_number=1,
        max_pixels=16_000_000,
    )
    assert _decode_metadata_free_png(preview.png_bytes).size == (
        preview.width,
        preview.height,
    )

    source_id = "src_dddddddddddddddddddddddddddddddd"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-literal-eof-stream.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-literal-eof-stream.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    response = ui.client.get(f"/sources/{source_id}/preview")
    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert "content-disposition" not in response.headers
    assert response.content != source
    _decode_metadata_free_png(response.content)


def test_pdf_preview_allows_length_name_value_with_actual_direct_length_key() -> None:
    """Catch value-position /Length names being mistaken for duplicate keys."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_direct_stream_dictionary(b"<< /Foo /Length /L#65ngth 4 >>")

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    preview = pdf.render_pdf_page(
        source,
        page_number=1,
        max_pixels=16_000_000,
    )
    assert _decode_metadata_free_png(preview.png_bytes).size == (
        preview.width,
        preview.height,
    )


def test_pdf_rejects_length_used_only_as_stream_value_to_exact_hex() -> None:
    """Catch flattened stream values masquerading as the direct /Length key."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_direct_stream_dictionary(b"<< /Foo /Length 4 >>")

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_26262626262626262626262626262626"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-length-value-only.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-length-value-only.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    response = ui.client.get(f"/sources/{source_id}/preview")
    assert response.status_code == 422
    assert response.text == "Preview unavailable"
    assert response.headers["content-type"].startswith("text/plain")
    assert source not in response.content

    detail = ui.client.get(f"/sources/{source_id}")
    assert detail.status_code == 200
    assert _hex_from_page(detail.text) == source
    assert "<object" not in detail.text
    assert "<embed" not in detail.text
    assert "<iframe" not in detail.text


def test_pdf_preview_allows_literal_eof_in_string_and_ordinary_comment() -> None:
    """Catch EOF detection treating inert lexical contexts as document ends."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_literal_eof_in_string_and_comment()
    assert source.count(b"%%EOF") == 4

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    preview = pdf.render_pdf_page(
        source,
        page_number=1,
        max_pixels=16_000_000,
    )
    assert _decode_metadata_free_png(preview.png_bytes).size == (
        preview.width,
        preview.height,
    )


def test_pdf_preview_rejects_table_xref_increment_with_prev() -> None:
    """Catch table-style incremental history bypassing the single revision rule."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_table_xref_increment()
    assert source.count(b"%%EOF") == 2
    assert b"trailer\n<<" in source
    assert b"/Prev " in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"


def test_pdf_preview_rejects_pdfium_tolerated_mismatched_stream_length() -> None:
    """Catch ambiguous endstream recovery entering the bounded preview subset."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_mismatched_stream_length()
    assert b"/Length 2\n" in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-mismatched-length.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-mismatched-length.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    preview = ui.client.get(f"/sources/{source_id}/preview")
    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"
    detail = ui.client.get(f"/sources/{source_id}")
    assert detail.status_code == 200
    assert _hex_from_page(detail.text) == source
    assert "<object" not in detail.text
    assert "<embed" not in detail.text


def test_pdf_preview_rejects_indirect_stream_length_as_ambiguous() -> None:
    """Catch unbounded length-object resolution entering the preview scanner."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_indirect_stream_length()
    assert b"/Length 5 0 R" in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"


def test_pdf_preview_rejects_terminal_xref_stream_prev() -> None:
    """Catch terminal xref-stream history when an earlier EOF is obscured."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_terminal_xref_stream_prev()
    assert source.count(b"%%EOF") == 1
    assert b"/Type /XRef" in source
    assert b"/Prev " in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"


def test_pdf_preview_rejects_startxref_into_literal_xref_to_exact_hex() -> None:
    """Catch raw xref-prefix matching inside an unreferenced literal string."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_startxref_into_literal_xref()
    claimed_xref = int(source[source.rfind(b"startxref") + 9 :].splitlines()[1])
    real_xref = source.index(b"xref\n0 5")
    assert claimed_xref != real_xref
    assert source[claimed_xref : claimed_xref + 5] == b"xref\n"

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_ffffffffffffffffffffffffffffffff"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-literal-xref-target.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-literal-xref-target.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    preview = ui.client.get(f"/sources/{source_id}/preview")
    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"
    detail = ui.client.get(f"/sources/{source_id}")
    assert detail.status_code == 200
    assert _hex_from_page(detail.text) == source
    assert "<object" not in detail.text
    assert "<embed" not in detail.text


def test_pdf_preview_allows_escaped_name_xref_stream() -> None:
    """Catch raw name matching rejecting a structurally valid xref stream."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_escaped_name_xref_stream()
    assert source.count(b"%%EOF") == 1
    assert b"/T#79pe /XR#65f" in source
    assert b"/Type /XRef" not in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    preview = pdf.render_pdf_page(
        source,
        page_number=1,
        max_pixels=16_000_000,
    )
    assert _decode_metadata_free_png(preview.png_bytes).size == (
        preview.width,
        preview.height,
    )


def test_pdf_preview_allows_type_name_value_with_actual_direct_xref_type() -> None:
    """Catch a value-position /Type name hiding an actual direct escaped key."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_escaped_name_xref_stream(
        type_entries=b"/Foo /Type /T#79pe /XR#65f"
    )

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    preview = pdf.render_pdf_page(
        source,
        page_number=1,
        max_pixels=16_000_000,
    )
    assert _decode_metadata_free_png(preview.png_bytes).size == (
        preview.width,
        preview.height,
    )


def test_pdf_preview_rejects_type_name_used_only_as_xref_stream_value() -> None:
    """Catch a flattened xref-stream value masquerading as direct /Type."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_escaped_name_xref_stream(type_entries=b"/Foo /Type /XRef")

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"

    source_id = "src_27272727272727272727272727272727"
    service = SyntheticInspectionService()
    service.media[source_id] = (
        "application/pdf",
        source,
        "synthetic-type-value-only.pdf",
    )
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type="application/pdf",
        name="synthetic-type-value-only.pdf",
        byte_length=len(source),
    )
    ui = _authenticated_ui(service)
    response = ui.client.get(f"/sources/{source_id}/preview")
    assert response.status_code == 422
    assert response.text == "Preview unavailable"
    assert response.headers["content-type"].startswith("text/plain")
    assert source not in response.content

    detail = ui.client.get(f"/sources/{source_id}")
    assert detail.status_code == 200
    assert _hex_from_page(detail.text) == source
    assert "<object" not in detail.text
    assert "<embed" not in detail.text
    assert "<iframe" not in detail.text


@pytest.mark.parametrize(
    "context",
    [
        "hex",
        "comment",
        "stream",
        "ordinary-object-word",
        "ordinary-object-fake-type",
    ],
)
def test_pdf_preview_rejects_startxref_in_inert_context(context: str) -> None:
    """Catch inert bytes or an ordinary object masquerading as terminal xref."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_startxref_in_inert_context(context)

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
        page = document[0]
        try:
            bitmap = page.render(scale=1)
            try:
                assert bitmap.to_pil().size == (96, 64)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"


def test_pdf_preview_rejects_wrong_xref_stream_object_offset() -> None:
    """Catch a repaired offset inside, rather than at, an xref-stream object."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_wrong_xref_stream_object_offset()

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"


def test_pdf_preview_rejects_duplicate_structural_xref() -> None:
    """Catch multiple top-level xref candidates making the binding ambiguous."""
    pdf = importlib.import_module("memory.ui.pdf_render")
    pdfium = importlib.import_module("pypdfium2")
    source = _pdf_with_duplicate_structural_xref()
    assert source.count(b"xref\n") == 2
    assert b"/Type /XRef /Length 0" in source

    document = pdfium.PdfDocument(source)
    try:
        assert len(document) == 1
    finally:
        document.close()

    with pytest.raises(pdf.MediaPreviewError) as error:
        pdf.render_pdf_page(
            source,
            page_number=1,
            max_pixels=16_000_000,
        )
    assert error.value.code == "invalid_pdf_framing"


def test_media_source_byte_limit_is_enforced_before_decode() -> None:
    """Catch a limit-plus-one source being handed to a decoder child."""
    media = importlib.import_module("memory.ui.media_preview")

    with pytest.raises(media.MediaPreviewError) as exact:
        media.render_image_preview(
            b"x" * media.MAX_MEDIA_SOURCE_BYTES,
            max_pixels=media.MAX_PREVIEW_PIXELS,
        )
    with pytest.raises(media.MediaPreviewError) as over:
        media.render_image_preview(
            b"x" * (media.MAX_MEDIA_SOURCE_BYTES + 1),
            max_pixels=media.MAX_PREVIEW_PIXELS,
        )

    assert exact.value.code == "invalid_media"
    assert over.value.code == "source_too_large"


def test_image_frame_dimension_and_output_pixel_limits_are_exact() -> None:
    """Catch animated or limit-plus-one image output entering a preview."""
    media = importlib.import_module("memory.ui.media_preview")
    exact_dimension = _image_bytes(
        "PNG",
        size=(media.MAX_PREVIEW_DIMENSION, 1),
        metadata=False,
    )
    over_dimension = _image_bytes(
        "PNG",
        size=(media.MAX_PREVIEW_DIMENSION + 1, 1),
        metadata=False,
    )
    first = Image.new("RGBA", (4, 4), "red")
    second = Image.new("RGBA", (4, 4), "blue")
    animated = io.BytesIO()
    first.save(
        animated,
        format="PNG",
        save_all=True,
        append_images=[second],
        duration=10,
        loop=0,
    )

    assert (
        media.render_image_preview(
            exact_dimension,
            max_pixels=media.MAX_PREVIEW_PIXELS,
        ).width
        == media.MAX_PREVIEW_DIMENSION
    )
    with pytest.raises(media.MediaPreviewError) as dimension_error:
        media.render_image_preview(
            over_dimension,
            max_pixels=media.MAX_PREVIEW_PIXELS,
        )
    with pytest.raises(media.MediaPreviewError) as frame_error:
        media.render_image_preview(
            animated.getvalue(),
            max_pixels=media.MAX_PREVIEW_PIXELS,
        )
    with pytest.raises(media.MediaPreviewError) as output_error:
        media.render_image_preview(
            _image_bytes("PNG", metadata=False),
            max_pixels=media.MAX_PREVIEW_PIXELS + 1,
        )

    assert dimension_error.value.code == "dimension_limit"
    assert frame_error.value.code == "frame_limit"
    assert output_error.value.code == "output_pixel_limit"


@pytest.mark.slow
def test_pdf_page_limit_accepts_exact_and_rejects_plus_one() -> None:
    """Catch a document over 500 pages entering the rasterizer."""
    pdf = importlib.import_module("memory.ui.pdf_render")

    exact = pdf.render_pdf_page(
        _pdf_bytes(pages=pdf.MAX_PDF_PAGES),
        page_number=pdf.MAX_PDF_PAGES,
        max_pixels=16_000_000,
    )
    with pytest.raises(Exception) as over:
        pdf.render_pdf_page(
            _pdf_bytes(pages=pdf.MAX_PDF_PAGES + 1),
            page_number=1,
            max_pixels=16_000_000,
        )

    assert exact.page_number == pdf.MAX_PDF_PAGES
    assert getattr(over.value, "code", None) == "pdf_page_limit"


def _worker_success(_source: bytes, output: Any) -> None:
    output.send_bytes(f"{os.getpid()}:synthetic-success".encode("ascii"))


def _worker_crash(_source: bytes, _output: Any) -> None:
    os._exit(23)


def _worker_block(_source: bytes, _output: Any) -> None:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(0.05)


def _worker_record_pid_and_block(_source: bytes, _output: Any) -> None:
    path = os.environ["PMS_SYNTHETIC_MEDIA_PID_PATH"]
    Path(path).write_text(str(os.getpid()))
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    while True:
        time.sleep(0.02)


def _worker_exact_ipc(_source: bytes, output: Any) -> None:
    output.send_bytes(b"x" * 1_024)


def _worker_over_ipc(_source: bytes, output: Any) -> None:
    output.send_bytes(b"x" * 1_025)


def _assert_reaped(pid: int) -> None:
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)


def _child_is_reaped(pid: int) -> bool:
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        return True
    return False


def test_spawn_worker_is_reaped_after_success_crash_timeout_and_cancellation() -> None:
    """Catch any preview exit path leaving a live or zombie child."""
    media = importlib.import_module("memory.ui.media_preview")
    success = media._run_spawn_worker(
        _worker_success,
        b"synthetic",
        timeout_seconds=1.0,
        max_result_bytes=1_024,
    )
    success_pid = int(success.payload.split(b":", 1)[0])
    assert success.payload.endswith(b"synthetic-success")
    _assert_reaped(success_pid)

    with pytest.raises(media.MediaWorkerError) as crashed:
        media._run_spawn_worker(
            _worker_crash,
            b"synthetic",
            timeout_seconds=1.0,
            max_result_bytes=1_024,
        )
    _assert_reaped(crashed.value.worker_pid)

    started = time.monotonic()
    with pytest.raises(media.MediaWorkerError) as timed_out:
        media._run_spawn_worker(
            _worker_block,
            b"synthetic",
            timeout_seconds=0.05,
            max_result_bytes=1_024,
        )
    assert time.monotonic() - started >= media.MEDIA_WORKER_JOIN_SECONDS
    _assert_reaped(timed_out.value.worker_pid)

    with pytest.raises(media.MediaWorkerError) as cancelled:
        media._run_spawn_worker(
            _worker_block,
            b"synthetic",
            timeout_seconds=1.0,
            max_result_bytes=1_024,
            cancelled=lambda: True,
        )
    _assert_reaped(cancelled.value.worker_pid)


def test_media_capacity_is_nonblocking_and_precedes_source_construction() -> None:
    """Catch preview queuing or worker-bound bytes retained above the global cap."""
    media = importlib.import_module("memory.ui.media_preview")
    entered = threading.Barrier(media.MAX_CONCURRENT_MEDIA_WORKERS + 1)
    release = threading.Event()
    loaded: list[str] = []

    def occupied_job(name: str) -> str:
        def load() -> bytes:
            loaded.append(name)
            return name.encode("ascii")

        def render(value: bytes) -> str:
            entered.wait(timeout=2)
            release.wait(timeout=2)
            return value.decode("ascii")

        return run_media_job(load, render)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(occupied_job, f"worker-{index}") for index in range(2)
        ]
        entered.wait(timeout=2)
        refused_loader_called = False

        def refused_loader() -> bytes:
            nonlocal refused_loader_called
            refused_loader_called = True
            return b"must-not-be-retained"

        with pytest.raises(media.MediaWorkerBusyError):
            run_media_job(refused_loader, lambda value: value)
        assert refused_loader_called is False
        assert sorted(loaded) == ["worker-0", "worker-1"]
        assert media.MAX_CONCURRENT_MEDIA_WORKERS * media.MEDIA_WORKER_MEMORY_BYTES == (
            1_073_741_824
        )
        release.set()
        assert sorted(future.result(timeout=2) for future in futures) == [
            "worker-0",
            "worker-1",
        ]

    assert run_media_job(lambda: b"retry", bytes.decode) == "retry"


def test_worker_memory_and_ipc_caps_fail_closed_at_limit_plus_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch worker memory or IPC budgets expanding past their hard maxima."""
    media = importlib.import_module("memory.ui.media_preview")
    monkeypatch.setattr(
        media,
        "MEDIA_WORKER_MEMORY_BYTES",
        536_870_913,
    )
    with pytest.raises(media.MediaWorkerError) as memory:
        media._run_spawn_worker(
            _worker_success,
            b"synthetic",
            timeout_seconds=1.0,
            max_result_bytes=1_024,
        )
    assert memory.value.code == "memory_limit"

    monkeypatch.setattr(media, "MEDIA_WORKER_MEMORY_BYTES", 536_870_912)

    exact = media._run_spawn_worker(
        _worker_exact_ipc,
        b"synthetic",
        timeout_seconds=1.0,
        max_result_bytes=1_024,
    )
    assert len(exact.payload) == 1_024

    with pytest.raises(media.MediaWorkerError) as ipc:
        media._run_spawn_worker(
            _worker_over_ipc,
            b"synthetic",
            timeout_seconds=1.0,
            max_result_bytes=1_024,
        )
    assert ipc.value.code == "ipc_limit"


@pytest.mark.parametrize(
    "source_id",
    [PNG_SOURCE_ID, JPEG_SOURCE_ID, WEBP_SOURCE_ID, PDF_SOURCE_ID],
)
def test_media_route_returns_only_new_png_without_download_or_original(
    source_id: str,
) -> None:
    """Catch original image/PDF bytes or download semantics escaping the UI."""
    ui = _authenticated_ui()
    response = ui.client.get(f"/sources/{source_id}/preview?page=1")
    original = ui.service.media[source_id][1]

    assert response.status_code == 200
    assert response.headers["content-type"] == "image/png"
    assert "content-disposition" not in response.headers
    assert response.content != original
    _decode_metadata_free_png(response.content)
    # `TestClient` keeps the app as the bare ASGI callable, and `create_ui_app`
    # registers every path as a plain `Route`.
    routes = cast("list[Route]", cast("Starlette", ui.client.app).routes)
    assert not any("download" in route.path for route in routes)


@pytest.mark.parametrize(
    "raw_page",
    [
        pytest.param("²", id="non-decimal-digit"),
        pytest.param("9" * 5_000, id="oversized-integer"),
    ],
)
def test_media_preview_refuses_unconvertible_numeric_pages(raw_page: str) -> None:
    """Catch a malformed preview page bypassing its content-free refusal."""
    ui = _authenticated_ui()

    response = ui.client.get(
        f"/sources/{PDF_SOURCE_ID}/preview", params={"page": raw_page}
    )

    assert response.status_code == 422
    assert response.text == "Preview unavailable"
    assert response.headers["cache-control"] == "no-store"


def test_unauthenticated_media_and_source_content_routes_fail_closed() -> None:
    """Catch active or original media routes bypassing the process session."""
    service = SyntheticInspectionService()
    bootstrap = "synthetic-unauthenticated-bootstrap"
    sessions = UiSessionStore(
        bootstrap_capability=bootstrap,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    app = create_ui_app(
        # The same deliberately partial fake `_authenticated_ui` casts: it
        # answers the `OwnerUiService` members these routes reach and no more.
        cast("OwnerUiService", service),
        sessions,
        _UnusedFinder(),
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    client = TestClient(app, base_url=PUBLIC_ORIGIN)

    assert client.get(f"/sources/{PNG_SOURCE_ID}").status_code == 401
    assert client.get(f"/sources/{PNG_SOURCE_ID}/preview").status_code == 401


def test_cancelled_image_route_reaps_child_before_cross_media_capacity_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch task cancellation abandoning a child while releasing its route task."""
    media = importlib.import_module("memory.ui.media_preview")
    pid_path = tmp_path / "synthetic-cancelled-image.pid"
    monkeypatch.setenv("PMS_SYNTHETIC_MEDIA_PID_PATH", os.fspath(pid_path))
    monkeypatch.setattr(media, "_image_worker", _worker_record_pid_and_block)
    monkeypatch.setattr(
        media, "MEDIA_WORKER_TIMEOUT_SECONDS", CANCELLED_WORKER_TIMEOUT_SECONDS
    )
    monkeypatch.setattr(media, "MEDIA_WORKER_JOIN_SECONDS", 0.15)

    service = SyntheticInspectionService()
    bootstrap = "synthetic-cancelled-image-bootstrap"
    sessions = UiSessionStore(
        bootstrap_capability=bootstrap,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    app = create_ui_app(
        # The same deliberately partial fake `_authenticated_ui` casts: it
        # answers the `OwnerUiService` members these routes reach and no more.
        cast("OwnerUiService", service),
        sessions,
        _UnusedFinder(),
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    anchor_entered = threading.Event()
    anchor_release = threading.Event()

    def occupy_one_permit() -> None:
        def blocked(_value: bytes) -> None:
            anchor_entered.set()
            anchor_release.wait(timeout=3)

        run_media_job(lambda: b"synthetic-anchor", blocked)

    executor = ThreadPoolExecutor(max_workers=1)
    anchor = executor.submit(occupy_one_permit)
    assert anchor_entered.wait(timeout=2)

    async def exercise() -> tuple[float, bool, int, int]:
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url=PUBLIC_ORIGIN,
        ) as client:
            exchanged = await client.post(
                "/session",
                content=bootstrap,
                headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
                follow_redirects=False,
            )
            assert exchanged.status_code == 303
            request_task = asyncio.create_task(
                client.get(f"/sources/{PNG_SOURCE_ID}/preview")
            )
            pid = await _wait_for_pid(pid_path)
            started = time.monotonic()
            request_task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await request_task
            elapsed = time.monotonic() - started
            reaped_before_return = _child_is_reaped(pid)
            retry = await client.get(f"/sources/{PDF_SOURCE_ID}/preview")
            cleanup_deadline = time.monotonic() + 2.0
            while not _child_is_reaped(pid) and time.monotonic() < cleanup_deadline:
                await asyncio.sleep(0.02)
            return elapsed, reaped_before_return, retry.status_code, pid

    try:
        elapsed, reaped_before_return, retry_status, pid = asyncio.run(exercise())
    finally:
        anchor_release.set()
        anchor.result(timeout=2)
        executor.shutdown(wait=True)

    assert elapsed < MAX_CANCELLED_RETURN_SECONDS
    assert reaped_before_return is True
    _assert_reaped(pid)
    assert retry_status == 200


def test_disconnected_pdf_route_reaps_child_before_cross_media_capacity_reuse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch an ASGI disconnect failing to reach a blocked PDF worker."""
    media = importlib.import_module("memory.ui.media_preview")
    pdf = importlib.import_module("memory.ui.pdf_render")
    pid_path = tmp_path / "synthetic-disconnected-pdf.pid"
    monkeypatch.setenv("PMS_SYNTHETIC_MEDIA_PID_PATH", os.fspath(pid_path))
    monkeypatch.setattr(pdf, "_pdf_worker", _worker_record_pid_and_block)
    monkeypatch.setattr(
        pdf, "MEDIA_WORKER_TIMEOUT_SECONDS", CANCELLED_WORKER_TIMEOUT_SECONDS
    )
    monkeypatch.setattr(media, "MEDIA_WORKER_JOIN_SECONDS", 0.15)

    service = SyntheticInspectionService()
    bootstrap = "synthetic-disconnected-pdf-bootstrap"
    sessions = UiSessionStore(
        bootstrap_capability=bootstrap,
        exact_host=EXACT_HOST,
        created_at_ns=time.monotonic_ns(),
    )
    app = create_ui_app(
        # The same deliberately partial fake `_authenticated_ui` casts: it
        # answers the `OwnerUiService` members these routes reach and no more.
        cast("OwnerUiService", service),
        sessions,
        _UnusedFinder(),
        build_test_orchestrator(service, sessions),
        public_origin=PUBLIC_ORIGIN,
    )
    anchor_entered = threading.Event()
    anchor_release = threading.Event()

    def occupy_one_permit() -> None:
        def blocked(_value: bytes) -> None:
            anchor_entered.set()
            anchor_release.wait(timeout=3)

        run_media_job(lambda: b"synthetic-anchor", blocked)

    executor = ThreadPoolExecutor(max_workers=1)
    anchor = executor.submit(occupy_one_permit)
    assert anchor_entered.wait(timeout=2)

    async def exercise() -> tuple[float, bool, int, bytes, int]:
        transport = httpx2.ASGITransport(app=app)
        async with httpx2.AsyncClient(
            transport=transport,
            base_url=PUBLIC_ORIGIN,
        ) as client:
            exchanged = await client.post(
                "/session",
                content=bootstrap,
                headers={"Origin": PUBLIC_ORIGIN, "Content-Type": "text/plain"},
                follow_redirects=False,
            )
            assert exchanged.status_code == 303
            cookie = client.cookies.get("memory_ui_session")
            assert cookie is not None
            received: asyncio.Queue[dict[str, object]] = asyncio.Queue()
            await received.put(
                {"type": "http.request", "body": b"", "more_body": False}
            )
            sent: list[dict[str, object]] = []

            async def receive() -> dict[str, object]:
                return await received.get()

            async def send(message: dict[str, object]) -> None:
                sent.append(message)

            scope: dict[str, object] = {
                "type": "http",
                "asgi": {"version": "3.0"},
                "http_version": "1.1",
                "method": "GET",
                "scheme": "http",
                "path": f"/sources/{PDF_SOURCE_ID}/preview",
                "raw_path": f"/sources/{PDF_SOURCE_ID}/preview".encode(),
                "query_string": b"page=1",
                "root_path": "",
                "headers": [
                    (b"host", EXACT_HOST.encode()),
                    (b"cookie", f"memory_ui_session={cookie}".encode()),
                ],
                "client": ("127.0.0.1", 54321),
                "server": ("127.0.0.1", 43210),
            }
            app_task = asyncio.create_task(app(scope, receive, send))  # type: ignore[arg-type]
            pid = await _wait_for_pid(pid_path)
            started = time.monotonic()
            await received.put({"type": "http.disconnect"})
            await app_task
            elapsed = time.monotonic() - started
            reaped_before_return = _child_is_reaped(pid)
            retry = await client.get(f"/sources/{PNG_SOURCE_ID}/preview")
            response_body = b"".join(
                body
                for message in sent
                if message.get("type") == "http.response.body"
                and isinstance(body := message.get("body", b""), bytes)
            )
            return elapsed, reaped_before_return, retry.status_code, response_body, pid

    try:
        elapsed, reaped_before_return, retry_status, response_body, pid = asyncio.run(
            exercise()
        )
    finally:
        anchor_release.set()
        anchor.result(timeout=2)
        executor.shutdown(wait=True)

    assert elapsed < MAX_CANCELLED_RETURN_SECONDS
    assert reaped_before_return is True
    _assert_reaped(pid)
    assert retry_status == 200
    assert PDF_SOURCE_ID.encode() not in response_body
    assert str(pid).encode() not in response_body


@pytest.mark.parametrize(
    ("kind", "media_type", "body"),
    [
        ("malformed", "image/png", b"not a synthetic image"),
        ("mismatch", "image/png", _image_bytes("JPEG")),
        (
            "polyglot",
            "image/png",
            _image_bytes("PNG") + b"<script>synthetic()</script>",
        ),
        (
            "jpeg-polyglot",
            "image/jpeg",
            _image_bytes("JPEG") + b"<script>synthetic()</script>\xff\xd9",
        ),
    ],
)
def test_failed_or_untrusted_image_preview_falls_back_to_complete_hex(
    kind: str,
    media_type: str,
    body: bytes,
) -> None:
    """Catch malformed, mismatched, or polyglot originals becoming active media."""
    service = SyntheticInspectionService()
    source_id = f"src_{kind[0] * 32}"
    service.media[source_id] = (media_type, body, f"synthetic-{kind}.bin")
    service.sources[source_id] = _source_summary(
        source_id,
        sensitivity=Sensitivity.RESTRICTED,
        media_type=media_type,
        name=f"synthetic-{kind}.bin",
        byte_length=len(body),
    )
    ui = _authenticated_ui(service)

    preview = ui.client.get(f"/sources/{source_id}/preview")
    detail = ui.client.get(f"/sources/{source_id}")

    assert preview.status_code == 422
    assert preview.text == "Preview unavailable"
    assert source_id not in preview.text
    assert detail.status_code == 200
    assert _hex_from_page(detail.text) == body
    assert "Original bytes remain available as inert hex/ASCII" in detail.text


def test_shared_image_pdf_capacity_returns_fixed_nonqueued_429_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Catch separate pools, queued previews, or source construction before capacity."""
    source_routes = importlib.import_module("memory.ui.routes.sources")
    service = SyntheticInspectionService()
    ui = _authenticated_ui(service)
    entered = threading.Barrier(3)
    release = threading.Event()

    def image_block(
        _source: bytes,
        *,
        max_pixels: int,
        cancelled: Callable[[], bool],
    ) -> ImagePreview:
        if not release.is_set():
            entered.wait(timeout=3)
            release.wait(timeout=3)
        return ImagePreview(
            width=1, height=1, png_bytes=_image_bytes("PNG", metadata=False)
        )

    def pdf_block(
        _source: bytes,
        *,
        page_number: int,
        max_pixels: int,
        cancelled: Callable[[], bool],
    ) -> PdfPageImage:
        if not release.is_set():
            entered.wait(timeout=3)
            release.wait(timeout=3)
        return PdfPageImage(
            page_number=page_number,
            width=1,
            height=1,
            png_bytes=_image_bytes("PNG", metadata=False),
        )

    monkeypatch.setattr(
        source_routes,
        "_render_image_preview_with_cancellation",
        image_block,
    )
    monkeypatch.setattr(
        source_routes,
        "_render_pdf_page_with_cancellation",
        pdf_block,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        image_future = executor.submit(
            ui.client.get,
            f"/sources/{PNG_SOURCE_ID}/preview",
        )
        pdf_future = executor.submit(
            ui.client.get,
            f"/sources/{PDF_SOURCE_ID}/preview?page=1",
        )
        entered.wait(timeout=3)
        reads_before = len(service.read_calls)
        refused = ui.client.get(f"/sources/{JPEG_SOURCE_ID}/preview")
        assert refused.status_code == 429
        assert refused.headers["retry-after"] == "1"
        assert refused.text == "Preview busy"
        assert JPEG_SOURCE_ID not in refused.text
        assert len(service.read_calls) == reads_before
        release.set()
        assert image_future.result(timeout=3).status_code == 200
        assert pdf_future.result(timeout=3).status_code == 200

    retry = ui.client.get(f"/sources/{JPEG_SOURCE_ID}/preview")
    assert retry.status_code == 200
