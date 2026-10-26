"""Process-isolated PDF rasterization for inert local owner previews."""

from __future__ import annotations

import math
import struct
from collections.abc import Callable
from dataclasses import dataclass
from multiprocessing.connection import Connection

import pypdfium2 as pdfium  # type: ignore[import-untyped]

from memory.ui.media_preview import (
    MAX_MEDIA_SOURCE_BYTES,
    MAX_PREVIEW_DIMENSION,
    MAX_PREVIEW_PIXELS,
    MAX_PREVIEW_PNG_BYTES,
    MEDIA_WORKER_TIMEOUT_SECONDS,
    MediaPreviewError,
    _canonical_png,
    _run_spawn_worker,
)

MAX_PDF_PAGES = 500
_ERROR_PREFIX = b"E\x00"
_SUCCESS_PREFIX = b"S\x00"
_PDF_WHITESPACE = b"\x00\x09\x0a\x0c\x0d\x20"
_PDF_HORIZONTAL_WHITESPACE = b"\x00\x09\x0c\x20"
_PDF_DELIMITERS = b"()<>[]{}/%"
_PDF_HEX_DIGITS = b"0123456789abcdefABCDEF"
_MAX_PDF_LEXICAL_DEPTH = 64
_MAX_PDF_DICTIONARY_TOKENS = 4_096
_MAX_PDF_TOKEN_BYTES = 1_024
_MAX_PDF_XREF_ENTRIES = 100_000
_MAX_PDF_XREF_SUBSECTIONS = 4_096
_MAX_PDF_XREF_HEADER_BYTES = 64
_MAX_PDF_INTEGER_BYTES = 20


@dataclass(frozen=True, slots=True)
class PdfPageImage:
    page_number: int
    width: int
    height: int
    png_bytes: bytes


@dataclass(slots=True)
class _PdfContext:
    kind: str
    tokens: list[tuple[str, bytes]]
    start: int


@dataclass(frozen=True, slots=True)
class _PdfDictionarySyntax:
    start: int
    end: int
    tokens: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True, slots=True)
class _PdfDictionaryEntry:
    key: bytes
    value_kind: str
    value: bytes


@dataclass(frozen=True, slots=True)
class _PdfObjectSyntax:
    offset: int
    object_number: int
    generation: int


@dataclass(frozen=True, slots=True)
class _PdfXrefEntry:
    offset: int
    generation: int
    in_use: bool


@dataclass(frozen=True, slots=True)
class _PdfSyntax:
    eof_positions: tuple[int, ...]
    startxref_positions: tuple[int, ...]
    table_xref_positions: tuple[int, ...]
    xref_stream_positions: tuple[int, ...]
    top_level_dictionaries: tuple[_PdfDictionarySyntax, ...]
    indirect_objects: tuple[_PdfObjectSyntax, ...]
    terminal_prev: bool
    terminal_xref_stm: bool


def _is_pdf_boundary(value: int) -> bool:
    return value in _PDF_WHITESPACE or value in _PDF_DELIMITERS


def _append_dictionary_token(
    contexts: list[_PdfContext],
    kind: str,
    value: bytes = b"",
) -> None:
    if not contexts or contexts[-1].kind != "dictionary":
        return
    tokens = contexts[-1].tokens
    if len(tokens) >= _MAX_PDF_DICTIONARY_TOKENS:
        raise MediaPreviewError("invalid_pdf_framing")
    tokens.append((kind, value))


def _skip_literal_string(source: bytes, position: int) -> int:
    depth = 1
    position += 1
    while position < len(source):
        value = source[position]
        if value == 0x5C:
            position += 1
            if position >= len(source):
                raise MediaPreviewError("invalid_pdf_framing")
            if source[position] == 0x0D:
                position += 1
                if position < len(source) and source[position] == 0x0A:
                    position += 1
            elif source[position] == 0x0A:
                position += 1
            else:
                position += 1
            continue
        if value == 0x28:
            depth += 1
            if depth > _MAX_PDF_LEXICAL_DEPTH:
                raise MediaPreviewError("invalid_pdf_framing")
        elif value == 0x29:
            depth -= 1
            if depth == 0:
                return position + 1
        position += 1
    raise MediaPreviewError("invalid_pdf_framing")


def _skip_hex_string(source: bytes, position: int) -> int:
    position += 1
    while position < len(source):
        value = source[position]
        if value == 0x3E:
            return position + 1
        if value not in _PDF_WHITESPACE and value not in _PDF_HEX_DIGITS:
            raise MediaPreviewError("invalid_pdf_framing")
        position += 1
    raise MediaPreviewError("invalid_pdf_framing")


def _read_name(source: bytes, position: int) -> tuple[bytes, int]:
    position += 1
    end = position
    while end < len(source) and not _is_pdf_boundary(source[end]):
        end += 1
        if end - position > _MAX_PDF_TOKEN_BYTES:
            raise MediaPreviewError("invalid_pdf_framing")
    raw = source[position:end]
    decoded = bytearray()
    index = 0
    while index < len(raw):
        if raw[index] != 0x23:
            decoded.append(raw[index])
            index += 1
            continue
        if index + 2 >= len(raw):
            raise MediaPreviewError("invalid_pdf_framing")
        escaped = raw[index + 1 : index + 3]
        if any(value not in _PDF_HEX_DIGITS for value in escaped):
            raise MediaPreviewError("invalid_pdf_framing")
        decoded.append(int(escaped, 16))
        index += 3
    return bytes(decoded), end


def _read_word(source: bytes, position: int) -> tuple[bytes, int]:
    end = position
    while end < len(source) and not _is_pdf_boundary(source[end]):
        end += 1
        if end - position > _MAX_PDF_TOKEN_BYTES:
            raise MediaPreviewError("invalid_pdf_framing")
    if end == position:
        raise MediaPreviewError("invalid_pdf_framing")
    return source[position:end], end


def _direct_dictionary_entries(
    tokens: tuple[tuple[str, bytes], ...],
) -> tuple[_PdfDictionaryEntry, ...]:
    """Derive bounded direct key/value roles from one scanned dictionary."""
    entries: list[_PdfDictionaryEntry] = []
    seen_keys: set[bytes] = set()
    index = 0
    while index < len(tokens):
        key_kind, key = tokens[index]
        if key_kind != "name" or key in seen_keys:
            raise MediaPreviewError("invalid_pdf_framing")
        seen_keys.add(key)
        index += 1
        if index >= len(tokens):
            raise MediaPreviewError("invalid_pdf_framing")

        value_kind, value = tokens[index]
        if (
            value_kind == "word"
            and value.isdigit()
            and index + 2 < len(tokens)
            and tokens[index + 1][0] == "word"
            and tokens[index + 1][1].isdigit()
            and tokens[index + 2] == ("word", b"R")
        ):
            if (
                len(value) > _MAX_PDF_INTEGER_BYTES
                or len(tokens[index + 1][1]) > _MAX_PDF_INTEGER_BYTES
            ):
                raise MediaPreviewError("invalid_pdf_framing")
            value_kind = "reference"
            value = b""
            index += 3
        else:
            index += 1
        entries.append(
            _PdfDictionaryEntry(
                key=key,
                value_kind=value_kind,
                value=value,
            )
        )
    return tuple(entries)


def _direct_dictionary_integer(
    entries: tuple[_PdfDictionaryEntry, ...],
    key: bytes,
) -> int:
    matches = [entry for entry in entries if entry.key == key]
    if len(matches) != 1:
        raise MediaPreviewError("invalid_pdf_framing")
    match = matches[0]
    if (
        match.value_kind != "word"
        or not match.value.isdigit()
        or len(match.value) > _MAX_PDF_INTEGER_BYTES
    ):
        raise MediaPreviewError("invalid_pdf_framing")
    return int(match.value)


def _direct_dictionary_has_key(
    entries: tuple[_PdfDictionaryEntry, ...],
    key: bytes,
) -> bool:
    return any(entry.key == key for entry in entries)


def _dictionary_has_name_value(
    entries: tuple[_PdfDictionaryEntry, ...],
    key: bytes,
    value: bytes,
) -> bool:
    return any(
        entry.key == key and entry.value_kind == "name" and entry.value == value
        for entry in entries
    )


def _stream_data_start(source: bytes, position: int) -> int:
    if source[position : position + 2] == b"\r\n":
        return position + 2
    if source[position : position + 1] in {b"\r", b"\n"}:
        return position + 1
    raise MediaPreviewError("invalid_pdf_framing")


def _endstream_end(source: bytes, position: int) -> int:
    if source[position : position + 2] == b"\r\n":
        position += 2
    elif source[position : position + 1] in {b"\r", b"\n"}:
        position += 1
    keyword = b"endstream"
    if source[position : position + len(keyword)] != keyword:
        raise MediaPreviewError("invalid_pdf_framing")
    end = position + len(keyword)
    if end < len(source) and not _is_pdf_boundary(source[end]):
        raise MediaPreviewError("invalid_pdf_framing")
    return end


def _effective_eof_comment(source: bytes, position: int) -> bool:
    marker = b"%%EOF"
    if source[position : position + len(marker)] != marker:
        return False
    after_marker = position + len(marker)
    if after_marker < len(source) and source[after_marker] not in _PDF_WHITESPACE:
        return False
    line_start = max(source.rfind(b"\n", 0, position), source.rfind(b"\r", 0, position))
    if any(
        value not in _PDF_HORIZONTAL_WHITESPACE
        for value in source[line_start + 1 : position]
    ):
        return False
    line_end = after_marker
    while line_end < len(source) and source[line_end] not in {0x0A, 0x0D}:
        if source[line_end] not in _PDF_HORIZONTAL_WHITESPACE:
            return False
        line_end += 1
    return True


def _scan_pdf_syntax(
    source: bytes,
    *,
    xref_offset: int,
    startxref: int,
) -> _PdfSyntax:
    contexts: list[_PdfContext] = []
    eof_positions: list[int] = []
    startxref_positions: list[int] = []
    table_xref_positions: list[int] = []
    xref_stream_positions: list[int] = []
    top_level_dictionaries: list[_PdfDictionarySyntax] = []
    indirect_objects: list[_PdfObjectSyntax] = []
    terminal_prev = False
    terminal_xref_stm = False
    last_dictionary: _PdfDictionarySyntax | None = None
    last_significant_was_dictionary = False
    inside_object = False
    object_header_words: list[tuple[bytes, int]] = []
    object_offset: int | None = None

    def record_xref(position: int, positions: list[int]) -> None:
        positions.append(position)
        if len(table_xref_positions) + len(xref_stream_positions) > 2:
            raise MediaPreviewError("invalid_pdf_framing")

    position = 0
    while position < len(source):
        value = source[position]
        if value in _PDF_WHITESPACE:
            position += 1
            continue
        if value == 0x25:
            if (
                not contexts
                and not inside_object
                and _effective_eof_comment(source, position)
            ):
                eof_positions.append(position)
                if len(eof_positions) > 2:
                    raise MediaPreviewError("invalid_pdf_framing")
            line_feed = source.find(b"\n", position)
            carriage_return = source.find(b"\r", position)
            endings = tuple(
                ending for ending in (line_feed, carriage_return) if ending >= 0
            )
            position = min(endings) if endings else len(source)
            continue
        if value == 0x28:
            _append_dictionary_token(contexts, "value")
            position = _skip_literal_string(source, position)
            last_significant_was_dictionary = False
            if not inside_object:
                object_header_words.clear()
            continue
        if source[position : position + 2] == b"<<":
            _append_dictionary_token(contexts, "value")
            if len(contexts) >= _MAX_PDF_LEXICAL_DEPTH:
                raise MediaPreviewError("invalid_pdf_framing")
            contexts.append(_PdfContext(kind="dictionary", tokens=[], start=position))
            position += 2
            last_significant_was_dictionary = False
            if len(contexts) == 1 and not inside_object:
                object_header_words.clear()
            continue
        if source[position : position + 2] == b">>":
            if not contexts or contexts[-1].kind != "dictionary":
                raise MediaPreviewError("invalid_pdf_framing")
            closed = contexts.pop()
            position += 2
            if not contexts:
                last_dictionary = _PdfDictionarySyntax(
                    start=closed.start,
                    end=position,
                    tokens=tuple(closed.tokens),
                )
                last_significant_was_dictionary = True
                if not inside_object:
                    top_level_dictionaries.append(last_dictionary)
                    if len(top_level_dictionaries) > 2:
                        raise MediaPreviewError("invalid_pdf_framing")
            continue
        if value == 0x3C:
            _append_dictionary_token(contexts, "value")
            position = _skip_hex_string(source, position)
            last_significant_was_dictionary = False
            if not inside_object:
                object_header_words.clear()
            continue
        if value == 0x3E:
            raise MediaPreviewError("invalid_pdf_framing")
        if value == 0x5B:
            _append_dictionary_token(contexts, "value")
            if len(contexts) >= _MAX_PDF_LEXICAL_DEPTH:
                raise MediaPreviewError("invalid_pdf_framing")
            contexts.append(_PdfContext(kind="array", tokens=[], start=position))
            position += 1
            last_significant_was_dictionary = False
            if len(contexts) == 1 and not inside_object:
                object_header_words.clear()
            continue
        if value == 0x5D:
            if not contexts or contexts[-1].kind != "array":
                raise MediaPreviewError("invalid_pdf_framing")
            contexts.pop()
            position += 1
            last_significant_was_dictionary = False
            continue
        if value == 0x2F:
            name, position = _read_name(source, position)
            _append_dictionary_token(contexts, "name", name)
            last_significant_was_dictionary = False
            if not inside_object and not contexts:
                object_header_words.clear()
            continue

        word_position = position
        word, position = _read_word(source, position)
        if not contexts and word == b"stream":
            if (
                not inside_object
                or not last_significant_was_dictionary
                or last_dictionary is None
            ):
                raise MediaPreviewError("invalid_pdf_framing")
            dictionary_entries = _direct_dictionary_entries(last_dictionary.tokens)
            length = _direct_dictionary_integer(dictionary_entries, b"Length")
            data_start = _stream_data_start(source, position)
            data_end = data_start + length
            if data_end > len(source):
                raise MediaPreviewError("invalid_pdf_framing")
            position = _endstream_end(source, data_end)
            if _dictionary_has_name_value(
                dictionary_entries,
                b"Type",
                b"XRef",
            ):
                if object_offset is None:
                    raise MediaPreviewError("invalid_pdf_framing")
                record_xref(object_offset, xref_stream_positions)
                terminal_prev = terminal_prev or _direct_dictionary_has_key(
                    dictionary_entries,
                    b"Prev",
                )
                terminal_xref_stm = terminal_xref_stm or _direct_dictionary_has_key(
                    dictionary_entries,
                    b"XRefStm",
                )
            last_dictionary = None
            last_significant_was_dictionary = False
            continue
        _append_dictionary_token(contexts, "word", word)
        if not contexts:
            if inside_object and word == b"endobj":
                inside_object = False
                object_offset = None
                object_header_words.clear()
            elif not inside_object and word == b"obj":
                if len(object_header_words) != 2 or not all(
                    item[0].isdigit() for item in object_header_words
                ):
                    raise MediaPreviewError("invalid_pdf_framing")
                object_number_raw = object_header_words[0][0]
                generation_raw = object_header_words[1][0]
                if (
                    len(object_number_raw) > _MAX_PDF_INTEGER_BYTES
                    or len(generation_raw) > _MAX_PDF_INTEGER_BYTES
                ):
                    raise MediaPreviewError("invalid_pdf_framing")
                object_number = int(object_number_raw)
                generation = int(generation_raw)
                if object_number >= _MAX_PDF_XREF_ENTRIES or generation > 65_535:
                    raise MediaPreviewError("invalid_pdf_framing")
                inside_object = True
                object_offset = object_header_words[0][1]
                indirect_objects.append(
                    _PdfObjectSyntax(
                        offset=object_offset,
                        object_number=object_number,
                        generation=generation,
                    )
                )
                if len(indirect_objects) > _MAX_PDF_XREF_ENTRIES:
                    raise MediaPreviewError("invalid_pdf_framing")
                object_header_words.clear()
            elif not inside_object and word == b"xref":
                record_xref(word_position, table_xref_positions)
                object_header_words.clear()
            elif not inside_object and word == b"startxref":
                startxref_positions.append(word_position)
                if len(startxref_positions) > 2:
                    raise MediaPreviewError("invalid_pdf_framing")
                object_header_words.clear()
            elif not inside_object:
                if word.isdigit():
                    object_header_words.append((word, word_position))
                    del object_header_words[:-2]
                else:
                    object_header_words.clear()
        last_significant_was_dictionary = False

    if contexts or inside_object:
        raise MediaPreviewError("invalid_pdf_framing")
    return _PdfSyntax(
        eof_positions=tuple(eof_positions),
        startxref_positions=tuple(startxref_positions),
        table_xref_positions=tuple(table_xref_positions),
        xref_stream_positions=tuple(xref_stream_positions),
        top_level_dictionaries=tuple(top_level_dictionaries),
        indirect_objects=tuple(indirect_objects),
        terminal_prev=terminal_prev,
        terminal_xref_stm=terminal_xref_stm,
    )


def _read_bounded_pdf_line(
    source: bytes,
    position: int,
    *,
    limit: int,
    max_bytes: int,
) -> tuple[bytes, int]:
    line_end = position
    while line_end < limit and source[line_end] not in {0x0A, 0x0D}:
        line_end += 1
        if line_end - position > max_bytes:
            raise MediaPreviewError("invalid_pdf_framing")
    if line_end >= limit:
        raise MediaPreviewError("invalid_pdf_framing")
    if source[line_end : line_end + 2] == b"\r\n":
        next_position = line_end + 2
    else:
        next_position = line_end + 1
    if next_position > limit:
        raise MediaPreviewError("invalid_pdf_framing")
    return source[position:line_end], next_position


def _split_xref_header(line: bytes) -> tuple[bytes, bytes]:
    words: list[bytes] = []
    position = 0
    while position < len(line):
        while position < len(line) and line[position] in _PDF_HORIZONTAL_WHITESPACE:
            position += 1
        if position == len(line):
            break
        start = position
        while position < len(line) and line[position] not in _PDF_HORIZONTAL_WHITESPACE:
            position += 1
        words.append(line[start:position])
        if len(words) > 2:
            raise MediaPreviewError("invalid_pdf_framing")
    if (
        len(words) != 2
        or any(not word.isdigit() for word in words)
        or any(len(word) > _MAX_PDF_INTEGER_BYTES for word in words)
    ):
        raise MediaPreviewError("invalid_pdf_framing")
    return words[0], words[1]


def _read_classic_xref_entry(
    source: bytes,
    position: int,
    *,
    limit: int,
) -> tuple[_PdfXrefEntry, int]:
    end = position + 20
    if end > limit:
        raise MediaPreviewError("invalid_pdf_framing")
    raw = source[position:end]
    if (
        not raw[:10].isdigit()
        or raw[10] != 0x20
        or not raw[11:16].isdigit()
        or raw[16] != 0x20
        or raw[17] not in {0x66, 0x6E}
        or not (raw[18:20] == b"\r\n" or (raw[18] == 0x20 and raw[19] in {0x0A, 0x0D}))
    ):
        raise MediaPreviewError("invalid_pdf_framing")
    generation = int(raw[11:16])
    if generation > 65_535:
        raise MediaPreviewError("invalid_pdf_framing")
    return (
        _PdfXrefEntry(
            offset=int(raw[:10]),
            generation=generation,
            in_use=raw[17] == 0x6E,
        ),
        end,
    )


def _validate_classic_xref_table(
    source: bytes,
    *,
    xref_offset: int,
    startxref: int,
    syntax: _PdfSyntax,
) -> None:
    """Accept only the bounded single-revision classic-table preview subset."""
    keyword_end = xref_offset + len(b"xref")
    if source[xref_offset:keyword_end] != b"xref":
        raise MediaPreviewError("invalid_pdf_framing")
    keyword_tail, position = _read_bounded_pdf_line(
        source,
        keyword_end,
        limit=startxref,
        max_bytes=_MAX_PDF_XREF_HEADER_BYTES,
    )
    if any(value not in _PDF_HORIZONTAL_WHITESPACE for value in keyword_tail):
        raise MediaPreviewError("invalid_pdf_framing")

    entries: dict[int, _PdfXrefEntry] = {}
    subsection_count = 0
    trailer_position: int | None = None
    trailer_line_end: int | None = None
    while position < startxref:
        line_start = position
        line, position = _read_bounded_pdf_line(
            source,
            position,
            limit=startxref,
            max_bytes=_MAX_PDF_XREF_HEADER_BYTES,
        )
        if line == b"trailer":
            trailer_position = line_start
            trailer_line_end = position
            break
        first_raw, count_raw = _split_xref_header(line)
        first_object = int(first_raw)
        count = int(count_raw)
        subsection_count += 1
        if (
            count == 0
            or subsection_count > _MAX_PDF_XREF_SUBSECTIONS
            or first_object >= _MAX_PDF_XREF_ENTRIES
            or count > _MAX_PDF_XREF_ENTRIES
            or first_object + count > _MAX_PDF_XREF_ENTRIES
            or len(entries) + count > _MAX_PDF_XREF_ENTRIES
        ):
            raise MediaPreviewError("invalid_pdf_framing")
        for object_number in range(first_object, first_object + count):
            if object_number in entries:
                raise MediaPreviewError("invalid_pdf_framing")
            entry, position = _read_classic_xref_entry(
                source,
                position,
                limit=startxref,
            )
            entries[object_number] = entry

    if trailer_position is None or trailer_line_end is None:
        raise MediaPreviewError("invalid_pdf_framing")
    if len(syntax.top_level_dictionaries) != 1:
        raise MediaPreviewError("invalid_pdf_framing")
    trailer = syntax.top_level_dictionaries[0]
    dictionary_start = trailer_line_end
    while dictionary_start < startxref and source[dictionary_start] in _PDF_WHITESPACE:
        dictionary_start += 1
    if trailer.start != dictionary_start or trailer.end > startxref:
        raise MediaPreviewError("invalid_pdf_framing")
    if any(value not in _PDF_WHITESPACE for value in source[trailer.end : startxref]):
        raise MediaPreviewError("invalid_pdf_framing")
    trailer_entries = _direct_dictionary_entries(trailer.tokens)
    if _direct_dictionary_has_key(
        trailer_entries,
        b"Prev",
    ) or _direct_dictionary_has_key(
        trailer_entries,
        b"XRefStm",
    ):
        raise MediaPreviewError("invalid_pdf_framing")

    size = _direct_dictionary_integer(trailer_entries, b"Size")
    if size == 0 or size > _MAX_PDF_XREF_ENTRIES:
        raise MediaPreviewError("invalid_pdf_framing")
    if len(entries) != size or set(entries) != set(range(size)):
        raise MediaPreviewError("invalid_pdf_framing")

    object_zero = entries[0]
    if object_zero.in_use or object_zero.generation != 65_535:
        raise MediaPreviewError("invalid_pdf_framing")
    free_objects = {
        object_number for object_number, entry in entries.items() if not entry.in_use
    }
    for entry in entries.values():
        if not entry.in_use and entry.offset >= size:
            raise MediaPreviewError("invalid_pdf_framing")

    linked_free_objects = {0}
    next_free = object_zero.offset
    while next_free != 0:
        if next_free in linked_free_objects:
            raise MediaPreviewError("invalid_pdf_framing")
        linked_entry = entries.get(next_free)
        if linked_entry is None or linked_entry.in_use:
            raise MediaPreviewError("invalid_pdf_framing")
        linked_free_objects.add(next_free)
        next_free = linked_entry.offset
    if linked_free_objects != free_objects:
        raise MediaPreviewError("invalid_pdf_framing")

    expected_objects = {
        (entry.offset, object_number, entry.generation)
        for object_number, entry in entries.items()
        if entry.in_use
    }
    if any(entry.offset >= xref_offset for entry in entries.values() if entry.in_use):
        raise MediaPreviewError("invalid_pdf_framing")
    scanned_objects = {
        (item.offset, item.object_number, item.generation)
        for item in syntax.indirect_objects
    }
    if scanned_objects != expected_objects:
        raise MediaPreviewError("invalid_pdf_framing")


def _validate_pdf_framing(source: bytes) -> None:
    """Require one exact PDF envelope before handing bytes to PDFium."""
    if not source.startswith(b"%PDF-"):
        raise MediaPreviewError("invalid_pdf_framing")
    framed = source.rstrip(_PDF_WHITESPACE)
    if not framed.endswith(b"%%EOF"):
        raise MediaPreviewError("invalid_pdf_framing")

    eof_start = len(framed) - len(b"%%EOF")
    startxref = framed.rfind(b"startxref", 0, eof_start)
    if startxref < 0:
        raise MediaPreviewError("invalid_pdf_framing")
    offset_token = framed[startxref + len(b"startxref") : eof_start].strip(
        _PDF_WHITESPACE
    )
    if not offset_token or len(offset_token) > 20 or not offset_token.isdigit():
        raise MediaPreviewError("invalid_pdf_framing")
    xref_offset = int(offset_token)
    if xref_offset >= startxref:
        raise MediaPreviewError("invalid_pdf_framing")

    syntax = _scan_pdf_syntax(
        framed,
        xref_offset=xref_offset,
        startxref=startxref,
    )
    if (
        syntax.eof_positions != (eof_start,)
        or syntax.startxref_positions != (startxref,)
        or syntax.terminal_prev
        or syntax.terminal_xref_stm
    ):
        raise MediaPreviewError("invalid_pdf_framing")

    structural_xrefs = syntax.table_xref_positions + syntax.xref_stream_positions
    if structural_xrefs != (xref_offset,):
        raise MediaPreviewError("invalid_pdf_framing")
    if syntax.table_xref_positions:
        _validate_classic_xref_table(
            framed,
            xref_offset=xref_offset,
            startxref=startxref,
            syntax=syntax,
        )


def _pdf_worker(source_envelope: bytes, output: Connection) -> None:
    try:
        page_number, max_pixels = struct.unpack(">II", source_envelope[:8])
        source = source_envelope[8:]
        _validate_pdf_framing(source)
        document = pdfium.PdfDocument(source)
        try:
            page_count = len(document)
            if page_count > MAX_PDF_PAGES:
                raise MediaPreviewError("pdf_page_limit")
            if page_number < 1 or page_number > page_count:
                raise MediaPreviewError("pdf_page_invalid")
            page = document[page_number - 1]
            try:
                page_width, page_height = page.get_size()
                if page_width <= 0 or page_height <= 0:
                    raise MediaPreviewError("invalid_media")
                scale = min(
                    2.0,
                    MAX_PREVIEW_DIMENSION / page_width,
                    MAX_PREVIEW_DIMENSION / page_height,
                    math.sqrt(max_pixels / (page_width * page_height)),
                )
                bitmap = page.render(scale=max(scale, 0.01))
                try:
                    image = bitmap.to_pil()
                    width, height = image.size
                    if (
                        width > MAX_PREVIEW_DIMENSION
                        or height > MAX_PREVIEW_DIMENSION
                        or width * height > max_pixels
                    ):
                        raise MediaPreviewError("output_pixel_limit")
                    png = _canonical_png(image)
                finally:
                    bitmap.close()
            finally:
                page.close()
        finally:
            document.close()
        payload = _SUCCESS_PREFIX + struct.pack(">II", width, height) + png
    except MediaPreviewError as error:
        payload = _ERROR_PREFIX + error.code.encode("ascii", errors="ignore")
    except Exception:
        payload = _ERROR_PREFIX + b"invalid_media"
    output.send_bytes(payload)


def _render_pdf_page(
    source_bytes: bytes,
    *,
    page_number: int,
    max_pixels: int,
    cancelled: Callable[[], bool] | None,
) -> PdfPageImage:
    """Rasterize exactly one bounded page without exposing the PDF to a browser."""
    if len(source_bytes) > MAX_MEDIA_SOURCE_BYTES:
        raise MediaPreviewError("source_too_large")
    if max_pixels <= 0 or max_pixels > MAX_PREVIEW_PIXELS:
        raise MediaPreviewError("output_pixel_limit")
    envelope = struct.pack(">II", page_number, max_pixels) + source_bytes
    result = _run_spawn_worker(
        _pdf_worker,
        envelope,
        timeout_seconds=MEDIA_WORKER_TIMEOUT_SECONDS,
        max_result_bytes=MAX_PREVIEW_PNG_BYTES + 10,
        cancelled=cancelled,
    )
    if result.payload.startswith(_ERROR_PREFIX):
        code = result.payload[len(_ERROR_PREFIX) :].decode("ascii")
        raise MediaPreviewError(code or "invalid_media")
    if not result.payload.startswith(_SUCCESS_PREFIX) or len(result.payload) < 10:
        raise MediaPreviewError("invalid_media")
    width, height = struct.unpack(">II", result.payload[2:10])
    return PdfPageImage(
        page_number=page_number,
        width=width,
        height=height,
        png_bytes=result.payload[10:],
    )


def render_pdf_page(
    source_bytes: bytes,
    *,
    page_number: int,
    max_pixels: int,
) -> PdfPageImage:
    """Rasterize exactly one bounded page without exposing the PDF to a browser."""
    return _render_pdf_page(
        source_bytes,
        page_number=page_number,
        max_pixels=max_pixels,
        cancelled=None,
    )


def _render_pdf_page_with_cancellation(
    source_bytes: bytes,
    *,
    page_number: int,
    max_pixels: int,
    cancelled: Callable[[], bool],
) -> PdfPageImage:
    return _render_pdf_page(
        source_bytes,
        page_number=page_number,
        max_pixels=max_pixels,
        cancelled=cancelled,
    )


# Kept as a descriptive type alias for callers that do not need page semantics.
PdfPreview = PdfPageImage
