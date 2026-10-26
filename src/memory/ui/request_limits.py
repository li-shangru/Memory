"""Central byte and structure budgets for the local owner UI."""

from __future__ import annotations

import urllib.parse
from collections.abc import AsyncIterable, AsyncIterator, Callable, Iterable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

import python_multipart
from python_multipart.multipart import parse_options_header
from starlette.types import Receive

if TYPE_CHECKING:
    from python_multipart.multipart import MultipartCallbacks

from memory.errors import InvalidArgumentError, RequestLimitError
from memory.inbox import MAX_BATCH_FILES
from memory.retrieval import MAX_QUERY_BYTES
from memory.reviews import (
    MAX_CHANGE_ITEMS,
    MAX_DIFF_BYTES,
    MAX_EDIT_OPERATIONS,
    MAX_EVIDENCE_EXCERPT_BYTES,
    MAX_EVIDENCE_PER_ITEM,
    MAX_GUARD_LINKS,
    MAX_NO_MEMORY_REASON_BYTES,
    MAX_STATEMENT_BYTES,
    MAX_TAG_BYTES,
    MAX_TAGS,
)
from memory.ui.view_models import OWNER_REVIEW_ITEM_PAGE_LIMIT
from memory.validation import require_invariant

MAX_CONTROL_FORM_BODY_BYTES = 3 * (MAX_QUERY_BYTES + MAX_TAGS * MAX_TAG_BYTES) + 65_536
MAX_REVIEW_EDIT_BODY_BYTES = 524_288
MAX_CORRECTION_FORM_BODY_BYTES = 3_211_264
MAX_UPLOAD_FILE_BYTES = 67_108_864
MAX_UPLOAD_REQUEST_BYTES = 67_174_400
MAX_MULTIPART_HEADER_BYTES = 8_192
MAX_MULTIPART_PARTS = 2
MAX_UPLOAD_FILES = 1
MAX_UPLOAD_FILENAME_BYTES = 255
MAX_FORM_FIELDS = 160
MAX_CONTROL_FORM_FIELD_BYTES = 16_384
MAX_REVIEW_FORM_FIELD_BYTES = 65_536
MAX_CORRECTION_TEXT_BYTES = 1_048_576

MAX_STANDARD_HTML_RESPONSE_BYTES = 4_194_304
STANDARD_PAGE_CHROME_BYTES = 262_144
MAX_ESCAPED_HTML_EXPANSION = 5
MAX_STANDARD_LIST_ROW_HTML_BYTES = 65_536
MAX_CORRECTION_HTML_RESPONSE_BYTES = (
    STANDARD_PAGE_CHROME_BYTES + 5 * MAX_CORRECTION_TEXT_BYTES + 65_536
)
UI_STANDARD_PAGE_LIMIT = min(
    50,
    (MAX_STANDARD_HTML_RESPONSE_BYTES - STANDARD_PAGE_CHROME_BYTES)
    // MAX_STANDARD_LIST_ROW_HTML_BYTES,
)
MAX_ESCAPED_MEMORY_SUMMARY_BYTES = 5 * (
    MAX_STATEMENT_BYTES + MAX_TAGS * MAX_TAG_BYTES + 4_096
)
UI_MEMORY_PAGE_LIMIT = (
    MAX_STANDARD_HTML_RESPONSE_BYTES - STANDARD_PAGE_CHROME_BYTES
) // MAX_ESCAPED_MEMORY_SUMMARY_BYTES
# Both relationship directions use small statement previews in the owner UI.
# Bound the SQL selection as well as the rendered roster; outgoing links have
# no lifetime count ceiling in the Store.
UI_MEMORY_RELATION_PAGE_LIMIT = 50
MAX_REVIEW_GUARD_CHANGES_PER_ITEM = 12
MAX_REVIEW_GUARD_CHANGE_TEXT_BYTES = 1_024
MAX_ESCAPED_REVIEW_ITEM_HTML_BYTES = 5 * (
    2
    * (
        MAX_STATEMENT_BYTES
        + MAX_TAGS * MAX_TAG_BYTES
        + MAX_EVIDENCE_PER_ITEM * (MAX_EVIDENCE_EXCERPT_BYTES + 512)
    )
    + MAX_NO_MEMORY_REASON_BYTES
    + MAX_REVIEW_GUARD_CHANGES_PER_ITEM * MAX_REVIEW_GUARD_CHANGE_TEXT_BYTES
    + 32_768
)
UI_REVIEW_ITEM_PAGE_LIMIT = OWNER_REVIEW_ITEM_PAGE_LIMIT
require_invariant(
    UI_REVIEW_ITEM_PAGE_LIMIT
    <= (MAX_STANDARD_HTML_RESPONSE_BYTES - STANDARD_PAGE_CHROME_BYTES)
    // MAX_ESCAPED_REVIEW_ITEM_HTML_BYTES,
    label="owner review item page budget",
)
MAX_REVIEW_ROSTER_ROW_HTML_BYTES = 4_096
MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES = MAX_STANDARD_HTML_RESPONSE_BYTES
MAX_FINAL_APPROVAL_RENDERED_REVIEW_BYTES = MAX_ESCAPED_HTML_EXPANSION * (
    MAX_DIFF_BYTES + 128
)
MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES = (
    STANDARD_PAGE_CHROME_BYTES
    + MAX_FINAL_APPROVAL_RENDERED_REVIEW_BYTES
    + (MAX_CHANGE_ITEMS + MAX_BATCH_FILES + 2 * MAX_GUARD_LINKS)
    * MAX_REVIEW_ROSTER_ROW_HTML_BYTES
)
require_invariant(
    STANDARD_PAGE_CHROME_BYTES
    + MAX_FINAL_APPROVAL_RENDERED_REVIEW_BYTES
    + (MAX_CHANGE_ITEMS + MAX_BATCH_FILES + 2 * MAX_GUARD_LINKS)
    * MAX_REVIEW_ROSTER_ROW_HTML_BYTES
    <= MAX_FINAL_APPROVAL_HTML_RESPONSE_BYTES,
    label="final approval complete-review budget",
)
# One selection of draft items rejected or restored in a single submission.
# `expected_digest` rides in the same body, so a selection filling the field
# budget is one field short of it -- which is also where a larger selection is
# refused, by the parser, before anything is allocated. The kernel's own
# ceilings sit above this: a revision carries at most MAX_CHANGE_ITEMS items
# and one edit call at most MAX_EDIT_OPERATIONS operations, so a bulk form can
# never ask for more than a single revision may hold.
MAX_BULK_REVIEW_ITEM_IDS = MAX_FORM_FIELDS - 1
require_invariant(
    MAX_BULK_REVIEW_ITEM_IDS <= min(MAX_CHANGE_ITEMS, MAX_EDIT_OPERATIONS),
    label="bulk review selection ceiling",
)
# One refused edit is carried back to its form in process memory, so its
# submitted bytes are budgeted twice: once repopulating the controls and once
# listing what was kept. The budget clears the largest edit the form can
# legitimately hold, and a submission past it is refused as it always was
# rather than retained into a page that cannot render.
MAX_RETAINED_REFUSAL_BYTES = 131_072
require_invariant(
    MAX_STATEMENT_BYTES
    + MAX_TAGS * MAX_TAG_BYTES
    + MAX_EVIDENCE_PER_ITEM * (MAX_EVIDENCE_EXCERPT_BYTES + 512)
    + MAX_NO_MEMORY_REASON_BYTES
    <= MAX_RETAINED_REFUSAL_BYTES,
    label="retained refusal budget",
)
require_invariant(
    # Twice the item roster: the compact bulk selection repeats every draft
    # item once as a checkbox beside the roster that lists it.
    STANDARD_PAGE_CHROME_BYTES
    + (2 * MAX_CHANGE_ITEMS + MAX_BATCH_FILES) * MAX_REVIEW_ROSTER_ROW_HTML_BYTES
    + 2 * MAX_ESCAPED_HTML_EXPANSION * MAX_RETAINED_REFUSAL_BYTES
    <= MAX_REVIEW_SECTION_HTML_RESPONSE_BYTES,
    label="review section response budget",
)
# One guard-repair candidate row: two clipped statements, two lineage
# identifiers, and its rationales. Clipped, because `lint_guards` reports up to
# MAX_GUARD_LINKS pairs and two whole statements on each of those rows exceed
# the standard page by an order of magnitude. The panel renders the report in
# one page rather than paging it: the report is quadratic in current heads and
# recomputed on every call, so a page control would buy navigation at the price
# of one full rescan per click.
MAX_GUARD_CANDIDATE_STATEMENT_CHARS = 160
# One character expands under HTML escaping (`&` becomes five bytes) or under
# UTF-8 (four bytes), never both -- a multi-byte character is never an HTML
# metacharacter -- so the escape factor bounds either.
MAX_ESCAPED_GUARD_CANDIDATE_HTML_BYTES = (
    MAX_ESCAPED_HTML_EXPANSION
    * (2 * MAX_GUARD_CANDIDATE_STATEMENT_CHARS + 2 * 256 + 128)
    + 1_024
)
UI_GUARD_CANDIDATE_LIMIT = MAX_GUARD_LINKS
# A standing violation renders two short identifiers and two sensitivity dots.
MAX_ESCAPED_GUARD_VIOLATION_HTML_BYTES = MAX_ESCAPED_HTML_EXPANSION * (2 * 256 + 128)
# Candidates are capped by the lint report itself; standing violations are not,
# and invariant 14 makes them a growing quantity by construction -- a violation
# an apply did not touch is reported, never silently repaired. Unbounded, the
# page whose job is to show them refuses to render in proportion to how many
# there are to fix, which is exactly backwards.
UI_GUARD_VIOLATION_LIMIT = MAX_GUARD_LINKS
require_invariant(
    STANDARD_PAGE_CHROME_BYTES
    + UI_GUARD_CANDIDATE_LIMIT * MAX_ESCAPED_GUARD_CANDIDATE_HTML_BYTES
    + UI_GUARD_VIOLATION_LIMIT * MAX_ESCAPED_GUARD_VIOLATION_HTML_BYTES
    <= MAX_STANDARD_HTML_RESPONSE_BYTES,
    label="guard candidate panel budget",
)


class BinarySink(Protocol):
    def write(self, value: bytes) -> int: ...


@dataclass(frozen=True, slots=True)
class BoundedMultipartFile:
    field_name: str
    filename: str
    content_type: str | None
    byte_length: int


@dataclass(frozen=True, slots=True)
class BoundedMultipart:
    fields: tuple[tuple[str, str], ...]
    file: BoundedMultipartFile | None


def validate_content_length(
    headers: Iterable[tuple[bytes, bytes]],
    max_bytes: int,
) -> int | None:
    """Validate one unambiguous nonnegative Content-Length before receive."""
    values = [value for name, value in headers if name.lower() == b"content-length"]
    if not values:
        return None
    if len(values) != 1:
        raise InvalidArgumentError("request length is ambiguous")
    raw = values[0]
    if not raw or not raw.isdigit():
        raise InvalidArgumentError("request length is invalid")
    declared = int(raw)
    if declared > max_bytes:
        raise RequestLimitError("request body exceeds its byte budget")
    return declared


async def read_bounded_body(
    receive: Receive,
    *,
    headers: Iterable[tuple[bytes, bytes]],
    max_bytes: int,
) -> bytes:
    """Read ASGI body chunks while enforcing declared and actual byte counts."""
    declared = validate_content_length(headers, max_bytes)
    chunks: list[bytes] = []
    total = 0
    while True:
        message = await receive()
        if message.get("type") != "http.request":
            raise InvalidArgumentError("request body stream is invalid")
        raw_body = message.get("body", b"")
        if not isinstance(raw_body, bytes):
            raise InvalidArgumentError("request body chunk is invalid")
        next_total = total + len(raw_body)
        if next_total > max_bytes or (declared is not None and next_total > declared):
            raise RequestLimitError("request body exceeds its declared budget")
        if raw_body:
            chunks.append(raw_body)
        total = next_total
        if not bool(message.get("more_body", False)):
            break
    if declared is not None and total != declared:
        raise InvalidArgumentError("request body length does not match declaration")
    return b"".join(chunks)


def parse_bounded_urlencoded(
    body: bytes,
    *,
    max_fields: int,
    max_field_bytes: int,
) -> tuple[tuple[str, str], ...]:
    """Decode a bounded UTF-8 form without permitting structural expansion."""
    try:
        encoded = body.decode("ascii")
        pairs = urllib.parse.parse_qsl(
            encoded,
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
            max_num_fields=max_fields,
        )
    except (UnicodeError, ValueError) as error:
        raise InvalidArgumentError("URL-encoded form is invalid") from error
    if len(pairs) > max_fields:
        raise RequestLimitError("form has too many fields")
    for name, value in pairs:
        if (
            len(name.encode("utf-8")) > max_field_bytes
            or len(value.encode("utf-8")) > max_field_bytes
        ):
            raise RequestLimitError("form field exceeds its byte budget")
    return tuple(pairs)


async def parse_bounded_multipart(
    chunks: AsyncIterable[bytes],
    *,
    boundary: bytes,
    file_sink: BinarySink,
    file_started: Callable[[str], None] | None = None,
) -> BoundedMultipart:
    """Parse one file plus one control field with streaming byte accounting."""
    if not boundary or b"\r" in boundary or b"\n" in boundary:
        raise InvalidArgumentError("multipart boundary is invalid")

    fields: list[tuple[str, str]] = []
    completed_file: BoundedMultipartFile | None = None
    part_count = 0
    file_count = 0
    current_headers: list[tuple[bytes, bytes]] = []
    header_name = bytearray()
    header_value = bytearray()
    header_bytes = 0
    current_name: str | None = None
    current_filename: str | None = None
    current_content_type: str | None = None
    current_field = bytearray()
    current_file_bytes = 0
    reached_end = False

    def on_part_begin() -> None:
        nonlocal part_count, header_bytes
        nonlocal current_name, current_filename, current_content_type
        nonlocal current_field, current_file_bytes
        part_count += 1
        if part_count > MAX_MULTIPART_PARTS:
            raise RequestLimitError("multipart has too many parts")
        current_headers.clear()
        header_name.clear()
        header_value.clear()
        header_bytes = 0
        current_name = None
        current_filename = None
        current_content_type = None
        current_field = bytearray()
        current_file_bytes = 0

    def on_header_field(data: bytes, start: int, end: int) -> None:
        nonlocal header_bytes
        value = data[start:end]
        header_bytes += len(value)
        if header_bytes > MAX_MULTIPART_HEADER_BYTES:
            raise RequestLimitError("multipart headers exceed their byte budget")
        header_name.extend(value)

    def on_header_value(data: bytes, start: int, end: int) -> None:
        nonlocal header_bytes
        value = data[start:end]
        header_bytes += len(value)
        if header_bytes > MAX_MULTIPART_HEADER_BYTES:
            raise RequestLimitError("multipart headers exceed their byte budget")
        header_value.extend(value)

    def on_header_end() -> None:
        nonlocal header_bytes
        header_bytes += 4
        if header_bytes > MAX_MULTIPART_HEADER_BYTES:
            raise RequestLimitError("multipart headers exceed their byte budget")
        current_headers.append((bytes(header_name).lower(), bytes(header_value)))
        header_name.clear()
        header_value.clear()

    def on_headers_finished() -> None:
        nonlocal file_count, current_name, current_filename, current_content_type
        values = [
            value for name, value in current_headers if name == b"content-disposition"
        ]
        if len(values) != 1:
            raise InvalidArgumentError("multipart disposition is invalid")
        disposition, options = parse_options_header(values[0])
        if disposition != b"form-data" or b"name" not in options:
            raise InvalidArgumentError("multipart disposition is invalid")
        try:
            current_name = options[b"name"].decode("utf-8", errors="strict")
            raw_filename = options.get(b"filename")
            if raw_filename is not None:
                if len(raw_filename) > MAX_UPLOAD_FILENAME_BYTES:
                    raise RequestLimitError("upload filename exceeds its byte budget")
                current_filename = raw_filename.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise InvalidArgumentError("multipart metadata is not UTF-8") from error
        content_types = [
            value for name, value in current_headers if name == b"content-type"
        ]
        if len(content_types) > 1:
            raise InvalidArgumentError("multipart content type is ambiguous")
        if content_types:
            try:
                current_content_type = content_types[0].decode("ascii", errors="strict")
            except UnicodeError as error:
                raise InvalidArgumentError(
                    "multipart content type is invalid"
                ) from error
        if current_filename is not None:
            file_count += 1
            if file_count > MAX_UPLOAD_FILES:
                raise RequestLimitError("multipart has too many files")
            if file_started is not None:
                file_started(current_filename)

    def on_part_data(data: bytes, start: int, end: int) -> None:
        nonlocal current_file_bytes
        value = data[start:end]
        if current_filename is None:
            if len(current_field) + len(value) > MAX_CONTROL_FORM_FIELD_BYTES:
                raise RequestLimitError("multipart field exceeds its byte budget")
            current_field.extend(value)
            return
        next_size = current_file_bytes + len(value)
        if next_size > MAX_UPLOAD_FILE_BYTES:
            raise RequestLimitError("upload file exceeds its byte budget")
        if value and file_sink.write(value) != len(value):
            raise InvalidArgumentError("upload sink rejected bytes")
        current_file_bytes = next_size

    def on_part_end() -> None:
        nonlocal completed_file
        if current_name is None:
            raise InvalidArgumentError("multipart field name is missing")
        if current_filename is None:
            if len(fields) >= MAX_FORM_FIELDS:
                raise RequestLimitError("multipart has too many fields")
            try:
                field_value = bytes(current_field).decode("utf-8", errors="strict")
            except UnicodeError as error:
                raise InvalidArgumentError("multipart field is not UTF-8") from error
            fields.append((current_name, field_value))
            return
        completed_file = BoundedMultipartFile(
            field_name=current_name,
            filename=current_filename,
            content_type=current_content_type,
            byte_length=current_file_bytes,
        )

    def on_end() -> None:
        nonlocal reached_end
        reached_end = True

    callbacks: MultipartCallbacks = {
        "on_part_begin": on_part_begin,
        "on_part_data": on_part_data,
        "on_part_end": on_part_end,
        "on_header_field": on_header_field,
        "on_header_value": on_header_value,
        "on_header_end": on_header_end,
        "on_headers_finished": on_headers_finished,
        "on_end": on_end,
    }
    try:
        parser = python_multipart.MultipartParser(
            boundary,
            callbacks,
            max_size=MAX_UPLOAD_REQUEST_BYTES,
            max_header_count=8,
            max_header_size=MAX_MULTIPART_HEADER_BYTES,
        )
        total = 0
        async for chunk in _iter_bytes(chunks):
            next_total = total + len(chunk)
            if next_total > MAX_UPLOAD_REQUEST_BYTES:
                raise RequestLimitError("multipart request exceeds its byte budget")
            if parser.write(chunk) != len(chunk):
                raise RequestLimitError("multipart parser exceeded its byte budget")
            total = next_total
        parser.finalize()
    except InvalidArgumentError, RequestLimitError:
        raise
    except Exception as error:
        raise InvalidArgumentError("multipart request is invalid") from error
    if not reached_end:
        raise InvalidArgumentError("multipart request is incomplete")
    return BoundedMultipart(fields=tuple(fields), file=completed_file)


async def _iter_bytes(chunks: AsyncIterable[bytes]) -> AsyncIterator[bytes]:
    async for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise InvalidArgumentError("multipart chunk is invalid")
        yield chunk


def render_bounded_chunks(
    chunks: Iterable[bytes],
    *,
    max_bytes: int,
) -> bytes:
    """Join rendered chunks only while their exact byte budget remains valid."""
    output = bytearray()
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise InvalidArgumentError("rendered chunk is invalid")
        if len(output) + len(chunk) > max_bytes:
            raise RequestLimitError("rendered response exceeds its byte budget")
        output.extend(chunk)
    return bytes(output)
