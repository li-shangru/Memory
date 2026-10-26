"""Fail-closed, process-isolated rendering helpers for inert owner previews."""

from __future__ import annotations

import io
import math
import multiprocessing
import resource
import struct
import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from multiprocessing.connection import Connection
from multiprocessing.process import BaseProcess
from typing import Any

from PIL import Image, ImageFile

MAX_MEDIA_SOURCE_BYTES = 67_108_864
MAX_SOURCE_TEXT_CHUNK_BYTES = 262_144
MAX_BINARY_WINDOW_BYTES = 65_536
MAX_IMAGE_DECODE_PIXELS = 40_000_000
MAX_PREVIEW_PIXELS = 16_000_000
MAX_PREVIEW_DIMENSION = 8_192
MAX_PREVIEW_PNG_BYTES = 65_048_576
MAX_MEDIA_FRAMES = 1
MEDIA_WORKER_MEMORY_BYTES = 536_870_912
MEDIA_WORKER_TIMEOUT_SECONDS = 10.0
MEDIA_WORKER_JOIN_SECONDS = 1.0
MAX_CONCURRENT_MEDIA_WORKERS = 2
MEDIA_BUSY_RETRY_AFTER_SECONDS = 1

_MAX_WORKER_MEMORY_BYTES = 536_870_912
_WORKER_ERROR_PREFIX = b"E\x00"
_WORKER_SUCCESS_PREFIX = b"S\x00"
_MEDIA_CAPACITY = multiprocessing.BoundedSemaphore(MAX_CONCURRENT_MEDIA_WORKERS)


class MediaPreviewError(Exception):
    """A source could not be converted into a safe inert preview."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class MediaWorkerError(MediaPreviewError):
    """The isolated renderer failed without exposing child details."""

    def __init__(self, code: str, *, worker_pid: int = -1) -> None:
        super().__init__(code)
        self.worker_pid = worker_pid


class MediaWorkerBusyError(MediaPreviewError):
    """Both fixed renderer slots are already in use."""

    def __init__(self) -> None:
        super().__init__("media_busy")


@dataclass(frozen=True, slots=True)
class MediaWorkerResult:
    payload: bytes


@dataclass(frozen=True, slots=True)
class ImagePreview:
    width: int
    height: int
    png_bytes: bytes


def run_media_job[T, R](loader: Callable[[], T], renderer: Callable[[T], R]) -> R:
    """Reserve process capacity before constructing or retaining source bytes."""
    if not _MEDIA_CAPACITY.acquire(block=False):
        raise MediaWorkerBusyError
    try:
        value = loader()
        return renderer(value)
    finally:
        _MEDIA_CAPACITY.release()


def _set_worker_memory_limit(memory_bytes: int) -> None:
    for limit_name in ("RLIMIT_AS", "RLIMIT_DATA"):
        limit = getattr(resource, limit_name, None)
        if limit is None:
            continue
        try:
            resource.setrlimit(limit, (memory_bytes, memory_bytes))
        except OSError, ValueError:
            continue


def _worker_entry(
    target: Callable[[bytes, Any], None],
    source: bytes,
    output: Connection,
    memory_bytes: int,
) -> None:
    try:
        _set_worker_memory_limit(memory_bytes)
        target(source, output)
    finally:
        output.close()


def _stop_and_reap(
    process: BaseProcess,
    *,
    wait_before_terminate: bool,
) -> None:
    if process.is_alive() and wait_before_terminate:
        process.join(MEDIA_WORKER_JOIN_SECONDS)
    if process.is_alive():
        process.terminate()
        process.join(MEDIA_WORKER_JOIN_SECONDS)
    if process.is_alive():
        process.kill()
    process.join()


def _run_spawn_worker(
    target: Callable[[bytes, Any], None],
    source: bytes,
    *,
    timeout_seconds: float,
    max_result_bytes: int,
    cancelled: Callable[[], bool] | None = None,
) -> MediaWorkerResult:
    """Run one importable target under spawn and reap it on every exit path."""
    if MEDIA_WORKER_MEMORY_BYTES > _MAX_WORKER_MEMORY_BYTES:
        raise MediaWorkerError("memory_limit")
    if MEDIA_WORKER_MEMORY_BYTES <= 0 or max_result_bytes <= 0:
        raise MediaWorkerError("invalid_limit")

    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker_entry,
        args=(target, source, send, MEDIA_WORKER_MEMORY_BYTES),
        daemon=True,
    )
    process.start()
    worker_pid = process.pid or -1
    send.close()
    deadline = time.monotonic() + timeout_seconds
    failure_code = "worker_crash"
    payload: bytes | None = None
    try:
        while True:
            if cancelled is not None and cancelled():
                failure_code = "cancelled"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure_code = "timeout"
                break
            if receive.poll(min(remaining, 0.02)):
                try:
                    payload = receive.recv_bytes(maxlength=max_result_bytes)
                except OSError:
                    failure_code = "ipc_limit"
                except EOFError:
                    failure_code = "worker_crash"
                break
            if not process.is_alive():
                if receive.poll():
                    continue
                failure_code = "worker_crash"
                break
    finally:
        receive.close()
        _stop_and_reap(
            process,
            wait_before_terminate=failure_code == "timeout",
        )
        process.close()

    if payload is None:
        raise MediaWorkerError(failure_code, worker_pid=worker_pid)
    return MediaWorkerResult(payload=payload)


def _strict_image_container(source: bytes, image_format: str) -> None:
    """Reject appended payloads and format confusion before decoding."""
    if image_format == "PNG":
        if not source.startswith(b"\x89PNG\r\n\x1a\n"):
            raise MediaPreviewError("invalid_media")
        offset = 8
        saw_end = False
        while offset + 12 <= len(source):
            length = int.from_bytes(source[offset : offset + 4], "big")
            end = offset + 12 + length
            if end > len(source):
                raise MediaPreviewError("invalid_media")
            chunk_type = source[offset + 4 : offset + 8]
            offset = end
            if chunk_type == b"IEND":
                saw_end = True
                break
        if not saw_end or offset != len(source):
            raise MediaPreviewError("invalid_media")
    elif image_format == "JPEG":
        if not _jpeg_has_exact_end(source):
            raise MediaPreviewError("invalid_media")
    elif image_format == "WEBP":
        if (
            len(source) < 12
            or source[:4] != b"RIFF"
            or source[8:12] != b"WEBP"
            or int.from_bytes(source[4:8], "little") + 8 != len(source)
        ):
            raise MediaPreviewError("invalid_media")
    else:
        raise MediaPreviewError("invalid_media")


def _jpeg_has_exact_end(source: bytes) -> bool:
    """Parse JPEG marker framing and require EOI to be the final bytes."""
    if not source.startswith(b"\xff\xd8"):
        return False
    position = 2
    in_scan = False
    while position < len(source):
        if in_scan:
            marker_start = source.find(b"\xff", position)
            if marker_start < 0:
                return False
            position = marker_start
        elif source[position] != 0xFF:
            return False
        while position < len(source) and source[position] == 0xFF:
            position += 1
        if position >= len(source):
            return False
        marker = source[position]
        position += 1
        if in_scan and marker == 0x00:
            continue
        if marker == 0xD9:
            return position == len(source)
        if marker == 0xD8:
            return False
        if marker == 0x01 or 0xD0 <= marker <= 0xD7:
            continue
        in_scan = False
        if marker == 0x00 or position + 2 > len(source):
            return False
        segment_length = int.from_bytes(source[position : position + 2], "big")
        if segment_length < 2 or position + segment_length > len(source):
            return False
        position += segment_length
        if marker == 0xDA:
            in_scan = True
    return False


def _canonical_png(image: Image.Image) -> bytes:
    converted_source = image.convert("RGBA")
    converted = Image.frombytes(
        "RGBA", converted_source.size, converted_source.tobytes()
    )
    output = io.BytesIO()
    converted.save(output, format="PNG", compress_level=9, optimize=False)
    value = output.getvalue()
    if len(value) > MAX_PREVIEW_PNG_BYTES:
        raise MediaPreviewError("output_byte_limit")
    return value


def _render_image_in_worker(
    source: bytes,
    *,
    max_pixels: int,
    expected_format: str | None,
) -> ImagePreview:
    ImageFile.LOAD_TRUNCATED_IMAGES = False
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            with Image.open(io.BytesIO(source)) as image:
                image_format = image.format or ""
                if expected_format is not None and image_format != expected_format:
                    raise MediaPreviewError("format_mismatch")
                _strict_image_container(source, image_format)
                if getattr(image, "n_frames", 1) > MAX_MEDIA_FRAMES:
                    raise MediaPreviewError("frame_limit")
                width, height = image.size
                if width > MAX_PREVIEW_DIMENSION or height > MAX_PREVIEW_DIMENSION:
                    raise MediaPreviewError("dimension_limit")
                pixels = width * height
                if pixels > MAX_IMAGE_DECODE_PIXELS:
                    raise MediaPreviewError("decoded_pixel_limit")
                image.load()
                rendered: Image.Image = image
                if pixels > max_pixels:
                    scale = math.sqrt(max_pixels / pixels)
                    width = max(1, math.floor(width * scale))
                    height = max(1, math.floor(height * scale))
                    rendered = image.resize(
                        (width, height),
                        Image.Resampling.LANCZOS,
                    )
                png = _canonical_png(rendered)
        except MediaPreviewError:
            raise
        except Exception as error:
            raise MediaPreviewError("invalid_media") from error
    return ImagePreview(width=width, height=height, png_bytes=png)


def _image_worker(output_source: bytes, output: Connection) -> None:
    try:
        max_pixels, expected_length = struct.unpack(">II", output_source[:8])
        expected_raw = output_source[8 : 8 + expected_length]
        expected = expected_raw.decode("ascii") or None
        source = output_source[8 + expected_length :]
        preview = _render_image_in_worker(
            source,
            max_pixels=max_pixels,
            expected_format=expected,
        )
        payload = (
            _WORKER_SUCCESS_PREFIX
            + struct.pack(">II", preview.width, preview.height)
            + preview.png_bytes
        )
    except MediaPreviewError as error:
        payload = _WORKER_ERROR_PREFIX + error.code.encode("ascii", errors="ignore")
    except Exception:
        payload = _WORKER_ERROR_PREFIX + b"invalid_media"
    output.send_bytes(payload)


def _render_image_preview(
    source_bytes: bytes,
    *,
    max_pixels: int,
    expected_format: str | None,
    cancelled: Callable[[], bool] | None = None,
) -> ImagePreview:
    if len(source_bytes) > MAX_MEDIA_SOURCE_BYTES:
        raise MediaPreviewError("source_too_large")
    if max_pixels <= 0 or max_pixels > MAX_PREVIEW_PIXELS:
        raise MediaPreviewError("output_pixel_limit")
    expected = (expected_format or "").encode("ascii")
    envelope = struct.pack(">II", max_pixels, len(expected)) + expected + source_bytes
    result = _run_spawn_worker(
        _image_worker,
        envelope,
        timeout_seconds=MEDIA_WORKER_TIMEOUT_SECONDS,
        max_result_bytes=MAX_PREVIEW_PNG_BYTES + 10,
        cancelled=cancelled,
    )
    if result.payload.startswith(_WORKER_ERROR_PREFIX):
        code = result.payload[len(_WORKER_ERROR_PREFIX) :].decode("ascii")
        raise MediaPreviewError(code or "invalid_media")
    if (
        not result.payload.startswith(_WORKER_SUCCESS_PREFIX)
        or len(result.payload) < 10
    ):
        raise MediaPreviewError("invalid_media")
    width, height = struct.unpack(">II", result.payload[2:10])
    return ImagePreview(width=width, height=height, png_bytes=result.payload[10:])


def render_image_preview(
    source_bytes: bytes,
    *,
    max_pixels: int,
) -> ImagePreview:
    """Decode one bounded static image and return a newly encoded inert PNG."""
    return _render_image_preview(
        source_bytes,
        max_pixels=max_pixels,
        expected_format=None,
    )


def _render_image_preview_with_cancellation(
    source_bytes: bytes,
    *,
    max_pixels: int,
    cancelled: Callable[[], bool],
) -> ImagePreview:
    return _render_image_preview(
        source_bytes,
        max_pixels=max_pixels,
        expected_format=None,
        cancelled=cancelled,
    )


def render_image_preview_for_format(
    source_bytes: bytes,
    *,
    max_pixels: int,
    expected_format: str,
) -> ImagePreview:
    """Render only when the decoded container matches its declared media type."""
    return _render_image_preview(
        source_bytes,
        max_pixels=max_pixels,
        expected_format=expected_format,
    )


def validate_declared_image_container(
    source_bytes: bytes,
    *,
    expected_format: str,
) -> None:
    """Reject obvious format confusion or appended bytes before child startup."""
    if len(source_bytes) > MAX_MEDIA_SOURCE_BYTES:
        raise MediaPreviewError("source_too_large")
    _strict_image_container(source_bytes, expected_format)


def render_binary_window(data: bytes, *, offset: int, width: int = 16) -> str:
    """Render exact bytes as inert hexadecimal plus printable ASCII."""
    if offset < 0 or width <= 0:
        raise MediaPreviewError("invalid_binary_window")
    lines: list[str] = []
    for relative in range(0, len(data), width):
        chunk = data[relative : relative + width]
        hex_column = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_column = "".join(
            chr(byte) if 32 <= byte <= 126 and byte not in {60, 62} else "."
            for byte in chunk
        )
        lines.append(f"{offset + relative:08x}  {hex_column}  {ascii_column}")
    return "\n".join(lines)
