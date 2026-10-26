"""Bounded process-memory types for owner correction capture."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from memory.model import (
    CapturedCorrection,
    CaptureRecoveryIssue,
    CustodyKind,
    ExactCaptureMetadata,
    PrivateStagedEntry,
    StagedInboxEntry,
)

MAX_OWNER_CORRECTION_SOURCE_BYTES = 1_048_576
CORRECTION_FORM_TTL_NS = 600_000_000_000
MAX_CORRECTION_INTENTS = 8
MAX_CORRECTION_SESSION_RETAINED_BYTES = (
    MAX_CORRECTION_INTENTS * MAX_OWNER_CORRECTION_SOURCE_BYTES
)


@dataclass(frozen=True, slots=True)
class CorrectionFormBinding:
    session_id: str
    form_nonce: str
    selected_memory_id: str
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class PreparedOwnerCorrection:
    selected_memory_id: str
    lineage_id: str
    expected_head_id: str
    captured_at: int
    owner_text_offset: int
    owner_text_sha256: str
    source_bytes: bytes
    source_sha256: str


@dataclass(frozen=True, slots=True)
class CorrectionSubmissionLease:
    lease_id: str
    binding: CorrectionFormBinding
    prepared: PreparedOwnerCorrection
    capture_request_id: str
    reserved_batch_id: str
    state: Literal["in_flight", "revoked"]


type CorrectionLeaseResult = CorrectionSubmissionLease | CapturedCorrection


@dataclass(frozen=True, slots=True)
class CorrectionRetryView:
    form_nonce: str
    selected_memory_id: str
    owner_text: str
    expires_at_ns: int


@dataclass(frozen=True, slots=True)
class CorrectionInProgressView:
    form_nonce: str
    selected_memory_id: str
    expires_at_ns: int


type CorrectionStatusView = (
    CorrectionRetryView | CorrectionInProgressView | CapturedCorrection
)


__all__ = (
    "CORRECTION_FORM_TTL_NS",
    "MAX_CORRECTION_INTENTS",
    "MAX_CORRECTION_SESSION_RETAINED_BYTES",
    "MAX_OWNER_CORRECTION_SOURCE_BYTES",
    "CaptureRecoveryIssue",
    "CapturedCorrection",
    "CorrectionFormBinding",
    "CorrectionInProgressView",
    "CorrectionLeaseResult",
    "CorrectionRetryView",
    "CorrectionStatusView",
    "CorrectionSubmissionLease",
    "CustodyKind",
    "ExactCaptureMetadata",
    "PreparedOwnerCorrection",
    "PrivateStagedEntry",
    "StagedInboxEntry",
)
