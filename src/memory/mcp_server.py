"""Protocol-clean stdio MCP adapter for the generic Store tool slice.

It also serves the two read-only surfaces that hang off that slice: the three
Skill workflows as prompts (`memory.mcp_prompts`), and the
`memory://source/<id>` URIs `source.read` mints, resolved bounded and inert.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shlex
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from contextvars import ContextVar
from typing import Annotated, Any, Literal, cast
from urllib.parse import quote, unquote, urlsplit

from anyio import to_thread
from mcp.server.context import (
    CallNext,
    HandlerResult,
    ServerRequestContext,
)
from mcp.server.elicitation import ElicitationResult
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.server.mcpserver.prompts.base import Prompt, UserMessage
from mcp.server.mcpserver.resolve import Elicit, Resolve
from mcp.server.mcpserver.utilities.func_metadata import ArgModelBase, FuncMetadata
from mcp.server.request_state import (
    AESGCMRequestStateCodec,
    RequestStateBoundary,
    RequestStateSecurity,
)
from mcp.shared.exceptions import MCPError
from mcp.types import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    CallToolResult,
    InputRequiredResult,
    ReadResourceResult,
    ResourceTemplate,
    TextResourceContents,
    ToolAnnotations,
)
from pydantic import AnyUrl, BaseModel, ConfigDict, Field, RootModel

from memory.database import open_database
from memory.errors import (
    InvalidArgumentError,
    OwnerApprovalRequiredError,
    OwnerDeclinedError,
    SourceTooLargeError,
    StoreError,
)
from memory.inbox import scan_inbox
from memory.keys import load_master_key
from memory.mcp_prompts import SkillPrompt, skill_prompts
from memory.mcp_schemas import (
    _TOOL_SCHEMAS,
    ENVELOPE_SCHEMA,
    INSTRUCTION_TRUST,
    RETRYABLE_ERROR_CODES,
)
from memory.mcp_schemas import (
    contract_digest as contract_digest,
)
from memory.mcp_schemas import (
    contract_document as contract_document,
)
from memory.mcp_schemas import (
    skill_digest as skill_digest,
)
from memory.mcp_schemas import (
    tool_schemas as tool_schemas,
)
from memory.memories import (
    MAX_MEMORY_SELECTION,
    get_memory_facets,
    search_memories,
)
from memory.memory_detail_pages import (
    DETAIL_BODY_LIMIT,
    DetailRecord,
    read_detail_page,
)
from memory.model import (
    AddGuardLink,
    AddItem,
    ApplicationResult,
    Authorship,
    BatchDetail,
    ChangeEdit,
    ChangeSetAdapterOrigin,
    ChangeSetView,
    ClearSourceNoMemory,
    Coverage,
    DraftGuardLink,
    DraftItem,
    DuplicateCapture,
    EvidenceInput,
    EvidenceLocator,
    FacetCount,
    GuardAttachment,
    GuardLinkInput,
    GuardViolation,
    InboxBatch,
    MemoryDetail,
    MemoryFacets,
    MemoryFields,
    MemoryFilters,
    MemoryKind,
    MemorySearchHit,
    MemorySearchPage,
    MemorySummary,
    Page,
    RejectItem,
    RemoveGuardLink,
    ReplaceItem,
    RestoreItem,
    RevokeGuardLink,
    RuntimePaths,
    Sensitivity,
    SetSourceNoMemory,
    SourceCaptureOrigin,
    SourceChunk,
    SourceDecision,
    SourceFilters,
    SourceSearchHit,
    SourceSearchPage,
    SourceSummary,
    StoreStatus,
)
from memory.retrieval import MAX_READ_BYTES, read_source, search_sources
from memory.reviews import (
    _mint_owner_approval,
    approve_and_apply,
    create_change_set,
    edit_change_set,
    get_change_set,
    render_change_set,
)
from memory.runtime import default_root, load_runtime_identity
from memory.sources import (
    get_store_status,
    list_batches,
    list_sources,
    read_batch,
)
from memory.validation import strict_utf8_bytes

#: The one addressable Store resource space. `source.read`'s binary arm has
#: always minted these URIs inside its embedded resource; until they resolved,
#: they looked addressable and were not.
SOURCE_RESOURCE_SCHEME = "memory"
SOURCE_RESOURCE_HOST = "source"

#: Ordinary text-heavy MCP result bodies stay beneath one eight-MiB ceiling.
#: The reserve covers Store/result-dependent envelope, cursor, and result-key
#: overhead; content costs charge every structured and escaped-text arm.
#: Client-supplied JSON-RPC request IDs live outside this result body.
_MCP_RESULT_BODY_BUDGET_BYTES = 8 * 1024 * 1024
_MCP_RESULT_BODY_RESERVE_BYTES = 64 * 1024
_MEMORY_SEARCH_RESULT_BUDGET_BYTES = _MCP_RESULT_BODY_BUDGET_BYTES
_MEMORY_SEARCH_RESULT_RESERVE_BYTES = _MCP_RESULT_BODY_RESERVE_BYTES
_MEMORY_SEARCH_ITEM_BUDGET_BYTES = (
    _MEMORY_SEARCH_RESULT_BUDGET_BYTES - _MEMORY_SEARCH_RESULT_RESERVE_BYTES
)
_SOURCE_READ_RESULT_BUDGET_BYTES = _MCP_RESULT_BODY_BUDGET_BYTES
_SOURCE_READ_RESULT_RESERVE_BYTES = _MCP_RESULT_BODY_RESERVE_BYTES
_SOURCE_READ_TEXT_ITEM_BUDGET_BYTES = (
    _SOURCE_READ_RESULT_BUDGET_BYTES - _SOURCE_READ_RESULT_RESERVE_BYTES
)
SOURCE_RESOURCE_TEMPLATE = (
    f"{SOURCE_RESOURCE_SCHEME}://{SOURCE_RESOURCE_HOST}/{{source_id}}"
)

#: One resource read serves at most this many bytes of one capture.
#:
#: `resources/read` has no cursor: the protocol offers a URI and one response,
#: so a resource read can either bound itself or become the unbounded read the
#: tool surface refuses to be. It takes the ceiling `source.read` already
#: enforces per response, because one response of source bytes should not mean
#: two different sizes depending on which door it came through. A capture over
#: the bound is refused rather than truncated: silently returning a prefix of
#: retained evidence, with no cursor to discover the rest and no field to say
#: it was cut, is the one failure this Store's complete-source-access invariant
#: cannot tolerate. The refusal names `source.read`, which reads the same
#: capture completely one bounded chunk at a time.
MAX_RESOURCE_BYTES = MAX_READ_BYTES
_RESOURCE_RESULT_BUDGET_BYTES = _MCP_RESULT_BODY_BUDGET_BYTES

#: The JSON-RPC code the resources specification reserves for a URI the server
#: understands and cannot resolve. `mcp.types` declares the four base codes and
#: not this one.
_RESOURCE_NOT_FOUND = -32002

#: Store codes mapped onto JSON-RPC codes for the resource door, which has no
#: `memory.mcp.v1` envelope to carry the typed code. `source_too_large` is
#: invalid-params rather than internal-error on purpose: nothing failed, this
#: method simply cannot serve that URI, and the bounded route is named in the
#: message. The Store code itself rides in `data` so a client keeps the same
#: vocabulary the tool envelope gives it.
_RESOURCE_ERROR_CODES = {
    "not_found": _RESOURCE_NOT_FOUND,
    "invalid_argument": INVALID_PARAMS,
    "source_too_large": INVALID_PARAMS,
    "stale_cursor": INVALID_PARAMS,
}


class _SuccessOutput(BaseModel):
    """Validate direct SDK results before MCPServer puts them on the wire."""

    schema_: Literal["memory.mcp.v1"] = Field(alias="schema")
    instruction_trust: Literal["inert"]
    data: object
    page: dict[str, object] | None = None
    coverage: dict[str, int] | None = None
    issues: list[dict[str, object]] | None = None

    model_config = ConfigDict(extra="forbid")


class _FailureBody(BaseModel):
    code: str
    retryable: bool
    details: dict[str, object] | None = None

    model_config = ConfigDict(extra="forbid")


class _FailureOutput(BaseModel):
    schema_: Literal["memory.mcp.v1"] = Field(alias="schema")
    instruction_trust: Literal["inert"]
    error: _FailureBody

    model_config = ConfigDict(extra="forbid")


class _EnvelopeOutput(RootModel[_SuccessOutput | _FailureOutput]):
    """The mutually exclusive ``memory.mcp.v1`` success/failure union."""


class _ToolArguments(ArgModelBase):
    """Preserve all raw fields for the Store's content-free validator."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="allow")

    def model_dump_one_level(self) -> dict[str, Any]:
        return dict(self.__pydantic_extra__ or {})


class _OwnerDecision(BaseModel):
    """Direct elicitation response; never part of normal tool arguments."""

    approve: bool = Field(
        description="Approve and atomically apply the exact displayed revision."
    )

    model_config = ConfigDict(extra="forbid")


_REQUEST_STATE_TTL_SECONDS = 600.0
_MAX_TRACKED_REQUEST_STATES = 4096
_AUTHENTICATED_REQUEST_STATE_FINGERPRINT: ContextVar[bytes | None] = ContextVar(
    "memory_authenticated_request_state_fingerprint",
    default=None,
)


class _AuthenticatedRequestStateCodec:
    """Hand off exact wire identity only after successful AEAD verification."""

    def __init__(self) -> None:
        self._delegate = AESGCMRequestStateCodec([os.urandom(32)])

    def seal(self, payload: bytes) -> str:
        return self._delegate.seal(payload)

    def unseal(self, token: str) -> bytes:
        payload = self._delegate.unseal(token)
        _AUTHENTICATED_REQUEST_STATE_FINGERPRINT.set(
            hashlib.sha256(token.encode("ascii")).digest()
        )
        return payload


class _RequestStateFingerprintScope:
    """Prevent an authenticated token identity from escaping its request task."""

    async def __call__(
        self,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        reset = _AUTHENTICATED_REQUEST_STATE_FINGERPRINT.set(None)
        try:
            return await call_next(ctx)
        finally:
            _AUTHENTICATED_REQUEST_STATE_FINGERPRINT.reset(reset)


class _ApprovalRequestStateLifecycle:
    """Track each sealed approval capability through its terminal outcome."""

    def __init__(self) -> None:
        self._outcomes: dict[
            bytes, tuple[Literal["accepted", "in_flight", "refused"], float]
        ] = {}
        self._lock = threading.Lock()

    async def __call__(
        self,
        ctx: ServerRequestContext[Any, Any],
        call_next: CallNext,
    ) -> HandlerResult:
        fingerprint = self._approval_continuation(ctx)
        if fingerprint is None:
            return await call_next(ctx)
        accepted_replay = self._begin(fingerprint)
        try:
            result = await call_next(ctx)
        except BaseException:
            if not accepted_replay:
                self._discard(fingerprint)
            raise
        if not accepted_replay:
            self._finish(fingerprint, accepted=_is_applied_approval_result(result))
        return result

    def _approval_continuation(
        self,
        context: ServerRequestContext[Any, Any],
    ) -> bytes | None:
        params = context.params
        if (
            context.method != "tools/call"
            or not isinstance(params, Mapping)
            or params.get("name") != "change_set.approve_and_apply"
        ):
            return None
        state = params.get("requestState")
        if not isinstance(state, str):
            return None
        return _AUTHENTICATED_REQUEST_STATE_FINGERPRINT.get()

    def _begin(self, fingerprint: bytes) -> bool:
        now = time.monotonic()
        with self._lock:
            expired = [
                tracked
                for tracked, (_outcome, deadline) in self._outcomes.items()
                if deadline <= now
            ]
            for tracked in expired:
                del self._outcomes[tracked]
            existing = self._outcomes.get(fingerprint)
            if existing is not None:
                outcome, _deadline = existing
                if outcome == "accepted":
                    return True
                raise MCPError(
                    code=INVALID_PARAMS,
                    message="Invalid or expired requestState",
                    data={"reason": "invalid_request_state"},
                )
            if len(self._outcomes) >= _MAX_TRACKED_REQUEST_STATES:
                raise MCPError(
                    code=INVALID_PARAMS,
                    message="Invalid or expired requestState",
                    data={"reason": "invalid_request_state"},
                )
            self._outcomes[fingerprint] = (
                "in_flight",
                now + _REQUEST_STATE_TTL_SECONDS,
            )
        return False

    def _finish(self, fingerprint: bytes, *, accepted: bool) -> None:
        with self._lock:
            existing = self._outcomes.get(fingerprint)
            if existing is None:  # pragma: no cover - one request owns its reservation
                return
            _outcome, deadline = existing
            self._outcomes[fingerprint] = (
                "accepted" if accepted else "refused",
                deadline,
            )

    def _discard(self, fingerprint: bytes) -> None:
        """Forget an unverified or interrupted first attempt without spending it."""
        with self._lock:
            existing = self._outcomes.get(fingerprint)
            if existing is not None and existing[0] == "in_flight":
                del self._outcomes[fingerprint]


def _is_applied_approval_result(result: HandlerResult) -> bool:
    """Recognize only Memory's exact successful application result envelope."""
    if isinstance(result, BaseModel):
        payload: Mapping[str, object] = result.model_dump(
            mode="python",
            by_alias=True,
            exclude_none=True,
        )
    elif isinstance(result, Mapping):
        payload = result
    else:
        return False
    structured = payload.get("structuredContent")
    if (
        not isinstance(structured, Mapping)
        or structured.get("schema") != ENVELOPE_SCHEMA
    ):
        return False
    data = structured.get("data")
    if not isinstance(data, Mapping):
        return False
    return set(data) == {
        "application_id",
        "change_set_id",
        "idempotent_replay",
        "memory_ids",
        "revision_id",
        "standing_guard_violations",
    } and isinstance(data.get("idempotent_replay"), bool)


class _MemoryMCPServer(MCPServer[None]):
    """Bind Store invariants to MCP v2's public dispatch boundaries."""

    def __init__(self, paths: RuntimePaths, *, trust_elicitation: bool = False) -> None:
        request_state_lifecycle = _ApprovalRequestStateLifecycle()
        super().__init__(
            "Memory",
            log_level="ERROR",
            request_state_security=RequestStateSecurity(
                codec=_AuthenticatedRequestStateCodec(),
                ttl=_REQUEST_STATE_TTL_SECONDS,
            ),
            middleware=(request_state_lifecycle,),
        )
        # Public middleware is outermost-first. This scope clears the codec's
        # authenticated wire-token handoff around every request; the SDK
        # boundary then verifies AEAD, expiry, and argument binding before the
        # inner lifecycle can reserve one exact approval capability.
        self.middleware.insert(0, _RequestStateFingerprintScope())
        boundary_index = next(
            (
                index
                for index, middleware in enumerate(self.middleware)
                if isinstance(middleware, RequestStateBoundary)
            ),
            None,
        )
        if boundary_index is None or boundary_index >= self.middleware.index(
            request_state_lifecycle
        ):
            raise RuntimeError("MCP request-state middleware order is unsafe")
        self._memory_paths = paths
        # Off by default: a harness that answers its own elicitation would
        # otherwise mint a real approval with no OS-verified owner presence.
        # The owner opts in per Store with `memory mcp --trust-elicitation`.
        self._trust_elicitation = trust_elicitation

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        context: Context[None, Any] | None = None,
    ) -> CallToolResult | InputRequiredResult:
        if name != "change_set.approve_and_apply":
            return await super().call_tool(name, arguments, context)
        try:
            values, replay, _view = await to_thread.run_sync(
                _validated_approval_state,
                self._memory_paths,
                arguments,
                abandon_on_cancel=False,
            )
            if replay is not None:
                return CallToolResult.model_validate(
                    _tool_result(_success(_application_data(replay)), binary=None)
                )
            if not (self._trust_elicitation and _supports_form_elicitation(context)):
                raise OwnerApprovalRequiredError("client elicitation is unavailable")
            exact_arguments = {
                "change_set_id": _required_string(values, "change_set_id"),
                "revision_id": _required_string(values, "revision_id"),
                "digest": _required_string(values, "digest"),
            }
            return await super().call_tool(name, exact_arguments, context)
        except ToolError as error:
            if isinstance(error.__cause__, StoreError):
                failure = error.__cause__
            else:
                failure = InvalidArgumentError("Store operation failed")
            return CallToolResult.model_validate(
                _approval_failure(self._memory_paths, arguments, failure)
            )
        except StoreError as error:
            return CallToolResult.model_validate(
                _approval_failure(self._memory_paths, arguments, error)
            )
        except UnicodeError:
            return CallToolResult.model_validate(
                _approval_failure(
                    self._memory_paths,
                    arguments,
                    InvalidArgumentError("tool string is invalid"),
                )
            )
        except OSError:
            return CallToolResult.model_validate(
                _approval_failure(
                    self._memory_paths,
                    arguments,
                    InvalidArgumentError("Store filesystem operation failed"),
                )
            )
        except Exception:
            return CallToolResult.model_validate(
                _approval_failure(
                    self._memory_paths,
                    arguments,
                    InvalidArgumentError("Store operation failed"),
                )
            )

    async def read_resource(
        self,
        uri: AnyUrl | str,
        context: Context[None, Any] | None = None,
    ) -> Iterable[ReadResourceContents] | InputRequiredResult:
        del context
        try:
            return await to_thread.run_sync(
                _read_source_resource,
                self._memory_paths,
                str(uri),
                abandon_on_cancel=False,
            )
        except StoreError as error:
            raise _resource_failure(error) from None
        except UnicodeError:
            raise _resource_failure(
                InvalidArgumentError("resource uri is invalid")
            ) from None
        except OSError:
            raise _resource_failure(
                InvalidArgumentError("Store filesystem operation failed")
            ) from None
        except Exception:
            raise _resource_failure(
                InvalidArgumentError("Store operation failed")
            ) from None

    async def list_resource_templates(self) -> list[ResourceTemplate]:
        return [
            ResourceTemplate(
                uri_template=SOURCE_RESOURCE_TEMPLATE,
                name="retained_source",
                title="Retained source",
                description=(
                    "Read one retained capture by its opaque source identifier. "
                    "Returns the complete capture when it fits one bounded "
                    "response, and otherwise refuses in favour of the "
                    "source.read tool, which continues by cursor. Enumerate "
                    "identifiers with the source.list tool."
                ),
            )
        ]


def create_server(
    paths: RuntimePaths, *, trust_elicitation: bool = False
) -> MCPServer[None]:
    """Register the exact Store tool contract with the approved MCP SDK."""
    server = _MemoryMCPServer(paths, trust_elicitation=trust_elicitation)
    for schema in _TOOL_SCHEMAS:
        name = str(schema["name"])
        server.add_tool(
            _registered_handler(paths, name),
            name=name,
            description=str(schema["description"]),
            annotations=ToolAnnotations.model_validate(schema["annotations"]),
            structured_output=False,
        )
        registered = server._tool_manager.get_tool(name)
        if registered is None:  # pragma: no cover - SDK registration invariant
            raise RuntimeError("MCPServer did not register a Store tool")
        registered.parameters = copy.deepcopy(
            cast(dict[str, Any], schema["inputSchema"])
        )
        registered.fn_metadata = FuncMetadata(
            arg_model=(
                registered.fn_metadata.arg_model
                if name == "change_set.approve_and_apply"
                else _ToolArguments
            ),
            output_schema=copy.deepcopy(cast(dict[str, Any], schema["outputSchema"])),
            output_model=_EnvelopeOutput,
            wrap_output=False,
        )
    _register_skill_prompts(server)
    return server


def _register_skill_prompts(server: MCPServer[None]) -> None:
    """Register the packaged Skill's workflows as reachable MCP prompts.

    Bodies are sliced from `SKILL.md` here, once, at server creation: a running
    server serves the Skill the wheel shipped, exactly as `skill_digest()`
    reports it, and a `prompts/get` touches no filesystem and can fail no
    request. A Skill missing one of the named sections raises before the server
    exists, rather than quietly serving whichever workflows still parse.
    """
    for prompt in skill_prompts():
        server.add_prompt(
            Prompt.from_function(
                _skill_prompt_render(prompt),
                name=prompt.name,
                title=prompt.section,
                description=prompt.description,
            )
        )


def _skill_prompt_render(prompt: SkillPrompt) -> Callable[[], list[UserMessage]]:
    """Bind one prompt's two packaged bodies as its rendered messages.

    Two messages, not one joined body: every byte a client receives is then
    packaged Skill, with no separator or framing sentence authored here that
    would quietly become a second, unversioned source of teaching.
    """
    messages = (UserMessage(prompt.preamble), UserMessage(prompt.workflow))

    def render() -> list[UserMessage]:
        return list(messages)

    return render


def source_resource_uri(source_id: str) -> str:
    """Mint the one resource URI that names one retained capture."""
    return (
        f"{SOURCE_RESOURCE_SCHEME}://{SOURCE_RESOURCE_HOST}/{quote(source_id, safe='')}"
    )


def _resource_source_id(uri: str) -> str:
    """Read one opaque source identifier out of a Store resource URI.

    Structural only, and deliberately strict: exactly one path segment under
    exactly this scheme and host, with no query or fragment. Nothing here
    resolves, joins, or stats a path, so a URI naming a filesystem location is
    refused as an unrecognized URI and never as a probe.
    """
    parsed = urlsplit(uri)
    if (
        parsed.scheme != SOURCE_RESOURCE_SCHEME
        or parsed.netloc != SOURCE_RESOURCE_HOST
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or "/" in parsed.path[1:]
    ):
        raise InvalidArgumentError("resource uri is not a Store source uri")
    return unquote(parsed.path[1:], errors="strict")


def _resource_text_result_wire_size(
    uri: str,
    media_type: str,
    content: str,
) -> int:
    """Measure the exact encoded MCP result body for one text resource."""
    result = ReadResourceResult(
        contents=[
            TextResourceContents(
                uri=uri,
                mime_type=media_type,
                text=content,
                _meta={
                    "instruction_trust": INSTRUCTION_TRUST,
                    "schema": ENVELOPE_SCHEMA,
                },
            )
        ]
    )
    return len(result.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))


def _read_source_resource(
    paths: RuntimePaths,
    uri: str,
) -> list[ReadResourceContents]:
    """Resolve one Store resource URI into one bounded, inert capture body."""
    chunk = read_source(
        paths,
        _resource_source_id(uri),
        cursor=None,
        max_bytes=MAX_RESOURCE_BYTES,
    )
    if not chunk.complete:
        raise SourceTooLargeError(
            f"source exceeds the {MAX_RESOURCE_BYTES}-byte resource bound; "
            "read it with the source.read tool"
        )
    content: str | bytes | None = chunk.text if chunk.text is not None else chunk.binary
    if content is None:  # pragma: no cover - a chunk always carries one arm
        raise InvalidArgumentError("retained capture has no readable body")
    if (
        isinstance(content, str)
        and _resource_text_result_wire_size(
            uri,
            chunk.media_type,
            content,
        )
        > _RESOURCE_RESULT_BUDGET_BYTES
    ):
        raise SourceTooLargeError(
            "source exceeds the encoded resource response bound; "
            "read it with the source.read tool"
        )
    return [
        ReadResourceContents(
            content=content,
            mime_type=chunk.media_type,
            # The same guarantee the tool envelope carries, on the same two
            # constant fields: retained bytes arriving through this door are
            # data, and never become agent, Skill, or tool instruction.
            meta={"instruction_trust": INSTRUCTION_TRUST, "schema": ENVELOPE_SCHEMA},
        )
    ]


def _resource_failure(error: StoreError) -> MCPError:
    """Translate one typed Store failure into a bounded JSON-RPC refusal."""
    return MCPError(
        code=_RESOURCE_ERROR_CODES.get(error.code, INTERNAL_ERROR),
        message=str(error),
        data={"code": error.code},
    )


def _registered_handler(
    paths: RuntimePaths,
    name: str,
) -> Callable[..., Any]:
    if name == "change_set.approve_and_apply":
        resolve_decision = _approval_resolver(paths)

        def invoke_with_approval(
            change_set_id: str,
            revision_id: str,
            digest: str,
            decision: object,
        ) -> CallToolResult:
            outcome = cast("ElicitationResult[_OwnerDecision]", decision)
            result = _complete_approval(
                paths,
                change_set_id,
                revision_id,
                digest,
                outcome,
            )
            return CallToolResult.model_validate(result)

        # `from __future__ import annotations` cannot resolve a closure-local
        # resolver name. Bind this one annotation to the actual resolver object
        # before MCPServer inspects the callable and builds its resolver plan.
        invoke_with_approval.__annotations__["decision"] = Annotated[
            ElicitationResult[_OwnerDecision], Resolve(resolve_decision)
        ]
        return invoke_with_approval

    def invoke(**arguments: object) -> CallToolResult:
        return CallToolResult.model_validate(call_tool(paths, name, arguments))

    return invoke


def _supports_form_elicitation(context: Context[None, Any] | None) -> bool:
    """Whether this request declared the form-elicitation capability."""
    if context is None:
        return False
    try:
        capabilities = context.client_capabilities
    except ValueError:
        return False
    elicitation = capabilities.elicitation if capabilities is not None else None
    return elicitation is not None and (
        elicitation.form is not None or elicitation.url is None
    )


def _validated_approval_state(
    paths: RuntimePaths,
    arguments: Mapping[str, object] | None,
) -> tuple[dict[str, object], ApplicationResult | None, ChangeSetView | None]:
    """Strictly validate one approval triple and probe exact replay first."""
    values = _validated_arguments("change_set.approve_and_apply", arguments)
    change_set_id = _required_string(values, "change_set_id")
    revision_id = _required_string(values, "revision_id")
    digest = _required_string(values, "digest")
    try:
        replay = approve_and_apply(
            paths,
            change_set_id,
            revision_id,
            digest,
            approval=None,
        )
    except OwnerApprovalRequiredError:
        replay = None
    if replay is not None:
        return values, replay, None
    view = get_change_set(paths, change_set_id)
    if view.revision_id != revision_id or view.digest != digest:
        approve_and_apply(
            paths,
            change_set_id,
            revision_id,
            digest,
            approval=None,
        )
    return values, None, view


def _approval_resolver(
    paths: RuntimePaths,
) -> Callable[[str, str, str], Elicit[_OwnerDecision] | _OwnerDecision]:
    """Build one deterministic era-portable direct-owner question."""

    def resolve_decision(
        change_set_id: str,
        revision_id: str,
        digest: str,
    ) -> Elicit[_OwnerDecision] | _OwnerDecision:
        _values, replay, view = _validated_approval_state(
            paths,
            {
                "change_set_id": change_set_id,
                "revision_id": revision_id,
                "digest": digest,
            },
        )
        if replay is not None:
            return _OwnerDecision(approve=True)
        if view is None:  # pragma: no cover - replay and view are exclusive
            raise RuntimeError("approval state has neither replay nor review")
        return Elicit(render_change_set(view), _OwnerDecision)

    return resolve_decision


def _complete_approval(
    paths: RuntimePaths,
    change_set_id: str,
    revision_id: str,
    digest: str,
    elicited: ElicitationResult[_OwnerDecision],
) -> dict[str, object]:
    """Revalidate one resolved owner decision and atomically apply it."""
    arguments = {
        "change_set_id": change_set_id,
        "revision_id": revision_id,
        "digest": digest,
    }
    try:
        _values, replay, _view = _validated_approval_state(paths, arguments)
        if replay is not None:
            return _tool_result(_success(_application_data(replay)), binary=None)
        if elicited.action == "cancel":
            raise OwnerApprovalRequiredError("owner approval was cancelled")
        if elicited.action == "decline" or not elicited.data.approve:
            raise OwnerDeclinedError("owner declined the exact revision")
        approval = _mint_owner_approval(
            paths,
            change_set_id,
            revision_id,
            digest,
            adapter="mcp_elicitation",
        )
        result = approve_and_apply(
            paths,
            change_set_id,
            revision_id,
            digest,
            approval=approval,
        )
        return _tool_result(_success(_application_data(result)), binary=None)
    except StoreError as error:
        # The replay probe above catches its own OwnerApprovalRequiredError, so
        # an already-applied replay never reaches here and never gains a handoff.
        return _tool_failure(
            _with_approval_handoff(
                error,
                paths=paths,
                name="change_set.approve_and_apply",
                arguments=arguments,
            )
        )
    except UnicodeError:
        return _tool_failure(InvalidArgumentError("tool string is invalid"))
    except OSError:
        return _tool_failure(InvalidArgumentError("Store filesystem operation failed"))
    except Exception:
        return _tool_failure(InvalidArgumentError("Store operation failed"))


def _approval_failure(
    paths: RuntimePaths,
    arguments: Mapping[str, object] | None,
    error: StoreError,
) -> dict[str, object]:
    """Build one typed approval failure at the public dispatch boundary."""
    return _tool_failure(
        _with_approval_handoff(
            error,
            paths=paths,
            name="change_set.approve_and_apply",
            arguments=arguments,
        )
    )


def call_tool(
    paths: RuntimePaths,
    name: str,
    arguments: Mapping[str, object] | None,
) -> dict[str, object]:
    """Invoke one registered tool and translate domain errors into wire envelopes."""
    try:
        values = _validated_arguments(name, arguments)
        envelope: dict[str, object]
        binary: SourceChunk | None = None
        if name == "store.status":
            envelope = _success(_status_data(get_store_status(paths)))
        elif name == "source.list":
            source_page = list_sources(
                paths,
                cursor=_optional_string(values.get("cursor")),
                limit=_integer_argument(values, "limit", 50),
                filters=_source_filters(values.get("filters")),
            )
            envelope = _success(
                [_source_data(source) for source in source_page.items],
                page=_page_data(source_page),
            )
        elif name == "source.search":
            result = search_sources(
                paths,
                _required_string(values, "query"),
                cursor=_optional_string(values.get("cursor")),
                limit=_integer_argument(values, "limit", 50),
            )
            envelope = _success(
                [_search_hit_data(hit) for hit in result.items],
                page=_page_data(result),
                coverage=_coverage_data(result.coverage),
            )
        elif name == "source.read":
            chunk = read_source(
                paths,
                _required_string(values, "source_id"),
                cursor=_optional_string(values.get("cursor")),
                max_bytes=_integer_argument(values, "max_bytes", 256 * 1024),
                _text_result_budget=_SOURCE_READ_TEXT_ITEM_BUDGET_BYTES,
                _text_character_cost=_source_read_text_character_wire_cost,
            )
            envelope = _success(_chunk_data(chunk))
            binary = chunk if chunk.binary is not None else None
        elif name == "inbox.scan":
            try:
                authorship = Authorship(_enum_argument(values, "authorship", "unknown"))
                sensitivity = Sensitivity(
                    _enum_argument(values, "sensitivity", "restricted")
                )
            except (TypeError, ValueError) as error:
                raise InvalidArgumentError("scan metadata is invalid") from error
            batch = scan_inbox(paths, authorship=authorship, sensitivity=sensitivity)
            envelope = _success(
                _batch_data(batch),
                page={"has_more": batch.has_more},
                issues=[_issue_data(issue.code, issue.count) for issue in batch.issues],
            )
        elif name == "inbox.list":
            batch_page = list_batches(
                paths,
                cursor=_optional_string(values.get("cursor")),
                limit=_integer_argument(values, "limit", 50),
            )
            envelope = _success(
                [_batch_data(batch) for batch in batch_page.items],
                page=_page_data(batch_page),
            )
        elif name == "inbox.read":
            detail = read_batch(paths, _required_string(values, "batch_id"))
            envelope = _success(_batch_detail_data(detail))
        elif name == "memory.search":
            memory_page = search_memories(
                paths,
                _optional_string(values.get("query")),
                filters=_memory_filters(values.get("filters")),
                cursor=_optional_string(values.get("cursor")),
                limit=_integer_argument(values, "limit", 50),
                _wire_item_budget=_MEMORY_SEARCH_ITEM_BUDGET_BYTES,
                _wire_item_cost=_memory_search_hit_wire_cost,
            )
            envelope = _success(
                [_memory_search_hit_data(item) for item in memory_page.items],
                page=_page_data(memory_page),
                coverage=_coverage_data(memory_page.coverage),
            )
        elif name == "memory.get":
            envelope = _memory_selection_data(paths, values)
        elif name == "memory.facets":
            envelope = _success(_memory_facets_data(get_memory_facets(paths)))
        elif name == "change_set.create":
            view = create_change_set(
                paths,
                _required_string(values, "batch_id"),
                adapter_origin=ChangeSetAdapterOrigin.MCP,
            )
            envelope = _success(_change_set_data(view))
        elif name == "change_set.get":
            view = get_change_set(
                paths,
                _required_string(values, "change_set_id"),
            )
            envelope = _success(_change_set_data(view))
        elif name == "change_set.edit":
            view = edit_change_set(
                paths,
                _required_string(values, "change_set_id"),
                _required_string(values, "expected_revision_id"),
                _change_edits(values.get("edits")),
                adapter_origin=ChangeSetAdapterOrigin.MCP,
            )
            envelope = _success(_change_set_data(view))
        elif name == "change_set.approve_and_apply":
            application = approve_and_apply(
                paths,
                _required_string(values, "change_set_id"),
                _required_string(values, "revision_id"),
                _required_string(values, "digest"),
                approval=None,
            )
            envelope = _success(_application_data(application))
        else:
            raise InvalidArgumentError("tool name is not registered")
        tool_result = _tool_result(envelope, binary=binary)
        if name == "memory.get":
            # Verify the SDK body, including its default fields, after the
            # additive record budget. JSON-RPC request IDs/framing are outside
            # this result-body contract.
            size = len(
                CallToolResult.model_validate(tool_result)
                .model_dump_json(
                    by_alias=True,
                    exclude_none=True,
                )
                .encode("utf-8")
            )
            if size > DETAIL_BODY_LIMIT:
                raise InvalidArgumentError("memory detail exceeds the response budget")
        return tool_result
    except StoreError as error:
        return _tool_failure(
            _with_approval_handoff(error, paths=paths, name=name, arguments=arguments)
        )
    except UnicodeError:
        return _tool_failure(InvalidArgumentError("tool string is invalid"))
    except OSError:
        return _tool_failure(InvalidArgumentError("Store filesystem operation failed"))
    except Exception:
        return _tool_failure(InvalidArgumentError("Store operation failed"))


def _validated_arguments(
    name: str,
    arguments: Mapping[str, object] | None,
) -> dict[str, object]:
    # A second hand-maintained copy of the argument sets the schemas declare,
    # deliberately: the declared input schema is advertisement and client-side
    # validation only, since every registered tool's arg model accepts extra
    # fields. An argument added to a schema and not here is refused at runtime.
    allowed = {
        "store.status": set(),
        "source.list": {"cursor", "filters", "limit"},
        "source.search": {"query", "cursor", "limit"},
        "source.read": {"source_id", "cursor", "max_bytes"},
        "inbox.scan": {"authorship", "sensitivity"},
        "inbox.list": {"cursor", "limit"},
        "inbox.read": {"batch_id"},
        "memory.search": {"query", "filters", "cursor", "limit"},
        "memory.get": {"memory_id", "lineage_id", "memory_ids", "cursor"},
        "memory.facets": set(),
        "change_set.create": {"batch_id"},
        "change_set.get": {"change_set_id"},
        "change_set.edit": {
            "change_set_id",
            "expected_revision_id",
            "edits",
        },
        "change_set.approve_and_apply": {
            "change_set_id",
            "revision_id",
            "digest",
        },
    }
    if name not in allowed:
        raise InvalidArgumentError("tool name is not registered")
    if arguments is None:
        values: dict[str, object] = {}
    elif isinstance(arguments, Mapping) and all(
        isinstance(key, str) for key in arguments
    ):
        values = dict(arguments)
        for key in values:
            strict_utf8_bytes(key, label="tool argument name")
    else:
        raise InvalidArgumentError("tool arguments must be an object")
    if not set(values) <= allowed[name]:
        raise InvalidArgumentError("tool arguments contain unsupported fields")
    required = {
        "source.search": {"query"},
        "source.read": {"source_id"},
        "inbox.read": {"batch_id"},
        # `memory.search` requires no query: an absent one enumerates. And
        # `memory.get` requires exactly one of three selectors, which a flat
        # required-set cannot express, so its handler checks that itself.
        "change_set.create": {"batch_id"},
        "change_set.get": {"change_set_id"},
        "change_set.edit": {
            "change_set_id",
            "expected_revision_id",
            "edits",
        },
        "change_set.approve_and_apply": {
            "change_set_id",
            "revision_id",
            "digest",
        },
    }.get(name, set())
    if not required <= set(values):
        raise InvalidArgumentError("tool arguments are missing required fields")
    return values


def _required_string(values: Mapping[str, object], key: str) -> str:
    value = values.get(key)
    strict_utf8_bytes(value, label="required tool string")
    return cast(str, value)


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    strict_utf8_bytes(value, label="optional tool string")
    return cast(str, value)


def _integer_argument(
    values: Mapping[str, object],
    key: str,
    default: int,
) -> int:
    value = values.get(key, default)
    if not isinstance(value, int):
        raise InvalidArgumentError("tool integer is invalid")
    return value


def _enum_argument(
    values: Mapping[str, object],
    key: str,
    default: str,
) -> str:
    value = values.get(key, default)
    strict_utf8_bytes(value, label="tool enum")
    return cast(str, value)


def _memory_filters(raw: object) -> MemoryFilters:
    if raw is None:
        return MemoryFilters()
    values = _strict_mapping(
        raw,
        allowed={
            "include_undated",
            "kinds",
            "occurred_from",
            "occurred_to",
            "recorded_from",
            "recorded_to",
            "sensitivities",
            "tags_all",
            "tags_any",
        },
        required=set(),
    )
    try:
        kinds = tuple(MemoryKind(value) for value in _string_list(values, "kinds"))
        sensitivities = tuple(
            Sensitivity(value) for value in _string_list(values, "sensitivities")
        )
    except ValueError as error:
        raise InvalidArgumentError("memory filter enum is invalid") from error
    return MemoryFilters(
        kinds=kinds,
        tags_all=tuple(_string_list(values, "tags_all")),
        tags_any=tuple(_string_list(values, "tags_any")),
        occurred_from=_optional_string(values.get("occurred_from")),
        occurred_to=_optional_string(values.get("occurred_to")),
        recorded_from=_optional_integer(values.get("recorded_from")),
        recorded_to=_optional_integer(values.get("recorded_to")),
        include_undated=_boolean_argument(values, "include_undated", True),
        sensitivities=sensitivities,
    )


def _source_filters(raw: object) -> SourceFilters:
    if raw is None:
        return SourceFilters()
    values = _strict_mapping(raw, allowed={"origin", "searchable"}, required=set())
    origin = values.get("origin")
    searchable = values.get("searchable")
    if searchable is not None and not isinstance(searchable, bool):
        raise InvalidArgumentError("source filter boolean is invalid")
    parsed: SourceCaptureOrigin | None = None
    if origin is not None:
        try:
            parsed = SourceCaptureOrigin(_required_string(values, "origin"))
        except ValueError as error:
            raise InvalidArgumentError("source filter enum is invalid") from error
    return SourceFilters(searchable=searchable, origin=parsed)


def _optional_integer(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidArgumentError("tool integer is invalid")
    return value


def _boolean_argument(
    values: Mapping[str, object],
    key: str,
    default: bool,
) -> bool:
    value = values.get(key, default)
    if not isinstance(value, bool):
        raise InvalidArgumentError("tool boolean is invalid")
    return value


def _memory_selection_data(
    paths: RuntimePaths,
    values: Mapping[str, object],
) -> dict[str, object]:
    """Preserve complete legacy shapes; distinguish every partial detail."""
    named = {
        key
        for key in ("memory_id", "lineage_id", "memory_ids")
        if values.get(key) is not None
    }
    if len(named) != 1:
        raise InvalidArgumentError("memory.get needs exactly one selector")
    selector = named.pop()
    if selector == "memory_ids":
        raw = values.get("memory_ids")
        if not isinstance(raw, list) or not 1 <= len(raw) <= MAX_MEMORY_SELECTION:
            raise InvalidArgumentError("memory selection is invalid")
        if not all(isinstance(item, str) for item in raw):
            raise InvalidArgumentError("memory selection identifiers are invalid")
        selection = tuple(cast("list[str]", raw))
    else:
        selection = (_required_string(values, selector),)
    cursor = _optional_string(values.get("cursor"))
    page = read_detail_page(
        paths, selector, selection, cursor, _detail_record_wire_cost
    )
    if cursor is None and page.next_cursor is None:
        details: list[dict[str, Any]] = []
        for record in page.records:
            if record.section == "header":
                assert isinstance(record.value, MemoryDetail)
                details.append(_memory_detail_data(record.value))
            else:
                details[record.selection_index][record.section].append(
                    _detail_record_data(record)["value"]
                )
        return _success(
            details if selector == "memory_ids" else details[0],
            page={"has_more": False},
        )
    return _success(
        {"detail_fragments": [_detail_record_data(record) for record in page.records]},
        page={
            "has_more": page.next_cursor is not None,
            **({} if page.next_cursor is None else {"next_cursor": page.next_cursor}),
        },
    )


def _detail_record_data(record: DetailRecord) -> dict[str, object]:
    if isinstance(record.value, MemoryDetail):
        value: object = {
            key: item
            for key, item in _memory_detail_data(record.value).items()
            if key not in {"evidence", "guards", "governs", "revision_ids"}
        }
    elif isinstance(record.value, EvidenceLocator):
        value = _evidence_data(record.value)
    elif isinstance(record.value, GuardAttachment):
        value = _guard_attachment_data(record.value)
    else:
        value = record.value
    return {
        "selection_index": record.selection_index,
        "memory_id": record.memory_id,
        "section": record.section,
        "value": value,
    }


def _detail_record_wire_cost(record: DetailRecord) -> int:
    compact = _compact_json(_detail_record_data(record))
    return len(compact.encode("utf-8")) + len(
        _compact_json(compact)[1:-1].encode("utf-8")
    )


_GUARD_LINK_OPERATIONS: dict[
    str, type[AddGuardLink] | type[RemoveGuardLink] | type[RevokeGuardLink]
] = {
    "add_guard_link": AddGuardLink,
    "remove_guard_link": RemoveGuardLink,
    "revoke_guard_link": RevokeGuardLink,
}


def _edit_locators(ordinal: int, item: object) -> dict[str, object]:
    """Name which edit of a batch failed, using only opaque ids and an ordinal.

    A change_set.edit call carries up to 256 operations, and a refusal that
    named none of them left the caller bisecting its own batch. The ordinal is
    always available; the two ids are echoed only when the failing edit
    actually supplied them as strings, so a malformed edit cannot put arbitrary
    caller data into the envelope.
    """
    locators: dict[str, object] = {"ordinal": ordinal}
    if not isinstance(item, Mapping):
        return locators
    for key in ("client_item_id", "source_id"):
        value = item.get(key)
        if not isinstance(value, str) or not 0 < len(value) <= 256:
            continue
        try:
            # The failing edit may be failing precisely because one of its
            # strings is not encodable, and the envelope is serialized with
            # strict UTF-8: echoing such a value would raise inside the failure
            # path itself, turning a typed refusal into an escaping exception.
            strict_utf8_bytes(value, label="edit locator")
        except InvalidArgumentError:
            continue
        locators[key] = value
    return locators


def _change_edits(raw: object) -> tuple[ChangeEdit, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 256:
        raise InvalidArgumentError("change-set edits are invalid")
    edits: list[ChangeEdit] = []
    for ordinal, item in enumerate(raw):
        try:
            edits.append(_change_edit(item))
        except InvalidArgumentError as error:
            raise InvalidArgumentError(
                str(error),
                details={**(error.details or {}), **_edit_locators(ordinal, item)},
            ) from error
    return tuple(edits)


def _change_edit(item: object) -> ChangeEdit:
    """Parse one bounded edit operation into its typed domain form."""
    if not isinstance(item, Mapping) or not isinstance(item.get("op"), str):
        raise InvalidArgumentError("change-set edit is invalid")
    operation = str(item["op"])
    if operation == "add_item":
        values = _strict_mapping(
            item,
            allowed={"op", "client_item_id", "memory", "evidence"},
            required={"op", "client_item_id", "memory", "evidence"},
        )
        return AddItem(
            client_item_id=_required_string(values, "client_item_id"),
            memory=_memory_fields(values.get("memory")),
            evidence=_evidence_inputs(values.get("evidence")),
        )
    if operation == "replace_item":
        values = _strict_mapping(
            item,
            allowed={"op", "item_id", "memory", "evidence"},
            required={"op", "item_id", "memory", "evidence"},
        )
        return ReplaceItem(
            item_id=_required_string(values, "item_id"),
            memory=_memory_fields(values.get("memory")),
            evidence=_evidence_inputs(values.get("evidence")),
        )
    if operation in {"reject_item", "restore_item"}:
        values = _strict_mapping(
            item,
            allowed={"op", "item_id"},
            required={"op", "item_id"},
        )
        item_id = _required_string(values, "item_id")
        return (
            RejectItem(item_id=item_id)
            if operation == "reject_item"
            else RestoreItem(item_id=item_id)
        )
    if operation == "set_source_no_memory":
        values = _strict_mapping(
            item,
            allowed={"op", "source_id", "reason"},
            required={"op", "source_id", "reason"},
        )
        return SetSourceNoMemory(
            source_id=_required_string(values, "source_id"),
            reason=_required_string(values, "reason"),
        )
    if operation == "clear_source_no_memory":
        values = _strict_mapping(
            item,
            allowed={"op", "source_id"},
            required={"op", "source_id"},
        )
        return ClearSourceNoMemory(source_id=_required_string(values, "source_id"))
    if operation in _GUARD_LINK_OPERATIONS:
        values = _strict_mapping(
            item,
            allowed={
                "op",
                "guard_item_id",
                "guard_lineage_id",
                "governed_item_id",
                "governed_lineage_id",
            },
            required={"op"},
        )
        link = GuardLinkInput(
            guard_item_id=_optional_string(values.get("guard_item_id")),
            guard_lineage_id=_optional_string(values.get("guard_lineage_id")),
            governed_item_id=_optional_string(values.get("governed_item_id")),
            governed_lineage_id=_optional_string(values.get("governed_lineage_id")),
        )
        return _GUARD_LINK_OPERATIONS[operation](link=link)
    raise InvalidArgumentError("change-set edit operation is invalid")


def _memory_fields(raw: object) -> MemoryFields:
    allowed = {
        "kind",
        "statement",
        "occurred_on",
        "valid_from",
        "valid_to",
        "tags",
        "sensitivity",
        "target_lineage_id",
        "expected_head_id",
    }
    required = {"kind", "statement", "tags", "sensitivity"}
    values = _strict_mapping(raw, allowed=allowed, required=required)
    try:
        kind = MemoryKind(_required_string(values, "kind"))
        sensitivity = Sensitivity(_required_string(values, "sensitivity"))
    except ValueError as error:
        raise InvalidArgumentError("memory enum is invalid") from error
    return MemoryFields(
        kind=kind,
        statement=_required_string(values, "statement"),
        occurred_on=_optional_string(values.get("occurred_on")),
        valid_from=_optional_string(values.get("valid_from")),
        valid_to=_optional_string(values.get("valid_to")),
        tags=tuple(_string_list(values, "tags", required=True)),
        sensitivity=sensitivity,
        target_lineage_id=_optional_string(values.get("target_lineage_id")),
        expected_head_id=_optional_string(values.get("expected_head_id")),
    )


def _evidence_inputs(raw: object) -> tuple[EvidenceInput, ...]:
    if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
        raise InvalidArgumentError("evidence list is invalid")
    inputs: list[EvidenceInput] = []
    for item in raw:
        if not isinstance(item, Mapping):
            raise InvalidArgumentError("evidence input is invalid")
        if "excerpt" in item:
            values = _strict_mapping(
                item,
                allowed={"source_id", "blob_digest", "excerpt"},
                required={"source_id", "blob_digest", "excerpt"},
            )
            inputs.append(
                EvidenceInput(
                    source_id=_required_string(values, "source_id"),
                    blob_digest=_required_string(values, "blob_digest"),
                    excerpt=_required_string(values, "excerpt"),
                )
            )
        else:
            values = _strict_mapping(
                item,
                allowed={"source_id", "blob_digest", "source_level"},
                required={"source_id", "blob_digest", "source_level"},
            )
            if values.get("source_level") is not True:
                raise InvalidArgumentError("source-level evidence is invalid")
            inputs.append(
                EvidenceInput(
                    source_id=_required_string(values, "source_id"),
                    blob_digest=_required_string(values, "blob_digest"),
                    source_level=True,
                )
            )
    return tuple(inputs)


def _strict_mapping(
    raw: object,
    *,
    allowed: set[str],
    required: set[str],
) -> dict[str, object]:
    if not isinstance(raw, Mapping) or not all(isinstance(key, str) for key in raw):
        raise InvalidArgumentError("tool object is invalid")
    values = dict(raw)
    for key in values:
        strict_utf8_bytes(key, label="tool object field")
    if not required <= set(values) or not set(values) <= allowed:
        raise InvalidArgumentError("tool object fields are invalid")
    return values


def _string_list(
    values: Mapping[str, object],
    key: str,
    *,
    required: bool = False,
) -> list[str]:
    raw = values.get(key)
    if raw is None and not required:
        return []
    if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
        raise InvalidArgumentError("tool string list is invalid")
    for item in raw:
        strict_utf8_bytes(item, label="tool string list item")
    return list(raw)


def _success(
    data: object,
    *,
    page: dict[str, object] | None = None,
    coverage: dict[str, int] | None = None,
    issues: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    envelope: dict[str, object] = {
        "schema": ENVELOPE_SCHEMA,
        "instruction_trust": INSTRUCTION_TRUST,
        "data": data,
    }
    if page is not None:
        envelope["page"] = page
    if coverage is not None:
        envelope["coverage"] = coverage
    if issues:
        envelope["issues"] = issues
    return envelope


def _tool_result(
    envelope: dict[str, object],
    *,
    binary: SourceChunk | None,
) -> dict[str, object]:
    if binary is None:
        content: list[dict[str, object]] = [
            {
                "type": "text",
                "text": _compact_json(envelope),
            }
        ]
    else:
        assert binary.binary is not None
        content = [
            {
                "type": "resource",
                "resource": {
                    "uri": source_resource_uri(binary.source_id),
                    "mimeType": binary.media_type,
                    "blob": base64.b64encode(binary.binary).decode("ascii"),
                },
            }
        ]
    return {"content": content, "structuredContent": envelope}


def _compact_json(value: object) -> str:
    """Serialize one MCP JSON value exactly as the text content arm does."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _source_read_text_character_wire_cost(character: str) -> int:
    """Price one source character in both text `CallToolResult` copies.

    The structured envelope JSON-escapes the character once. The text content
    arm embeds that compact envelope in another JSON string, escaping the first
    fragment a second time. `ensure_ascii=False` leaves ordinary Unicode,
    U+2028/U+2029, and non-BMP characters literal; JSON syntax and C0 controls
    are the only special cases.
    """
    if len(character) != 1:
        raise ValueError("text wire cost requires exactly one character")
    if character in {'"', "\\"}:
        return 6
    if character in {"\b", "\t", "\n", "\f", "\r"}:
        return 5
    if ord(character) < 0x20:
        return 13
    return 2 * len(character.encode("utf-8"))


def _approval_handoff(
    paths: RuntimePaths,
    change_set_id: str,
    revision_id: str,
    digest: str,
) -> dict[str, object]:
    """Name the two OS-verified routes that approve this exact revision.

    The command names the console entry point rather than an interpreter
    path, so it survives being pasted into another shell, and `--home` is
    appended only for a Store that is not on the default home: the common
    install then puts no filesystem path on this wire at all.
    """
    relocated = paths.root != default_root()
    argv = [
        "memory",
        "approve",
        change_set_id,
        "--revision",
        revision_id,
        "--digest",
        digest,
        *(("--home", str(paths.root)) if relocated else ()),
    ]
    return {
        "command": shlex.join(argv),
        # An instruction, not a locator. The owner UI binds an ephemeral port
        # and trades a one-use launch link for a session, so a path emitted
        # here has no origin to hang off it: nothing resolves `/reviews/<id>`,
        # and an agent relaying it hands the owner a string their browser
        # cannot open. What the owner can act on is the command that starts
        # the UI and the name of the page to open once it is running.
        #
        # A relocated Store points at `command` rather than repeating the
        # home: one copy of a filesystem path on this wire is the most the
        # handoff needs, and this field's own 512-byte budget was written for
        # a short path, not for a second `--home`.
        "review_path": (
            "Run `memory ui` with the same --home as `command`, "
            "then open Pending Reviews."
            if relocated
            else "Run `memory ui`, then open Pending Reviews."
        ),
    }


def _with_approval_handoff(
    error: StoreError,
    *,
    paths: RuntimePaths,
    name: str,
    arguments: Mapping[str, object] | None,
) -> StoreError:
    """Give a refused apply the exact invocation that approves its revision.

    Only the approval tool raises these two codes, and both leave the
    displayed revision unapplied. `approve_and_apply` validates the revision
    against the current draft and the digest against the stored revision
    before it raises either, so the triple echoed back here is already
    known-good; a stale revision or wrong digest fails earlier under its own
    code and carries no handoff. The caller's exact triple is echoed and the
    current draft is never substituted, because a handoff naming a revision
    the agent did not present is the one thing the approval contract exists
    to prevent.
    """
    if name != "change_set.approve_and_apply" or error.code not in (
        "owner_approval_required",
        "owner_declined",
    ):
        return error
    supplied = tuple(
        (arguments or {}).get(key) for key in ("change_set_id", "revision_id", "digest")
    )
    if not all(isinstance(value, str) for value in supplied):
        return error
    change_set_id, revision_id, digest = cast(tuple[str, str, str], supplied)
    details = dict(error.details or {})
    details["approval_handoff"] = _approval_handoff(
        paths, change_set_id, revision_id, digest
    )
    return type(error)(str(error), details=details)


def _tool_failure(error: StoreError) -> dict[str, object]:
    """Translate one typed Store failure into the mutually exclusive error arm.

    `retryable` comes from the exhaustive per-code table rather than a single
    hard-coded code, so `stale_cursor` -- whose entire remedy is "refetch and
    retry" -- stops being reported as terminal. An unlisted code reports
    terminal, which is the safe direction; the table is asserted exhaustive
    over the approved set in the suite rather than at runtime.

    `details` is copied verbatim with no filter against the declared schema, so
    every key any raiser can emit must be declared in `_ERROR_DETAILS_SCHEMA`
    or the envelope silently violates its own `additionalProperties: false`.
    """
    failure: dict[str, object] = {
        "code": error.code,
        "retryable": RETRYABLE_ERROR_CODES.get(error.code, False),
    }
    if error.details:
        failure["details"] = dict(error.details)
    envelope: dict[str, object] = {
        "schema": ENVELOPE_SCHEMA,
        "instruction_trust": INSTRUCTION_TRUST,
        "error": failure,
    }
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(
                    envelope,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            }
        ],
        "structuredContent": envelope,
        "isError": True,
    }


def _status_data(status: StoreStatus) -> dict[str, object]:
    return {
        "mcp_contract_digest": status.mcp_contract_digest,
        "memory_count": status.memory_count,
        "pending_review_count": status.pending_review_count,
        "product": status.product,
        "product_version": status.product_version,
        "reindex_required": status.reindex_required,
        "schema_version": status.schema_version,
        "searchable_count": status.searchable_count,
        "skill_digest": status.skill_digest,
        "source_count": status.source_count,
        "store_id": status.store_id,
        "unsearchable_count": status.unsearchable_count,
    }


def _source_data(source: SourceSummary) -> dict[str, object]:
    return {
        "authorship": source.authorship.value,
        "blob_digest": source.blob_digest,
        "byte_length": source.byte_length,
        "captured_at": source.captured_at,
        "declared_sensitivity": source.declared_sensitivity.value,
        "effective_sensitivity": source.effective_sensitivity.value,
        "media_type": source.media_type,
        "original_name": source.original_name,
        "origin": source.origin.value,
        "searchable": source.searchable,
        "source_id": source.source_id,
    }


def _batch_data(batch: InboxBatch) -> dict[str, object]:
    """Serialize one sealed batch with everything the Store already knew.

    `has_more` is named `batch_has_more` here. The envelope's `page.has_more`
    means "another page of batches"; this one means "eligible inbox files this
    scan deferred", and one wire name for two unrelated questions is the kind
    of collision a reader resolves wrongly and silently.
    """
    data: dict[str, object] = {
        "batch_has_more": batch.has_more,
        "batch_id": batch.batch_id,
        "duplicates": [
            _duplicate_capture_data(duplicate) for duplicate in batch.duplicates
        ],
        "issues": [_issue_data(issue.code, issue.count) for issue in batch.issues],
        "review_state": batch.review_state,
        "sealed_at": batch.sealed_at,
        "source_count": batch.source_count,
        "source_ids": list(batch.source_ids),
    }
    if batch.change_set_id is not None:
        data["change_set_id"] = batch.change_set_id
    if batch.application_id is not None:
        data["application_id"] = batch.application_id
    return data


def _duplicate_capture_data(duplicate: DuplicateCapture) -> dict[str, object]:
    return {
        "duplicate_of": duplicate.duplicate_of,
        "source_id": duplicate.source_id,
    }


def _facet_count_data(facet: FacetCount) -> dict[str, object]:
    return {"count": facet.count, "value": facet.value}


def _memory_facets_data(facets: MemoryFacets) -> dict[str, object]:
    return {
        "kinds": [_facet_count_data(facet) for facet in facets.kinds],
        "tags": [_facet_count_data(facet) for facet in facets.tags],
        "total_tags": facets.total_tags,
        "truncated": facets.truncated,
    }


def _batch_detail_data(detail: BatchDetail) -> dict[str, object]:
    return {
        "batch": _batch_data(detail.batch),
        "sources": [_source_data(source) for source in detail.sources],
    }


def _memory_summary_data(memory: MemorySummary) -> dict[str, object]:
    data: dict[str, object] = {
        "effective_sensitivity": memory.effective_sensitivity.value,
        "kind": memory.kind.value,
        "lineage_id": memory.lineage_id,
        "memory_id": memory.memory_id,
        "recorded_at": memory.recorded_at,
        "statement": memory.statement,
        "stored_sensitivity": memory.stored_sensitivity.value,
        "tags": list(memory.tags),
    }
    if memory.occurred_on is not None:
        data["occurred_on"] = memory.occurred_on
    if memory.valid_from is not None:
        data["valid_from"] = memory.valid_from
    if memory.valid_to is not None:
        data["valid_to"] = memory.valid_to
    return data


def _guard_attachment_data(attachment: GuardAttachment) -> dict[str, object]:
    # One shape serves both link directions; the array a reader finds it in
    # (guards versus governs) is what names the side, never a field here.
    return {
        "effective_sensitivity": attachment.effective_sensitivity.value,
        "kind": attachment.kind.value,
        "lineage_id": attachment.lineage_id,
        "memory_id": attachment.memory_id,
        "statement": attachment.statement,
    }


def _memory_search_hit_data(hit: MemorySearchHit) -> dict[str, object]:
    return {
        "guards": [_guard_attachment_data(guard) for guard in hit.guards],
        "match_strength": hit.match_strength.value,
        "memory": _memory_summary_data(hit.memory),
    }


def _memory_search_hit_wire_cost(
    hit: MemorySearchHit,
    first_on_page: bool,
) -> int:
    """Count one hit in both serialized MCP result arms without page rescans.

    The structured arm contains the compact hit directly. The text arm embeds
    that same compact JSON inside an already-open JSON string, so only the
    escaped string fragment counts -- not `json.dumps`' two surrounding quote
    bytes. Every hit after the first also adds one array comma in each arm.
    """
    compact = _compact_json(_memory_search_hit_data(hit))
    escaped_fragment = _compact_json(compact)[1:-1]
    separators = 0 if first_on_page else 2
    return (
        len(compact.encode("utf-8"))
        + len(escaped_fragment.encode("utf-8"))
        + separators
    )


def _memory_detail_data(detail: MemoryDetail) -> dict[str, object]:
    data: dict[str, object] = {
        "current_head_id": detail.current_head_id,
        "evidence": [_evidence_data(item) for item in detail.evidence],
        "governs": [_guard_attachment_data(item) for item in detail.governs],
        "guards": [_guard_attachment_data(item) for item in detail.guards],
        "is_current": detail.is_current,
        "revision": _memory_summary_data(detail.revision),
        "revision_ids": list(detail.revision_ids),
    }
    if detail.predecessor_id is not None:
        data["predecessor_id"] = detail.predecessor_id
    return data


def _change_set_data(view: ChangeSetView) -> dict[str, object]:
    return {
        "adapter_origin": view.adapter_origin.value,
        "batch_id": view.batch_id,
        "change_set_id": view.change_set_id,
        "digest": view.digest,
        "guard_links": [_draft_guard_link_data(link) for link in view.guard_links],
        "items": [_draft_item_data(item) for item in view.items],
        "revision_id": view.revision_id,
        "revoked_guard_links": [
            _draft_guard_link_data(link) for link in view.revoked_guard_links
        ],
        "source_decisions": [
            _source_decision_data(decision) for decision in view.source_decisions
        ],
        "state": view.state,
    }


def _draft_item_data(item: DraftItem) -> dict[str, object]:
    return {
        "evidence": [_evidence_data(locator) for locator in item.evidence],
        "item_id": item.item_id,
        "memory": _memory_fields_data(item.memory),
        "ordinal": item.ordinal,
        "status": item.status,
    }


def _memory_fields_data(memory: MemoryFields) -> dict[str, object]:
    return {
        "expected_head_id": memory.expected_head_id,
        "kind": memory.kind.value,
        "occurred_on": memory.occurred_on,
        "sensitivity": memory.sensitivity.value,
        "statement": memory.statement,
        "tags": list(memory.tags),
        "target_lineage_id": memory.target_lineage_id,
        "valid_from": memory.valid_from,
        "valid_to": memory.valid_to,
    }


def _evidence_data(locator: EvidenceLocator) -> dict[str, object]:
    data: dict[str, object] = {
        "blob_digest": locator.blob_digest,
        "mode": locator.mode,
        "ordinal": locator.ordinal,
        "source_id": locator.source_id,
    }
    if locator.mode == "text":
        data.update(
            {
                "char_end": locator.char_end,
                "char_start": locator.char_start,
                "excerpt": locator.excerpt,
            }
        )
    else:
        data["source_level"] = True
    return data


def _source_decision_data(decision: SourceDecision) -> dict[str, object]:
    return {
        "blob_digest": decision.blob_digest,
        "ordinal": decision.ordinal,
        "reason": decision.reason,
        "source_id": decision.source_id,
        "state": decision.state,
    }


def _draft_guard_link_data(link: DraftGuardLink) -> dict[str, object]:
    return {
        "governed_item_id": link.governed_item_id,
        "governed_lineage_id": link.governed_lineage_id,
        "guard_item_id": link.guard_item_id,
        "guard_lineage_id": link.guard_lineage_id,
        "ordinal": link.ordinal,
        "status": link.status,
    }


def _guard_violation_data(violation: GuardViolation) -> dict[str, object]:
    return {
        "governed_lineage_id": violation.governed_lineage_id,
        "governed_sensitivity": violation.governed_sensitivity.value,
        "guard_lineage_id": violation.guard_lineage_id,
        "guard_sensitivity": violation.guard_sensitivity.value,
    }


def _application_data(application: ApplicationResult) -> dict[str, object]:
    return {
        "application_id": application.application_id,
        "change_set_id": application.change_set_id,
        "idempotent_replay": application.idempotent_replay,
        "memory_ids": list(application.memory_ids),
        "revision_id": application.revision_id,
        "standing_guard_violations": [
            _guard_violation_data(violation)
            for violation in application.standing_guard_violations
        ],
    }


def _search_hit_data(hit: SourceSearchHit) -> dict[str, object]:
    """Serialize one source hit with the span the excerpt was cut from.

    The two match keys are omitted rather than nulled when the ladder admitted
    the row through the stemmed projection with no literal occurrence to point
    at, following the same convention `_chunk_data` uses: an absent key says
    "no such coordinate", where a null would need its own reading.
    """
    data: dict[str, object] = {
        "exact_excerpt": hit.exact_excerpt,
        "excerpt_char_end": hit.excerpt_char_end,
        "excerpt_char_start": hit.excerpt_char_start,
        "match_strength": hit.match_strength.value,
        "rank": hit.rank,
        "source": _source_data(hit.source),
    }
    if hit.match_char_start is not None:
        data["match_char_start"] = hit.match_char_start
    if hit.match_char_end is not None:
        data["match_char_end"] = hit.match_char_end
    return data


def _chunk_data(chunk: SourceChunk) -> dict[str, object]:
    data: dict[str, object] = {
        "blob_digest": chunk.blob_digest,
        "byte_end": chunk.byte_end,
        "byte_start": chunk.byte_start,
        "complete": chunk.complete,
        "media_type": chunk.media_type,
        "source_id": chunk.source_id,
    }
    if chunk.next_cursor is not None:
        data["next_cursor"] = chunk.next_cursor
    if chunk.text is not None:
        data.update(
            {
                "char_end": chunk.char_end,
                "char_start": chunk.char_start,
                "text": chunk.text,
            }
        )
    else:
        data["resource_content_index"] = chunk.resource_content_index
    return data


def _coverage_data(coverage: Coverage) -> dict[str, int]:
    return {
        "enumerated": coverage.enumerated,
        "searchable": coverage.searchable,
        "total": coverage.total,
        "unsearchable": coverage.unsearchable,
    }


def _page_data(
    page: Page[Any] | SourceSearchPage | MemorySearchPage,
) -> dict[str, object]:
    data: dict[str, object] = {"has_more": page.has_more}
    if page.next_cursor is not None:
        data["next_cursor"] = page.next_cursor
    return data


def _issue_data(code: str, count: int) -> dict[str, object]:
    return {"code": code, "count": count}


def run_stdio(paths: RuntimePaths, *, trust_elicitation: bool = False) -> None:
    """Validate the selected runtime, then run MCP on process stdio."""
    identity = load_runtime_identity(paths)
    connection = open_database(paths, load_master_key(identity), read_only=True)
    connection.close()
    create_server(paths, trust_elicitation=trust_elicitation).run(transport="stdio")
