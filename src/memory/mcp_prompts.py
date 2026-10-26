"""Derive MCP prompts from the packaged Skill instead of restating it.

A compatible client that supports Prompts had no way to reach the three
workflows the Skill teaches. Registering them is not permission to write a
second copy of that teaching: the wire text a client receives from
``prompts/get`` is sliced out of the packaged ``SKILL.md`` bytes, so the Skill
stays the single source of truth and a reworded step reaches prompt users on
the next serve without anyone remembering to mirror it.

What is pinned here is the *derivation*, never the wording. The Skill is
word-budgeted and grows; the structure it grows within is its ``##`` headings.
So the registry names sections, not sentences, and refuses to serve at all when
a named section is missing, renamed, or duplicated -- because the alternative,
quietly serving whichever sections still parse, is how a client ends up
following a workflow the Skill no longer teaches.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib.resources import files

#: One `## ` heading and everything up to the next one.
#:
#: Deliberately naive about fenced code: a fence containing a `## ` line would
#: end its enclosing section early and mint a section nobody named. The runtime
#: cannot refuse that -- every heading it requires is still present -- so the
#: suite pins the packaged heading inventory exactly instead. The runtime stays
#: tolerant of sections it does not name on purpose, so the Skill can grow a
#: section without a serving Store refusing to start.
_SECTION_HEADING = re.compile(r"(?m)^## (?P<title>.+)$")


@dataclass(frozen=True, slots=True)
class WorkflowSection:
    """One registered prompt bound to the packaged section it is sliced from."""

    #: Stable client-facing prompt name. Deliberately not derived from the
    #: heading: a client that has learned to reach for a prompt should not have
    #: its name change under it because an editor reworded a title.
    name: str
    #: The exact `##` heading whose body becomes this prompt's workflow message.
    section: str
    #: Server metadata for a prompt picker, authored here rather than sliced:
    #: it describes the prompt, where the body *is* the Skill.
    description: str


#: The section every workflow prompt carries first. It holds the inert-data
#: rule, the operation table, and the sensitivity contract, none of which a
#: workflow section restates, so a prompt that omitted it would teach a
#: procedure without the discipline the procedure depends on.
PREAMBLE_SECTION = "Core contract"

#: The four workflows, in served order.
WORKFLOW_SECTIONS: tuple[WorkflowSection, ...] = (
    WorkflowSection(
        name="answer_a_question",
        section="Answer a question",
        description=(
            "Answer one question from retained Store evidence, including the "
            "coverage fallback a thin ranked result requires."
        ),
    ),
    WorkflowSection(
        name="review_one_inbox_batch",
        section="Review one inbox batch",
        description=(
            "Turn one sealed inbox batch into one complete Memory Review and "
            "request one direct owner approval."
        ),
    ),
    WorkflowSection(
        name="review_one_captured_correction",
        section="Review one captured correction",
        description=(
            "Turn one already-sealed owner correction batch into one Memory "
            "Review against the captured lineage and head."
        ),
    ),
    WorkflowSection(
        name="advise_the_owner",
        section="Advise the owner",
        description=(
            "Advise the owner from retained evidence: orient on the standing "
            "set, surface due open loops, and answer with the application, "
            "freshness, and candor checks."
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class SkillPrompt:
    """One prompt whose two message bodies are packaged Skill bytes."""

    name: str
    section: str
    description: str
    preamble: str
    workflow: str


def packaged_skill_markdown() -> str:
    """Read the Skill the wheel actually ships, not a checkout beside it."""
    return files("memory").joinpath("skill", "SKILL.md").read_text(encoding="utf-8")


def skill_sections(markdown: str) -> dict[str, str]:
    """Split one packaged Markdown document into its `##` sections, in order.

    A section is its heading line through the byte before the next heading,
    with surrounding blank lines trimmed. Anything above the first heading --
    the frontmatter and the document title -- belongs to no section and is
    dropped, because neither is workflow text.
    """
    sections: dict[str, str] = {}
    matches = list(_SECTION_HEADING.finditer(markdown))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(markdown)
        title = match.group("title").strip()
        if title in sections:
            raise RuntimeError(
                "the packaged Skill repeats a section heading, so no prompt "
                "body can name one section unambiguously"
            )
        sections[title] = markdown[match.start() : end].strip("\n")
    return sections


def skill_prompts(markdown: str | None = None) -> tuple[SkillPrompt, ...]:
    """Slice the packaged Skill into the exact registered prompt bodies.

    Raises rather than serving a partial set. A missing or renamed section is
    an editing decision nobody has made about the prompt surface, and the
    server refusing to start is how that decision gets made instead of being
    silently answered with stale text.
    """
    document = packaged_skill_markdown() if markdown is None else markdown
    sections = skill_sections(document)
    required = (PREAMBLE_SECTION, *(workflow.section for workflow in WORKFLOW_SECTIONS))
    missing = [heading for heading in required if heading not in sections]
    if missing:
        raise RuntimeError(
            f"the packaged Skill is missing {len(missing)} section(s) the MCP "
            "prompt registry names"
        )
    preamble = sections[PREAMBLE_SECTION]
    return tuple(
        SkillPrompt(
            name=workflow.name,
            section=workflow.section,
            description=workflow.description,
            preamble=preamble,
            workflow=sections[workflow.section],
        )
        for workflow in WORKFLOW_SECTIONS
    )
