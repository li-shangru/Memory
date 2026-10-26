"""Served evidence-discovery teaching, separate from model-answer evidence."""

from memory.mcp_prompts import skill_prompts


def test_served_answer_requires_semantic_fallback_and_complete_caveat_checks() -> None:
    """Catch lexical absence or a plausible preview ending discovery early."""
    prompt = next(
        prompt for prompt in skill_prompts() if prompt.name == "answer_a_question"
    )
    teaching = " ".join(prompt.workflow.split())

    assert (
        "A complete lexical scan can miss paraphrases and cross-language evidence"
        in teaching
    )
    assert "A preview cannot rule out a late caveat" in teaching
    assert (
        "Do not exclude a source because its name or preview lacks query terms"
        in teaching
    )
    assert "When metadata cannot establish irrelevance, read it" in teaching
    assert "keep the unread remainder explicit" in teaching
    assert "current approved heads and revision history" in teaching
    assert "every guard" in teaching
    assert "For unresolved coverage" in teaching
    assert "Complete any required fallback before answering" in teaching
    assert "Answer only after fallback" not in teaching
    assert "source.read" in teaching
    assert "memory.search" in teaching
