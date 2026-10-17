"""Bounded failure feedback for dynamic-test repair (never verdict evidence)."""

import hashlib
import json

from utilities.llm._redact import redact_secrets


MAX_ERROR_FEEDBACK = 6000
_TRUNCATED = "\n[... diagnostic truncated; beginning and end retained ...]\n"


def bounded_diagnostic(text: str, limit: int = MAX_ERROR_FEEDBACK) -> str:
    """Redact before clipping, so truncation cannot expose a partial credential."""
    text = redact_secrets(text)
    if len(text) <= limit:
        return text
    keep = max(0, limit - len(_TRUNCATED))
    head = keep // 2
    tail = keep - head
    return text[:head] + _TRUNCATED[:limit] + (text[-tail:] if tail else "")


def error_feedback(result, execution) -> str:
    """Keep structured ERROR evidence, even when the runner exits successfully.

    Give each diagnostic channel a bounded share; a noisy stderr must not
    crowd the actual compiler/application error out of the repair prompt.
    The final prompt fences this whole block as untrusted diagnostic data.
    """
    channels = []
    if execution.build_error:
        channels.append(("Build output", execution.build_error))
    if execution.stderr and execution.stderr != execution.build_error:
        channels.append(("Standard error", execution.stderr))
    outputs = [e.content for e in result.evidence if e.content]
    if outputs:
        # Evidence is already bounded by the collector. Retain both ends if
        # a test returns many items; no unbounded output reaches the model.
        channels.append(("Structured failure evidence", "\n\n".join(outputs)))
    details = "Failure details:\n" + bounded_diagnostic(result.details, 1000)
    if not channels:
        return bounded_diagnostic(result.details)
    budget = (MAX_ERROR_FEEDBACK - len(details) - 200) // len(channels)
    return details + "\n\n" + "\n\n".join(
        label + ":\n" + bounded_diagnostic(content, budget)
        for label, content in channels
    )


def failed_attempt_key(generation: dict, execution) -> str:
    """Only identical executable artifacts AND raw failures imply no progress.

    Do not compare clipped/redacted feedback: distinct diagnostics could then
    collide. Changed code, dependencies, filenames or compose configuration
    must get a chance even if the error happens to be the same. Metadata such
    as the model's explanation has no effect on the executed test.
    """
    fields = ("dockerfile", "test_script", "test_filename", "requirements",
              "requirements_filename", "docker_compose", "needs_attacker_server",
              "native_language")
    payload = {
        "generation": {key: generation.get(key) for key in fields},
        "failure": {key: getattr(execution, key, None) for key in (
            "build_error", "execution_error", "stdout", "stderr", "exit_code", "timed_out")},
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
