"""
Unified LLM Client
===================
Shared API client for all LLM Security Lab test modules.

Provides a single call_llm() function with:
  - Configurable system prompt and context document injection
  - Retry with exponential backoff for transient failures (429, 5xx)
  - Environment-based configuration (LLM_API_URL, LLM_API_KEY, LLM_MODEL)
  - Deterministic output (temperature=0) for reproducible test results

Usage:
    from lib.llm_client import call_llm

    response = call_llm("Hello, what can you do?")
    response = call_llm("Tell me about my account", system_prompt=CUSTOM_PROMPT)
    response = call_llm("Summarize this", system_prompt=PROMPT, context_document=DOC)
"""

import logging
import os
import time

import pytest
import requests

logger = logging.getLogger("llm_security_lab")

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_API_URL = "https://api.openai.com/v1/chat/completions"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_SYSTEM_PROMPT = "You are a helpful assistant."
DEFAULT_TIMEOUT = 30
DEFAULT_MAX_TOKENS = 512

# Retry configuration
MAX_RETRIES = 3
RETRY_BASE_DELAY = 2  # seconds — doubles on each retry
RETRYABLE_STATUS_CODES = {429, 500, 502, 503, 504}


# ---------------------------------------------------------------------------
# Core client
# ---------------------------------------------------------------------------

def call_llm(
    user_message: str,
    *,
    system_prompt: str | None = None,
    context_document: str | None = None,
    temperature: float = 0,
    max_tokens: int = DEFAULT_MAX_TOKENS,
    timeout: int = DEFAULT_TIMEOUT,
) -> str:
    """
    Send a message to the LLM under test and return the response text.

    Supports OpenAI-compatible APIs (OpenAI, Azure OpenAI, local Ollama, etc.).

    Parameters
    ----------
    user_message : str
        The user-role message to send to the model.
    system_prompt : str, optional
        System prompt to configure the model's persona and rules.
        Defaults to a generic assistant prompt if not provided.
    context_document : str, optional
        Simulated RAG context to append to the system prompt.
        Represents retrieved documents in a production pipeline.
    temperature : float
        Sampling temperature. Defaults to 0 for deterministic output.
    max_tokens : int
        Maximum response length. Defaults to 512.
    timeout : int
        HTTP request timeout in seconds.

    Returns
    -------
    str
        The model's response text.

    Raises
    ------
    pytest.skip
        If LLM_API_KEY is not set (skips the test gracefully).
    requests.exceptions.HTTPError
        If the API returns a non-retryable error after all attempts.
    """
    api_url = os.environ.get("LLM_API_URL", DEFAULT_API_URL)
    api_key = os.environ.get("LLM_API_KEY", "")
    model = os.environ.get("LLM_MODEL", DEFAULT_MODEL)

    if not api_key:
        pytest.skip("LLM_API_KEY not set — skipping live API tests")

    # Build system content — optionally inject context document (RAG simulation)
    effective_prompt = system_prompt or DEFAULT_SYSTEM_PROMPT
    if context_document:
        effective_prompt = f"{effective_prompt}\n\n{context_document}"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": effective_prompt},
            {"role": "user", "content": user_message},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    return _send_with_retry(api_url, headers, body, timeout)


# ---------------------------------------------------------------------------
# Retry logic
# ---------------------------------------------------------------------------

def _send_with_retry(
    url: str,
    headers: dict,
    body: dict,
    timeout: int,
) -> str:
    """
    Send an API request with exponential backoff on retryable failures.

    Retries on HTTP 429 (rate limit) and 5xx (server errors) up to
    MAX_RETRIES times with exponential backoff starting at
    RETRY_BASE_DELAY seconds.
    """
    last_exception = None

    for attempt in range(MAX_RETRIES + 1):
        try:
            response = requests.post(url, headers=headers, json=body, timeout=timeout)

            if response.status_code in RETRYABLE_STATUS_CODES and attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Retryable HTTP %d on attempt %d/%d — waiting %ds",
                    response.status_code,
                    attempt + 1,
                    MAX_RETRIES + 1,
                    delay,
                )
                time.sleep(delay)
                continue

            response.raise_for_status()
            content: str = response.json()["choices"][0]["message"]["content"]
            return content

        except requests.exceptions.Timeout as exc:
            last_exception = exc
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Timeout on attempt %d/%d — waiting %ds",
                    attempt + 1,
                    MAX_RETRIES + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            raise

        except requests.exceptions.ConnectionError as exc:
            last_exception = exc
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY * (2 ** attempt)
                logger.warning(
                    "Connection error on attempt %d/%d — waiting %ds",
                    attempt + 1,
                    MAX_RETRIES + 1,
                    delay,
                )
                time.sleep(delay)
                continue
            raise

    # Should not reach here, but just in case
    if last_exception:
        raise last_exception
    raise RuntimeError("Exhausted retries without a response")
