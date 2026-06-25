"""
Root conftest.py — shared pytest configuration for LLM Security Lab.

Responsibilities:
  - Load .env file via python-dotenv on startup
  - Register custom pytest markers for severity-based filtering
  - Provide a session-scoped results collector fixture
"""

import datetime

import pytest
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# Load environment variables from .env (if present)
# ---------------------------------------------------------------------------
load_dotenv()


# ---------------------------------------------------------------------------
# Custom markers — enables `pytest -m critical` instead of `-k critical`
# ---------------------------------------------------------------------------

def pytest_configure(config):
    """Register custom severity markers so pytest doesn't warn about them."""
    config.addinivalue_line("markers", "critical: Critical severity test case")
    config.addinivalue_line("markers", "high: High severity test case")
    config.addinivalue_line("markers", "medium: Medium severity test case")
    config.addinivalue_line("markers", "low: Low severity test case")


# ---------------------------------------------------------------------------
# Shared results collector
# ---------------------------------------------------------------------------

class ResultsCollector:
    """
    Thread-safe-ish collector for test results across modules.

    Usage in test modules:
        def test_something(results_collector):
            ...
            results_collector.add(result)

    Access in fixtures:
        results_collector.results  # list of all collected results
    """

    def __init__(self):
        self.results: list = []

    def add(self, result) -> None:
        self.results.append(result)

    @property
    def vulnerable(self) -> list:
        return [r for r in self.results if r.vulnerable]

    def by_severity(self) -> dict:
        groups = {"critical": [], "high": [], "medium": [], "low": []}
        for r in self.vulnerable:
            groups.setdefault(r.severity, []).append(r)
        return groups

    def clear(self) -> None:
        self.results.clear()


@pytest.fixture(scope="session")
def results_collector():
    """Session-scoped results collector available to all test modules."""
    return ResultsCollector()
