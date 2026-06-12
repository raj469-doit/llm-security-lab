# Attacks

Each subfolder contains a focused test suite for a specific OWASP LLM vulnerability
category, mapped to the **OWASP Top 10 for LLM Applications 2025**.

| Folder | OWASP ID | Vulnerability | Payloads | Status |
|--------|----------|---------------|----------|--------|
| `prompt-injection/` | LLM01 | Prompt Injection | 12 | 🔬 Active |
| `system-prompt-leakage/` | LLM07 | System Prompt Leakage | 15 | 🔬 Active |
| `sensitive-info-disclosure/` | LLM02 | Sensitive Information Disclosure | — | 📋 Planned |
| `improper-output/` | LLM05 | Improper Output Handling | — | 📋 Planned |
| `excessive-agency/` | LLM06 | Excessive Agency (Agentic AI misuse) | — | 📋 Planned |
| `vector-embedding/` | LLM08 | Vector and Embedding Weaknesses | — | 📋 Planned |

**Total active test cases: 27** across 2 modules (LLM01 + LLM07)

---

## Running a specific suite

```bash
# Run all prompt injection tests
pytest attacks/prompt-injection/ -v

# Run all system prompt leakage tests
pytest attacks/system-prompt-leakage/ -v

# Run the full lab (all active modules)
pytest attacks/ -v

# Run with HTML report output
pytest attacks/ -v --html=reports/findings.html --self-contained-html

# Run only critical severity tests across all modules
pytest attacks/ -v -k "critical"
```

## How LLM01 and LLM07 chain together

These two modules are intentionally sequenced. In real-world attacks:

1. **LLM01 Prompt Injection** — attacker manipulates model behavior via crafted input
2. **LLM07 System Prompt Leakage** — attacker extracts the system prompt to learn guardrails,
   credentials, and business logic
3. Armed with that knowledge, they return to LLM01 with a *targeted* bypass

The `SPL-04x` payloads in `system-prompt-leakage/` demonstrate this chain explicitly.

## Environment setup

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

For system prompt leakage tests, optionally set `LLM_SYSTEM_PROMPT` to the
actual system prompt of the application under test:

```bash
export LLM_SYSTEM_PROMPT="You are Aria, a customer support assistant..."
```

Never commit `.env` to version control.
