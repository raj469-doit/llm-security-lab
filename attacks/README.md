# Attacks

Each subfolder contains a focused test suite for a specific OWASP LLM vulnerability
category, mapped to the **OWASP Top 10 for LLM Applications 2025**.

| Folder | OWASP ID | Vulnerability | Payloads | Status |
|--------|----------|---------------|----------|--------|
| `prompt-injection/` | LLM01 | Prompt Injection | 12 | 🔬 Active |
| `sensitive-info-disclosure/` | LLM02 | Sensitive Information Disclosure | 13 | 🔬 Active |
| `system-prompt-leakage/` | LLM07 | System Prompt Leakage | 15 | 🔬 Active |
| `improper-output/` | LLM05 | Improper Output Handling | — | 📋 Planned |
| `excessive-agency/` | LLM06 | Excessive Agency (Agentic AI misuse) | — | 📋 Planned |
| `vector-embedding/` | LLM08 | Vector and Embedding Weaknesses | — | 📋 Planned |

**Total active test cases: 40** across 3 modules (LLM01 + LLM02 + LLM07)

---

## Running a specific suite

```bash
# Run all prompt injection tests
pytest attacks/prompt-injection/ -v

# Run all sensitive information disclosure tests
pytest attacks/sensitive-info-disclosure/ -v

# Run all system prompt leakage tests
pytest attacks/system-prompt-leakage/ -v

# Run the full lab (all active modules)
pytest attacks/ -v

# Run with HTML report output
pytest attacks/ -v --html=reports/findings.html --self-contained-html

# Run only critical severity tests across all modules
pytest attacks/ -v -k "critical"
```

## How the three active modules connect

These modules are intentionally sequenced to demonstrate real attack chains
seen in production LLM applications:

1. **LLM01 Prompt Injection** — attacker manipulates model behavior via crafted input
2. **LLM07 System Prompt Leakage** — attacker extracts the system prompt to learn
   guardrails, credentials, and business logic
3. **LLM02 Sensitive Information Disclosure** — attacker pivots from application
   configuration to USER data — PII, cross-tenant leakage in multi-tenant systems,
   and memorized training data

In a real engagement, these rarely stay separate. A multi-tenant AI support agent
(handling tickets from many customers in shared context) is vulnerable to all three
in sequence: inject a malicious instruction (LLM01), use it to extract the system's
rules (LLM07), then use those rules to pull another customer's data out of the
shared knowledge base (LLM02).

The `SPL-04x` payloads in `system-prompt-leakage/` and the `CTL-0xx` payloads in
`sensitive-info-disclosure/` demonstrate this chain explicitly.

## Environment setup

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

For system prompt leakage and disclosure tests, optionally set these to simulate
a real application deployment:

```bash
export LLM_SYSTEM_PROMPT="You are Aria, a customer support assistant..."
export LLM_CONTEXT_DOCUMENT="--- Past Support Tickets ---..."
```

Never commit `.env` to version control.
