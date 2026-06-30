# Attacks

Each subfolder contains a focused test suite for a specific OWASP LLM vulnerability
category, mapped to the **OWASP Top 10 for LLM Applications 2025**.

| Folder | OWASP ID | Vulnerability | Payloads | Status |
|--------|----------|---------------|----------|--------|
| `prompt-injection/` | LLM01 | Prompt Injection | 12 | 🔬 Active |
| `sensitive-info-disclosure/` | LLM02 | Sensitive Information Disclosure | 13 | 🔬 Active |
| `excessive-agency/` | LLM06 | Excessive Agency (Agentic AI misuse) | 21 | 🔬 Active |
| `system-prompt-leakage/` | LLM07 | System Prompt Leakage | 15 | 🔬 Active |
| `improper-output/` | LLM05 | Improper Output Handling | — | 📋 Planned |
| `vector-embedding/` | LLM08 | Vector and Embedding Weaknesses | — | 📋 Planned |

**Total active test cases: 61** across 4 modules (LLM01 + LLM02 + LLM06 + LLM07)

---

## Running a specific suite

```bash
# Run all prompt injection tests
pytest attacks/prompt-injection/ -v

# Run all sensitive information disclosure tests
pytest attacks/sensitive-info-disclosure/ -v

# Run all excessive agency tests
pytest attacks/excessive-agency/ -v

# Run all system prompt leakage tests
pytest attacks/system-prompt-leakage/ -v

# Run the full lab (all active modules)
pytest attacks/ -v

# Run with HTML report output
pytest attacks/ -v --html=reports/findings.html --self-contained-html

# Run only critical severity tests across all modules
pytest attacks/ -v -k "critical"
```

## How the four active modules connect

These modules are intentionally sequenced to demonstrate real attack chains
seen in production LLM applications:

1. **LLM01 Prompt Injection** — attacker manipulates model behavior via crafted input
2. **LLM07 System Prompt Leakage** — attacker extracts the system prompt to learn
   guardrails, credentials, and business logic
3. **LLM02 Sensitive Information Disclosure** — attacker pivots from application
   configuration to USER data — PII, cross-tenant leakage in multi-tenant systems,
   and memorized training data
4. **LLM06 Excessive Agency** — attacker triggers the agent to take real-world
   actions — sending emails, deleting accounts, executing SQL, exfiltrating data
   via tool chaining

In a real engagement, these rarely stay separate. An agentic AI support system
(handling tickets, managing subscriptions, accessing databases) is vulnerable
to all four in sequence: inject a malicious instruction (LLM01), extract the
system's rules (LLM07), access another customer's data (LLM02), then trigger
the agent to exfiltrate that data or take destructive action (LLM06).

The `SPL-04x` payloads in `system-prompt-leakage/`, the `CTL-0xx` payloads in
`sensitive-info-disclosure/`, and the `IAL-0xx` payloads in `excessive-agency/`
demonstrate these chains explicitly.

## Environment setup

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

For modules that simulate real application deployments, optionally set:

```bash
# System prompt for the application under test
export LLM_SYSTEM_PROMPT="You are Aria, a customer support assistant..."

# Multi-tenant context for LLM02 disclosure testing
export LLM_CONTEXT_DOCUMENT="--- Past Support Tickets ---..."
```

The LLM06 excessive agency module uses its own `DEFAULT_AGENT_SYSTEM_PROMPT`
which configures an agent with 8 tools and decision-making rules. Override via
`LLM_SYSTEM_PROMPT` to test your own agent's tool configuration.

Never commit `.env` to version control.
