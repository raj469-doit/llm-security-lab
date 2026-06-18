# 🔐 LLM Security Lab

![LLM Security Test Suite](https://github.com/raj469-doit/llm-security-lab/actions/workflows/security-tests.yml/badge.svg)



**Probing AI systems for vulnerabilities so your users don't find them first.**

Built and maintained by **Robert Johnson** — DevSecOps & Automation Engineer with 15+ years
hardening enterprise infrastructure, now specializing in LLM red-teaming and AI security validation.

---

## Why this repo exists

I spent 14 years at Ribbon Communications as the engineer enterprises called when
their systems were on fire. VoIP networks down. Carriers losing millions per hour.
My job was to get inside the system — deep log forensics, threat modeling, root-cause
analysis under pressure — and make it stop.

When I started watching AI companies ship LLM-powered products at speed, I saw the
same patterns I'd seen in telecom: move fast, integrate first, secure it later.
Except with LLMs, "later" can mean your chatbot leaking customer data, your AI agent
executing unintended actions, or your product being weaponized against your own users.

This lab is where I document that work — real vulnerability research, reproducible
test cases, and practical mitigations. Everything is built with the same Python
automation stack I've used in production: Pytest, Pydantic, Playwright, GitHub Actions.

---

## What I test for

Mapped to the **OWASP Top 10 for LLM Applications 2025**:

| # | Vulnerability | Payloads | Status |
|---|--------------|----------|--------|
| LLM01 | Prompt Injection | 12 | 🔬 Active research |
| LLM02 | Sensitive Information Disclosure | 13 | 🔬 Active research |
| LLM07 | System Prompt Leakage | 15 | 🔬 Active research |
| LLM05 | Improper Output Handling | — | 📋 Planned |
| LLM06 | Excessive Agency (Agentic AI misuse) | — | 📋 Planned |
| LLM08 | Vector and Embedding Weaknesses | — | 📋 Planned |

**Total active test cases: 40** — growing weekly.

---

## Repository structure

```
llm-security-lab/
├── attacks/                          # Test suites by vulnerability category
│   ├── prompt-injection/             # LLM01 — 12 payloads, 5 categories
│   ├── sensitive-info-disclosure/    # LLM02 — 13 payloads, 4 categories
│   └── system-prompt-leakage/        # LLM07 — 15 payloads, 5 categories
├── tools/                            # Reusable Python test utilities
├── reports/                          # Generated findings reports
├── checklists/                       # LLM Security Checklist (free resource)
└── .github/workflows/                # CI/CD — runs on every push
```

---

## How the three active modules chain together

These modules are intentionally sequenced to demonstrate real attack chains:

1. **LLM01 Prompt Injection** — attacker manipulates model behavior via crafted input
2. **LLM07 System Prompt Leakage** — attacker extracts system prompt to learn guardrails,
   credentials, and business logic
3. **LLM02 Sensitive Information Disclosure** — attacker pivots from application
   configuration to USER data — PII, cross-tenant leakage, and memorized training data

In a real engagement these rarely stay separate. A multi-tenant AI support agent is
vulnerable to all three in sequence: inject a malicious instruction, extract the
system's rules, then use those rules to pull another customer's data out of shared context.

The `SPL-04x` injection-assisted payloads and the `CTL-0xx` cross-tenant payloads
demonstrate this chain explicitly.

---

## Tech stack

```python
pytest          # Test orchestration and assertions
pydantic        # Input/output schema validation
playwright      # Headless UI interaction with AI-powered interfaces
requests        # Direct API probing
github_actions  # Automated CI execution of security test suites
```

Plus: **SQL**, **log analysis**, **PKI/TLS**, **Linux hardening** — the infrastructure
layer most LLM security researchers skip entirely.

---

## Running the lab

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
cp .env.example .env
# Edit .env with your API key and endpoint

# Run all active modules
pytest attacks/ -v

# Run with HTML report
pytest attacks/ -v --html=reports/findings.html --self-contained-html

# Run only critical severity tests
pytest attacks/ -v -k "critical"
```

---

## Featured modules

### 🔴 LLM01: Prompt Injection (`attacks/prompt-injection/`)
12 payloads across 5 categories: direct injection, indirect injection, role confusion,
instruction override, and obfuscation (adversarial suffix, multilingual, emoji encoding).
Automated severity scoring and markdown findings report.

### 🔴 LLM02: Sensitive Information Disclosure (`attacks/sensitive-info-disclosure/`)
13 payloads across 4 categories: PII leakage, cross-tenant leakage in multi-tenant
systems, training data extraction, and business data disclosure. Simulates a realistic
RAG knowledge base containing multiple customers' data to test isolation boundaries.

### 🔴 LLM07: System Prompt Leakage (`attacks/system-prompt-leakage/`)
15 payloads across 5 categories: direct extraction, completion priming, inference probing,
injection-assisted leakage, and persona bypass. Three-layer detection including regex
pattern matching for credentials and internal hostnames.

---

## About me

I'm a DevSecOps and Automation Engineer based in the DFW Metroplex. My background
spans 15+ years across telecom infrastructure, QA framework architecture, and
security engineering — with recent focused work in Python automation, cybersecurity,
and generative AI integration.

**Certifications:**
- Google Cybersecurity Professional Certificate
- ISC² Certified in Cybersecurity (CC)
- Generative AI Mastermind (Outskill)
- Google Data Analytics Professional Certificate
- Google AI Essentials

**Other projects:**
- [Weather Service Automation Suite](https://github.com/raj469-doit/weather-api-automation) — Production-grade Python/Pytest/Playwright CI framework
- [Cyclistic Bike Share Analysis](https://github.com/raj469-doit/cyclistic-bike-share-analysis) — Big data capstone using SQL, R, and Tableau

---

## Work with me

I offer **LLM Security Audits** for AI teams who want to know what's exploitable
before someone else finds it. Engagements are scoped, time-boxed, and delivered
as a written findings report with severity ratings and remediation guidance.

📬 [linkedin.com/in/robert-johnson-sdet](https://linkedin.com/in/robert-johnson-sdet)
📧 raj972@gmail.com

---

*This repository is for defensive security research and education. All testing is
performed in controlled environments against systems I am authorized to test.*
