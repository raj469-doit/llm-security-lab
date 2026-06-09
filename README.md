# 🔐 LLM Security Lab

[![LLM Security Test Suite](https://github.com/raj469-doit/llm-security-lab/actions/workflows/security-tests.yml/badge.svg)](https://github.com/raj469-doit/llm-security-lab/actions/workflows/security-tests.yml)

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

This lab maps directly to the **OWASP Top 10 for LLM Applications**:

| # | Vulnerability | Status |
|---|--------------|--------|
| LLM01 | Prompt Injection | 🔬 Active research |
| LLM02 | Insecure Output Handling | 🔬 Active research |
| LLM03 | Training Data Poisoning | 📋 Planned |
| LLM06 | Sensitive Information Disclosure | 🔬 Active research |
| LLM08 | Excessive Agency (Agentic AI misuse) | 📋 Planned |

---

## Repository structure

```
llm-security-lab/
├── attacks/              # Documented attack notebooks by vulnerability type
│   ├── prompt-injection/
│   └── data-exfiltration/
├── tools/                # Reusable Python test utilities and harnesses
├── reports/              # Sample audit report templates
├── checklists/           # LLM Security Checklist (free resource)
└── docs/                 # Research notes and references
```

---

## Tech stack

```python
# Core testing stack
pytest          # Test orchestration and assertions
pydantic        # Input/output schema validation
playwright      # Headless UI interaction with AI-powered interfaces
requests        # Direct API probing
github_actions  # Automated CI execution of security test suites
```

Plus: **SQL**, **log analysis**, **PKI/TLS**, **Linux hardening** — the infrastructure
layer most LLM security researchers skip entirely.

---

## Featured work

### 🧪 Prompt Injection Test Suite *(coming Week 1)*
A structured Pytest framework for testing LLM API endpoints against direct and
indirect prompt injection. Includes automated severity scoring and markdown report generation.

### 📋 LLM Security Checklist *(coming Week 2)*
A free, practical checklist for AI teams to assess their LLM product against the
OWASP Top 10. No vendor lock-in, no sales pitch.

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
