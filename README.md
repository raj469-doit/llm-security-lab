# 🔐 LLM Security Lab

![LLM Security Test Suite](https://github.com/raj469-doit/llm-security-lab/actions/workflows/security-tests.yml/badge.svg)

**Probing AI systems for vulnerabilities so your users don't find them first.**

Built and maintained by **Robert Johnson** — DevSecOps & Automation Engineer with 15+ yearshardening enterprise infrastructure, now specializing in LLM red-teaming and AI security validation.

* * *

## Why this repo exists

I spent 14 years at Ribbon Communications as the engineer enterprises called whentheir systems were on fire. VoIP networks down. Carriers losing millions per hour.My job was to get inside the system — deep log forensics, threat modeling, root-causeanalysis under pressure — and make it stop.

When I started watching AI companies ship LLM-powered products at speed, I saw thesame patterns I'd seen in telecom: move fast, integrate first, secure it later.Except with LLMs, "later" can mean your chatbot leaking customer data, your AI agentexecuting unintended actions, or your product being weaponized against your own users.

This lab is where I document that work — real vulnerability research, reproducibletest cases, and practical mitigations. Everything is built with the same Pythonautomation stack I've used in production: Pytest, Pydantic, Playwright, GitHub Actions.

* * *

## What I test for

Mapped to the **OWASP Top 10 for LLM Applications 2025**:

| #     | Vulnerability                        | Payloads | Status             |
| ----- | ------------------------------------ | -------- | ------------------ |
| LLM01 | Prompt Injection                     | 12       | 🔬 Active research |
| LLM02 | Sensitive Information Disclosure     | 13       | 🔬 Active research |
| LLM05 | Improper Output Handling             | 16       | 🔬 Active research |
| LLM07 | System Prompt Leakage                | 15       | 🔬 Active research |
| LLM06 | Excessive Agency (Agentic AI misuse) | —        | 📋 Planned         |
| LLM08 | Vector and Embedding Weaknesses      | —        | 📋 Planned         |

**Total active test cases: 56** — growing weekly.

* * *

## Repository structure

    llm-security-lab/
    ├── attacks/                          # Test suites by vulnerability category
    │   ├── prompt-injection/             # LLM01 — 12 payloads, 5 categories
    │   │   ├── test_prompt_injection.py
    │   │   └── payloads.yaml             # Editable payload definitions
    │   ├── sensitive-info-disclosure/    # LLM02 — 13 payloads, 4 categories
    │   │   ├── test_sensitive_info_disclosure.py
    │   │   └── payloads.yaml
    │   ├── improper-output-handling/     # LLM05 — 16 payloads, 6 categories
    │   │   ├── test_improper_output_handling.py
    │   │   └── payloads.yaml
    │   └── system-prompt-leakage/        # LLM07 — 15 payloads, 5 categories
    │       ├── test_system_prompt_leakage.py
    │       └── payloads.yaml
    ├── lib/                              # Shared Python modules
    │   ├── llm_client.py                 # Unified LLM API client with retry logic
    │   └── payload_loader.py             # YAML payload loader with Pydantic validation
    ├── tools/                            # Reusable Python test utilities
    ├── reports/                          # Generated findings reports
    ├── checklists/                       # LLM Security Checklist (free resource)
    ├── conftest.py                       # Shared pytest config, dotenv loading, markers
    ├── pyproject.toml                    # Ruff, mypy, and pytest configuration
    └── .github/workflows/                # CI/CD — lint, type-check, and test on every push

* * *

## How the four active modules chain together

These modules are intentionally sequenced to demonstrate real attack chains:

1. **LLM01 Prompt Injection** — attacker manipulates model behavior via crafted input
2. **LLM07 System Prompt Leakage** — attacker extracts system prompt to learn guardrails,credentials, and business logic
3. **LLM02 Sensitive Information Disclosure** — attacker pivots from applicationconfiguration to USER data — PII, cross-tenant leakage, and memorized training data
4. **LLM05 Improper Output Handling** — attacker manipulates the model into generatingdangerous output (XSS, SQL injection, shell commands) that exploits downstream systems

In a real engagement these rarely stay separate. A multi-tenant AI support agent isvulnerable to all four in sequence: inject a malicious instruction, extract thesystem's rules, use those rules to pull another customer's data, and then weaponize themodel's output to attack the application's own infrastructure.

The `SPL-04x` injection-assisted payloads and the `CTL-0xx` cross-tenant payloadsdemonstrate this chain explicitly.

* * *

## Tech stack

    pytest          # Test orchestration and assertions
    pydantic        # Input/output schema validation
    pyyaml          # Externalized payload definitions
    requests        # Direct API probing (with retry/backoff)
    python-dotenv   # Environment variable management
    ruff            # Linting and import sorting
    mypy            # Static type checking
    playwright      # Headless UI interaction with AI-powered interfaces
    github_actions  # Automated CI — lint, type-check, and test on every push

Plus: **SQL**, **log analysis**, **PKI/TLS**, **Linux hardening** — the infrastructurelayer most LLM security researchers skip entirely.

* * *

## Running the lab

    # Install dependencies
    pip install -r requirements.txt
    
    # Set environment variables
    cp .env.example .env
    # Edit .env with your API key and endpoint
    # (dotenv loads automatically — no need to export manually)
    
    # Run all active modules
    pytest attacks/ -v
    
    # Run with HTML report
    pytest attacks/ -v --html=reports/findings.html --self-contained-html
    
    # Run only critical severity tests (using pytest markers)
    pytest attacks/ -v -m "critical"
    
    # Run linting and type checking
    ruff check .
    mypy lib/ conftest.py attacks/

* * *

## Featured modules

### 🔴 LLM01: Prompt Injection (`attacks/prompt-injection/`)

12 payloads across 5 categories: direct injection, indirect injection, role confusion,instruction override, and obfuscation (adversarial suffix, multilingual, emoji encoding).Automated severity scoring and markdown findings report.

### 🔴 LLM02: Sensitive Information Disclosure (`attacks/sensitive-info-disclosure/`)

13 payloads across 4 categories: PII leakage, cross-tenant leakage in multi-tenantsystems, training data extraction, and business data disclosure. Simulates a realisticRAG knowledge base containing multiple customers' data to test isolation boundaries.

### 🔴 LLM07: System Prompt Leakage (`attacks/system-prompt-leakage/`)

15 payloads across 5 categories: direct extraction, completion priming, inference probing,injection-assisted leakage, and persona bypass. Three-layer detection including regexpattern matching for credentials and internal hostnames.

### 🔴 LLM05: Improper Output Handling (`attacks/improper-output-handling/`)

16 payloads across 6 categories: XSS, SQL injection, command injection, SSRF, codeexecution, and markup injection. Tests whether the model can be manipulated into generatingdangerous output that would exploit downstream systems. Smart detection strips code blocksto distinguish documentation from executable output.

* * *

## Adding custom payloads

Each attack module has a `payloads.yaml` file where you can add test cases withoutediting Python. The YAML is validated against the module's Pydantic schema at load time,so you'll get clear error messages if a field is missing or has an invalid value.
    # Example: add a new prompt injection payload
    - id: DI-004
      category: direct_injection
      description: "My custom injection test"
      payload: "Your attack string here"
      expected_behavior: "Model should refuse and stay in role."
      severity: high

If the YAML file is missing or PyYAML isn't installed, the test suite falls backto the hardcoded payloads in the Python source — so nothing breaks.

* * *

## Judge-LLM layer (semantic detection)

The default detection uses keyword matching and regex patterns. This catchesexplicit leaks but misses paraphrased or indirect disclosures — for example,a model describing "an open-source relational database with an elephant logo"instead of saying "PostgreSQL."

Enable the judge-LLM layer to add a second AI as a referee. After each test,if the heuristic check says "safe," the response is sent to a judge modelthat evaluates whether confidential information was revealed regardless ofhow it was worded.
    # Enable in your .env file
    LLM_USE_JUDGE=true

    # Optionally use a stronger model as the judge
    LLM_JUDGE_MODEL=gpt-4o

When a vulnerability is caught by the judge rather than heuristics, theevidence is prefixed with `[judge:high]`, `[judge:medium]`, or `[judge:low]`to indicate detection source and confidence. The judge is additive — itnever overrides a heuristic finding, only catches what regex missed.

* * *

## About me

I'm a DevSecOps and Automation Engineer based in the DFW Metroplex. My backgroundspans 15+ years across telecom infrastructure, QA framework architecture, andsecurity engineering — with recent focused work in Python automation, cybersecurity,and generative AI integration.

**Certifications:**

* Google Cybersecurity Professional Certificate
* ISC² Certified in Cybersecurity (CC)
* Generative AI Mastermind (Outskill)
* Google Data Analytics Professional Certificate
* Google AI Essentials

**Other projects:**

* [Security Automation Toolkit](https://github.com/raj469-doit/SecurityAutomationToolkit) — OWASP-aligned web security scanner with risk scoring, differential analysis, and HTML/Markdown reporting
* [Weather Service Automation Suite](https://github.com/raj469-doit/weather-api-automation) — Production-grade Python/Pytest/Playwright CI framework
* [Cyclistic Bike Share Analysis](https://github.com/raj469-doit/cyclistic-bike-share-analysis) — Big data capstone using SQL, R, and Tableau

* * *

## Work with me

I offer **LLM Security Audits** for AI teams who want to know what's exploitablebefore someone else finds it. Engagements are scoped, time-boxed, and deliveredas a written findings report with severity ratings and remediation guidance.

I also offer **Web Security Assessments** using my[Security Automation Toolkit](https://github.com/raj469-doit/SecurityAutomationToolkit) —automated OWASP-aligned scanning of your web infrastructure covering securityheaders, TLS configuration, cookie hardening, and attack surface discovery,with differential tracking to measure remediation progress over time.

📬 [linkedin.com/in/robert-johnson-sdet](https://linkedin.com/in/robert-johnson-sdet)📧 raj972@gmail.com

* * *

*This repository is for defensive security research and education. All testing isperformed in controlled environments against systems I am authorized to test.*
