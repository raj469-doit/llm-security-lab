# Attacks

Each subfolder contains a focused test suite for a specific OWASP LLM vulnerability category.

| Folder | OWASP ID | Status |
| --- | --- | --- |
| `prompt-injection/` | LLM01 | 🔬 Active |
| `data-exfiltration/` | LLM06 | 📋 Coming Week 2 |
| `insecure-output/` | LLM02 | 📋 Coming Week 3 |
| `excessive-agency/` | LLM08 | 📋 Coming Week 3 |

## Running a specific suite

    # Run all prompt injection tests
    pytest attacks/prompt-injection/ -v
    
    # Run with HTML report output
    pytest attacks/prompt-injection/ -v --html=reports/findings.html --self-contained-html
    
    # Run only critical severity tests
    pytest attacks/prompt-injection/ -v -k "critical"

## Environment setup

Copy `.env.example` to `.env` and fill in your credentials:

    cp .env.example .env

Never commit `.env` to version control.
