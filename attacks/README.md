# Attacks

Each subfolder contains a focused test suite for a specific OWASP LLM vulnerability category.

| Folder | OWASP ID | Status |
| --- | --- | --- |
| LLM01 | Prompt Injection | 🔬 Active research |
| LLM02 | Sensitive Information Disclosure | 🔬 Active research |
| LLM05 | Improper Output Handling | 📋 Planned |
| LLM06 | Excessive Agency (Agentic AI misuse) | 📋 Planned |
| LLM07 | System Prompt Leakage | 🔬 Active research
| LLM08 | Vector and Embedding Weaknesses | 📋 Planned |
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
