# LLM Security Checklist
### Mapped to OWASP Top 10 for LLM Applications 2025

**Author:** Robert Johnson — LLM Security Engineer  
**GitHub:** [llm-security-lab](https://github.com/raj469-doit/llm-security-lab)  
**LinkedIn:** [linkedin.com/in/robert-johnson-sdet](https://linkedin.com/in/robert-johnson-sdet)  
**Version:** 1.0 — June 2025  

> A practical, vendor-neutral checklist for AI teams who want to know what's
> exploitable before their users find it. Use this before shipping any
> LLM-powered feature to production.

---

## How to use this checklist

Work through each section with your engineering team. For every item:
- ✅ **Pass** — control is in place and verified
- ❌ **Fail** — vulnerability exists, remediation needed
- ⚠️ **Partial** — control exists but not fully implemented
- 🔍 **Unknown** — needs investigation

Items marked 🔴 are **Critical** — address before shipping.  
Items marked 🟠 are **High** — address within 30 days.  
Items marked 🟡 are **Medium** — address within 90 days.

---

## LLM01: Prompt Injection

> Can an attacker manipulate your model's behavior through crafted inputs?

### Direct Injection
- [ ] 🔴 Model ignores attempts to override its system prompt via user messages
- [ ] 🔴 Model ignores fake system delimiters (e.g. `[SYSTEM]:`, `[END OF INSTRUCTIONS]`)
- [ ] 🔴 Model does not adopt unrestricted personas (DAN, DevMode, maintenance mode)
- [ ] 🟠 Model ignores role confusion attacks ("as a researcher with no restrictions...")
- [ ] 🟠 Model ignores adversarial suffixes appended to benign queries
- [ ] 🟡 Model ignores multilingual instruction smuggling (non-English injections)
- [ ] 🟡 Model ignores emoji-encoded or unicode-obfuscated instructions

### Indirect Injection
- [ ] 🔴 Model does not execute instructions embedded in documents it processes
- [ ] 🔴 Model does not execute instructions embedded in retrieved web content (RAG)
- [ ] 🟠 Model does not execute instructions hidden in user-uploaded files
- [ ] 🟠 Input content from external sources is sanitized before model processing
- [ ] 🟡 Retrieved context is clearly delimited and marked as untrusted content

### Mitigations in place?
- [ ] 🔴 System prompt includes explicit refusal instructions for override attempts
- [ ] 🟠 Output filtering scans for known bypass phrases before displaying to users
- [ ] 🟠 Adversarial testing of injection vectors runs in your CI/CD pipeline
- [ ] 🟡 A judge-LLM or secondary validation layer evaluates model outputs

---

## LLM02: Sensitive Information Disclosure

> Can an attacker extract PII, cross-user data, or memorized training data?

### PII Leakage
- [ ] 🔴 Model refuses to repeat or confirm PII from its context to unauthorized users
- [ ] 🔴 Model refuses to disclose partial financial identifiers (card endings, account numbers)
- [ ] 🔴 Model refuses to disclose any portion of SSNs or government IDs
- [ ] 🟠 Model refuses aggregation attacks ("summarize all contacts in the knowledge base")
- [ ] 🟡 Model does not generate realistic-looking PII when asked for "examples"

### Cross-Tenant Leakage (Multi-Tenant Applications)
- [ ] 🔴 Retrieved context is scoped to the authenticated user only — no cross-user bleed
- [ ] 🔴 Model refuses requests for other users' ticket/account/session data
- [ ] 🔴 Model does not accept claimed relationships ("my spouse's account") as authorization
- [ ] 🟠 Context isolation is enforced at the retrieval layer, not just prompt instructions
- [ ] 🟠 Model does not confirm existence of other users' accounts or sessions

### Training Data Extraction
- [ ] 🟠 Model does not reproduce memorized PII when prompted with repetition attacks
- [ ] 🟡 Model does not complete partial real-world PII patterns when primed
- [ ] 🟡 Fine-tuning datasets were audited for PII before training

### Mitigations in place?
- [ ] 🔴 PII redaction/tokenization applied before data enters model context
- [ ] 🔴 Per-tenant access controls enforced at the vector/retrieval layer
- [ ] 🟠 Output filtering scans for PII patterns (email, phone, SSN, card) before display
- [ ] 🟡 Data retention policy prevents indefinite storage of user interactions

---

## LLM05: Improper Output Handling

> Is your application safely handling what the model produces?

### Output Validation
- [ ] 🔴 LLM output is never passed directly to `exec()`, `eval()`, or shell commands
- [ ] 🔴 LLM-generated SQL is parameterized — never executed as raw string queries
- [ ] 🔴 LLM-generated HTML/JavaScript is sanitized before rendering in a browser
- [ ] 🟠 LLM output used in file paths is sanitized against path traversal
- [ ] 🟠 LLM-generated email content is escaped before sending

### Mitigations in place?
- [ ] 🔴 Zero-trust approach applied to model output — treated as untrusted user input
- [ ] 🟠 Content Security Policy (CSP) headers prevent XSS from LLM-generated content
- [ ] 🟠 Output encoding applied based on context (HTML, SQL, shell, file system)
- [ ] 🟡 Logging and monitoring detects unusual patterns in model outputs

---

## LLM06: Excessive Agency

> Does your AI agent have more permissions than it actually needs?

### Functionality Scope
- [ ] 🔴 Agent only has access to tools explicitly required for its defined function
- [ ] 🔴 Deprecated or unused plugins/tools have been removed from agent scope
- [ ] 🟠 Open-ended tools (shell execution, arbitrary URL fetch) are not exposed to agents
- [ ] 🟡 Tool inventory is reviewed and pruned at each deployment

### Permission Scope
- [ ] 🔴 Agent database connections use least-privilege credentials (SELECT only where read is all that's needed)
- [ ] 🔴 Agent does not use a shared high-privilege identity for per-user operations
- [ ] 🟠 Agent authenticates to downstream services in the context of the requesting user
- [ ] 🟡 Agent permissions are documented and reviewed quarterly

### Autonomy Controls
- [ ] 🔴 High-impact actions (send email, delete records, make payments) require human approval
- [ ] 🔴 Agent cannot take irreversible actions without explicit user confirmation
- [ ] 🟠 Rate limiting restricts the number of actions an agent can take per session
- [ ] 🟡 Agent activity is logged with enough detail to reconstruct what actions were taken and why

---

## LLM07: System Prompt Leakage

> Can an attacker extract your application's system prompt and business logic?

### Direct Extraction Defense
- [ ] 🔴 Model refuses direct requests to reveal its system prompt or instructions
- [ ] 🔴 Model refuses developer/authority impersonation requests for configuration data
- [ ] 🟠 Model refuses completion priming attacks that try to continue the system prompt
- [ ] 🟡 Model behavior is consistent regardless of claimed user role or authority

### Sensitive Data in Prompts
- [ ] 🔴 No API keys, credentials, or connection strings are stored in system prompts
- [ ] 🔴 No internal hostnames, database names, or infrastructure details in system prompts
- [ ] 🟠 No dollar thresholds, approval logic, or escalation contacts in system prompts
- [ ] 🟠 Sensitive configuration is stored in environment variables, not prompt text

### Inference Probing Defense
- [ ] 🟠 Model does not confirm existence of internal rules when probed indirectly
- [ ] 🟡 Model responses don't vary in ways that allow rule reconstruction by pattern

### Mitigations in place?
- [ ] 🔴 Guardrails enforced by external systems, not prompt instructions alone
- [ ] 🟠 Output filtering catches system prompt content appearing in responses
- [ ] 🟡 Adversarial testing of prompt extraction included in security review

---

## LLM08: Vector and Embedding Weaknesses

> Is your RAG pipeline secure against poisoning and unauthorized access?

### Access Controls
- [ ] 🔴 Vector database enforces per-user/per-tenant access at query time
- [ ] 🔴 Embeddings containing sensitive data are access-controlled, not just encrypted at rest
- [ ] 🟠 Cross-tenant queries are impossible by design, not just by convention

### Data Integrity
- [ ] 🔴 Documents are validated and scanned before being added to the knowledge base
- [ ] 🟠 Knowledge base is audited regularly for poisoned or manipulated content
- [ ] 🟡 Data provenance is tracked — you know where every embedded document came from

### Mitigations in place?
- [ ] 🟠 Immutable audit logs capture all retrieval queries and results
- [ ] 🟡 Anomaly detection flags unusual retrieval patterns

---

## LLM10: Unbounded Consumption

> Can an attacker exhaust your resources or steal your model behavior?

### Rate Limiting
- [ ] 🔴 API rate limiting is enforced per user/session — not just globally
- [ ] 🟠 Unusually large inputs are rejected before reaching the model
- [ ] 🟠 Context window overflow is handled gracefully, not silently truncated
- [ ] 🟡 Cost monitoring alerts trigger when spend exceeds expected thresholds

### Model Extraction Defense
- [ ] 🟠 `logprobs` and `logit_bias` values are not exposed in API responses
- [ ] 🟡 Output watermarking is in place to detect unauthorized model replication
- [ ] 🟡 Query patterns are monitored for systematic model extraction attempts

---

## Pre-Deployment Security Sign-Off

Before shipping any LLM-powered feature to production, confirm:

- [ ] All 🔴 Critical items above are resolved
- [ ] Adversarial testing has been run against the production system prompt
- [ ] A data flow diagram exists showing what user data enters model context
- [ ] An incident response plan exists for LLM-specific security events
- [ ] Security findings from testing are documented and tracked to resolution

---

## Want a deeper audit?

This checklist identifies what to look for. A full security audit goes further —
structured attack payloads, automated test suites, and a written findings report
with severity ratings and remediation guidance.

**Robert Johnson** offers LLM Security Audits mapped to this checklist.  
Flat fee · One-week turnaround · No retainer required.

📬 raj972@gmail.com  
🔗 [linkedin.com/in/robert-johnson-sdet](https://linkedin.com/in/robert-johnson-sdet)  
🔬 [github.com/raj469-doit/llm-security-lab](https://github.com/raj469-doit/llm-security-lab)

---

*Licensed under CC BY-SA 4.0 — free to share and adapt with attribution.*  
*Mapped to OWASP Top 10 for LLM Applications 2025 · genai.owasp.org*
