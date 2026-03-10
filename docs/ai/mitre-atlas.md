---
title: MITRE ATLAS — AI Threat Framework
description: Adversarial threat modeling for AI/ML systems using MITRE ATLAS
tags: [mitre, atlas, ai-security, threat-modeling, adversarial-ml]
---

# MITRE ATLAS — Adversarial Threat Landscape for AI Systems

[atlas.mitre.org](https://atlas.mitre.org/) — The ATT&CK equivalent for AI/ML systems.

## Overview

ATLAS catalogs real-world adversarial tactics and techniques targeting AI systems. As of 2025: **15 tactics, 66 techniques, 46 sub-techniques, 26 mitigations, 33 case studies**.

The October 2025 update added **14 new agentic AI techniques** targeting autonomous AI agent attack surfaces (developed with Zenity Labs).

## ATLAS vs ATT&CK

| Aspect | MITRE ATT&CK | MITRE ATLAS |
|--------|-------------|-------------|
| Target | IT systems, networks | AI/ML systems |
| Threats | Malware, exploitation | Model attacks, data poisoning |
| Tactics | 14 | 15 (includes ML-specific) |
| Case studies | Enterprise focused | AI-specific incidents |
| Structure | Same matrix format | Same matrix format |

---

## Key Tactics and Techniques

### Reconnaissance
| Technique | Description |
|-----------|-------------|
| Search for victim's ML artifacts | Find published models, datasets, API endpoints |
| Discover ML model family | Identify architecture (GPT, BERT, etc.) |
| Search for technical blogs/publications | Gather model training details |

### ML Attack Staging
| Technique | Description |
|-----------|-------------|
| Acquire public ML model | Download and analyze target model architecture |
| Develop adversarial ML attack | Create evasion/poisoning attacks offline |
| Craft adversarial data | Generate inputs that fool the model |
| Train proxy model | Build a substitute model for black-box attacks |

### Initial Access (ML-Specific)
| Technique | Description |
|-----------|-------------|
| ML supply chain compromise | Poison pre-trained models or datasets |
| Valid accounts (API access) | Abuse ML API keys/tokens |
| Prompt injection | Manipulate LLM behavior via crafted input |

### ML Model Access
| Technique | Description |
|-----------|-------------|
| Inference API access | Query the model to extract information |
| ML-enabled product access | Interact with AI features in applications |
| Physical environment access | Manipulate sensors feeding ML models |

### Exfiltration
| Technique | Description |
|-----------|-------------|
| Model extraction via API | Reconstruct model through query-response pairs |
| Training data extraction | Recover training data from model responses |
| Membership inference | Determine if specific data was in training set |

### Evasion
| Technique | Description |
|-----------|-------------|
| Adversarial examples | Craft inputs that cause misclassification |
| Prompt injection (evasion) | Bypass content filters via prompt manipulation |

### Impact
| Technique | Description |
|-----------|-------------|
| Denial of ML service | Overwhelm model inference endpoints |
| Model poisoning | Degrade model performance via data manipulation |
| AI hallucination exploitation | Trigger harmful/incorrect outputs |

---

## Agentic AI Techniques (2025 Update)

New techniques targeting autonomous AI agents:

| Technique | Risk |
|-----------|------|
| Tool abuse | Agent uses permitted tools for unintended purposes |
| Prompt injection via tools | Malicious content in tool outputs influences agent |
| Excessive permissions | Agent granted broader access than necessary |
| Agent impersonation | Spoofing trusted agent identities |
| Memory poisoning | Corrupting agent's persistent memory/context |
| Chain-of-thought manipulation | Steering agent reasoning toward attacker goals |
| Multi-agent collusion | Compromised agent influences other agents |

### Mitigation for Agentic AI

```typescript
// 1. Least privilege — scope tool access per task
const agentTools = {
  readOnly: ['search', 'read_file'],
  writeEnabled: ['edit_file'],  // Only when needed
  dangerous: ['execute_shell'], // Require human approval
};

// 2. Output validation — don't trust tool results blindly
function processToolResult(result: string): string {
  // Check for injection attempts in tool output
  if (containsInjectionPattern(result)) {
    logger.warn('Potential injection in tool output');
    return sanitize(result);
  }
  return result;
}

// 3. Action boundaries — human-in-the-loop for high-impact
async function executeAction(action: AgentAction): Promise<void> {
  if (HIGH_IMPACT_ACTIONS.includes(action.type)) {
    const approved = await requestHumanApproval(action);
    if (!approved) throw new Error('Action denied by human reviewer');
  }
  await action.execute();
}
```

---

## Threat Modeling with ATLAS

### Step 1: Identify AI Components

```
System: Customer Support Chatbot
AI Components:
├── LLM (GPT-4 via API) — text generation
├── RAG pipeline — knowledge base retrieval
├── Embedding model — vector similarity search
├── Intent classifier — route to human/AI
└── Sentiment analyzer — priority escalation
```

### Step 2: Map ATLAS Techniques to Components

| Component | Relevant Techniques | Severity |
|-----------|-------------------|----------|
| LLM API | Prompt injection, data exfiltration | Critical |
| RAG pipeline | Knowledge poisoning, indirect injection | High |
| Embedding model | Adversarial examples, model extraction | Medium |
| Intent classifier | Evasion, misclassification | Medium |
| Sentiment analyzer | Adversarial input manipulation | Low |

### Step 3: Apply Mitigations

| ATLAS Mitigation | Implementation |
|------------------|----------------|
| AML.M0001 — Limit model queries | Rate limiting on API endpoints |
| AML.M0002 — Passive monitoring | Log all model inputs/outputs |
| AML.M0003 — Model hardening | Adversarial training, input validation |
| AML.M0004 — Restrict library loading | Pin ML framework versions |
| AML.M0005 — Control access to models | API authentication, IP allowlists |
| AML.M0013 — Code signing | Verify model artifact integrity |
| AML.M0015 — Adversarial input detection | Input classifiers, anomaly detection |

---

## ATLAS + OWASP LLM Top 10 Mapping

| OWASP LLM Risk | ATLAS Technique |
|-----------------|-----------------|
| LLM01 Prompt Injection | AML.T0051 |
| LLM02 Data Disclosure | AML.T0024 (training data extraction) |
| LLM03 Supply Chain | AML.T0010 (ML supply chain compromise) |
| LLM04 Data Poisoning | AML.T0020 (poison training data) |
| LLM06 Excessive Agency | Agentic AI techniques (2025) |
| LLM08 Vector Weaknesses | AML.T0043 (adversarial examples on embeddings) |

---

## Case Studies from ATLAS

| Case Study | Technique | Impact |
|------------|-----------|--------|
| GPT-2 training data extraction | Membership inference | PII exposed from model |
| Adversarial patches on stop signs | Physical adversarial examples | Safety-critical misclassification |
| ChatGPT data leak via prompt injection | Indirect prompt injection | User conversation exfiltration |
| Poisoned code completion models | ML supply chain + data poisoning | Backdoored code suggestions |

## References

- [MITRE ATLAS — atlas.mitre.org](https://atlas.mitre.org/)
- [ATLAS Matrix](https://atlas.mitre.org/matrices)
- [ATLAS Case Studies](https://atlas.mitre.org/resources/case-studies)
- [MITRE SAFE-AI Report (PDF)](https://atlas.mitre.org/pdf-files/SAFEAI_Full_Report.pdf)
- [NIST AI RMF — nist.gov](https://www.nist.gov/artificial-intelligence)
- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
