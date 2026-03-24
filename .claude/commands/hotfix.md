---
description: Urgent security update — fast-track CVE/threat response workflow
---
Fast-track security response for an urgent threat:

**Threat/CVE**: $ARGUMENTS

## Workflow (3-stage fast track)

### Stage 1: Triage (sec-researcher)
- Analyze the CVE/threat: severity, affected components, exploitation status
- Check if the project is affected (scan scanner/, hooks/, templates/)
- Produce a threat brief with CVSS score and impact assessment

### Stage 2: Patch (sec-implementer)
- Create or update relevant scanner rules to detect the vulnerability
- Update hooks/ if pre-commit checks need adjustment
- Write a remediation guide in docs/guides/
- Update templates/ if configuration changes are needed

### Stage 3: Fast Review (sec-reviewer)
- Verify the patch addresses the specific threat
- Confirm remediation guidance is accurate
- Quick-check that no regressions were introduced

### Output
- Threat summary (severity, impact, affected components)
- Changes made (files modified/created)
- Recommended user actions
