---
description: Create a new security guide using the full multi-agent workflow
---
Create a new security guide end-to-end using coordinated agents:

**Topic**: $ARGUMENTS

## Workflow (5-stage pipeline)

### Stage 1: Research (sec-researcher)
- Research the topic using authoritative sources (OWASP, NIST, CIS)
- Identify key threats, mitigations, and best practices
- Produce a research brief with source citations

### Stage 2: Implementation (sec-implementer)
- Create any scanner rules, hooks, or templates related to the topic
- Add to scanner/ or hooks/ or templates/ as appropriate

### Stage 3: Documentation (docs-writer)
- Write the guide in the appropriate docs/ subdirectory
- Use YAML frontmatter (title, description, tags)
- Include practical code examples
- Use kebab-case file naming

### Stage 4: Review (sec-reviewer)
- Verify all security claims cite authoritative sources
- Check technical accuracy of code examples
- Validate OWASP/NIST/CIS references

### Stage 5: Quality Gate (test-engineer)
- Run markdownlint on the new file
- Validate all links
- Ensure code blocks specify language

Report the final file path and a summary of what was created.
