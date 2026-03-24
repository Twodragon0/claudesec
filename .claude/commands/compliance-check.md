---
description: Run a compliance gap analysis against NIST/ISO/ISMS-P frameworks
---
Run a compliance gap analysis for the specified framework:

**Framework**: $ARGUMENTS (default: all — NIST 800-53, ISO 27001, ISMS-P)

## Workflow

### Stage 1: Research (sec-researcher)
- Review the target compliance framework requirements
- Map requirements to existing docs/compliance/ coverage
- Identify undocumented control areas

### Stage 2: Documentation (docs-writer)
- Draft missing compliance guides in docs/compliance/
- Include control mappings, implementation guidance, evidence requirements
- Use YAML frontmatter with compliance-specific tags

### Stage 3: Review (sec-reviewer)
- Verify framework requirement accuracy
- Cross-check control mappings against official framework documents
- Validate implementation guidance is actionable

### Stage 4: Quality Gate (test-engineer)
- Lint new documents
- Validate internal cross-references and links
- Ensure consistent formatting across compliance docs

### Output
- Compliance coverage percentage (before/after)
- List of newly created documents
- Remaining gaps requiring manual input
