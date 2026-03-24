---
description: Develop a new scanner feature using the architect-to-CI pipeline
---
Develop a new scanner feature end-to-end:

**Feature**: $ARGUMENTS

## Workflow (4-stage pipeline)

### Stage 1: Design (architect)
- Design the scanner feature architecture
- Define interfaces, data flow, and output format
- Consider integration with existing scanner categories

### Stage 2: Build (sec-implementer)
- Implement the feature in scanner/
- Follow existing scanner patterns and conventions
- Include proper error handling and output formatting

### Stage 3: Test (test-engineer)
- Write unit tests for the new feature
- Run existing test suite to check for regressions
- Validate scanner output format consistency

### Stage 4: CI Integration (ci-pipeline)
- Add the new feature to relevant GitHub Actions workflows
- Update quality gates if needed
- Ensure the feature works in the CI environment

### Output
- Files created/modified
- Test results summary
- CI integration status
