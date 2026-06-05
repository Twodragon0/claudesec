# Coding Style Rules

## Immutability (CRITICAL)

ALWAYS create new objects, NEVER mutate:

```javascript
// WRONG: Mutation
function updateUser(user, name) {
  user.name = name  // MUTATION!
  return user
}

// CORRECT: Immutability
function updateUser(user, name) {
  return { ...user, name }
}
```

## File Organization

MANY SMALL FILES > FEW LARGE FILES:
- High cohesion, low coupling
- 200-400 lines typical, 800 max
- Extract utilities from large components
- Organize by feature/domain, not by type

## Error Handling

ALWAYS handle errors comprehensively:

```typescript
try {
  const result = await riskyOperation()
  return result
} catch (error) {
  console.error('Operation failed:', error)
  throw new Error('User-friendly error message')
}
```

## Input Validation

ALWAYS validate user input:

```typescript
import { z } from 'zod'

const schema = z.object({
  email: z.string().email(),
  age: z.number().int().min(0).max(150)
})

const validated = schema.parse(input)
```

## Code Quality Checklist

Before marking work complete:
- [ ] Code is readable and well-named
- [ ] Functions are small (<50 lines)
- [ ] Files are focused (<800 lines)
- [ ] No deep nesting (>4 levels)
- [ ] Proper error handling
- [ ] No console.log statements
- [ ] No hardcoded values
- [ ] Immutable patterns used

## ClaudeSec-Specific Style

ClaudeSec is a DevSecOps toolkit: Markdown docs + a Bash scanner (`scanner/`),
Python dashboard generator (`scanner/dashboard-gen.py`), Claude Code hooks
(`hooks/`), and GitHub Actions. The immutability/TypeScript examples above are
generic illustrations — apply the intent, not the literal language.

### Naming & layout

- File names are kebab-case (e.g. `github-actions-security.md`).
- Place new content in the documented directory (`docs/devsecops/`, `docs/ai/`,
  `scanner/`, `hooks/`, ...); do not add ad-hoc top-level folders.
- Keep files small and focused; extract shared scanner logic into `scanner/lib/`.

### Markdown

- Every doc under `docs/` needs YAML frontmatter: `title`, `description`, `tags`.
- All fenced code blocks must declare a language (` ```bash `, ` ```yaml `).
- Code examples must be tested and runnable, not pseudocode.
- Security claims must cite an authoritative source (OWASP / NIST / CIS).

### Bash (scanner & scripts)

- Start scripts with `set -euo pipefail`; quote all expansions.
- Must pass `shellcheck` clean (enforced by the `shell-lint` CI job).
- Guard any code path that makes network calls so tests can run offline
  (see `CLAUDESEC_DASHBOARD_OFFLINE` in [Testing](./testing.md)).

### No sensitive data

- Never commit real paths, hostnames, IPs, account IDs, emails, or secrets.
- Use placeholders: `~/.kube/config`, `/path/to/kubeconfig`, `your-api-key-here`.
- `.claudesec.yml` is gitignored — users copy from `templates/*.example.yml`.
