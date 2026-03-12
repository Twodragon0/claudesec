# Recommended GitHub Labels

Create these labels in your repository so contributors can find suitable issues. In GitHub: **Settings → General → Labels → New label**.

| Label name        | Color   | Description |
|-------------------|---------|-------------|
| `good first issue` | `7057ff` | Good for newcomers; small scope, clear steps |
| `help wanted`      | `008672` | Extra help welcome; may need domain knowledge |

### One-time setup with GitHub CLI

If you have [GitHub CLI](https://cli.github.com/) installed and authenticated:

```bash
gh label create "good first issue" --color "7057ff" --description "Good for newcomers"
gh label create "help wanted" --color "008672" --description "Extra help welcome"
```

Or run the script from the repo root:

```bash
./scripts/github-setup-labels.sh
```

Then tag issues in the GitHub UI or when creating issues so new contributors can filter by **good first issue**.
