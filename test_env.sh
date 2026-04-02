#!/bin/bash
# Simulate a malicious .env file
TEST_ENV_FILE=$(mktemp "${TMPDIR:-/tmp}/test_env.XXXXXX")
trap 'rm -f "$TEST_ENV_FILE"' EXIT
cat <<'EOT' > "$TEST_ENV_FILE"
GOOD_VAR=hello
BAD_VAR=$(echo "THIS SHOULD NOT RUN")
QUOTED_VAR="with spaces"
COMMENTED_VAR=value # this is a comment
# FULL_COMMENT=ignored
EOT

while IFS='=' read -r key value || [ -n "$key" ]; do
  # Skip comments and empty lines
  [[ "$key" =~ ^#.*$ ]] && continue
  [[ -z "$key" ]] && continue
  
  # Remove trailing comments from value (simple version)
  value="${value%%#*}"
  
  # Trim whitespace
  key=$(echo "$key" | xargs)
  value=$(echo "$value" | xargs)
  
  # Remove surrounding quotes
  value="${value%\"}"
  value="${value#\"}"
  value="${value%\'}"
  value="${value#\'}"

  # Validate key: must be alphanumeric/underscore, reject dangerous names
  [[ ! "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && continue
  [[ "$key" =~ ^(PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_.*|BASH_ENV|SHELL|HOME|USER|LOGNAME|IFS)$ ]] && continue

  # Securely set the variable
  printf -v "$key" "%s" "$value"
  export "$key"
done < "$TEST_ENV_FILE"

echo "GOOD_VAR: $GOOD_VAR"
echo "BAD_VAR: $BAD_VAR"
echo "QUOTED_VAR: $QUOTED_VAR"
echo "COMMENTED_VAR: $COMMENTED_VAR"
