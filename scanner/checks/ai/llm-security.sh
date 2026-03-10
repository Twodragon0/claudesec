#!/usr/bin/env bash
# ClaudeSec — AI / LLM Security Checks

local has_ai=false
if files_contain "*.py" "(openai|anthropic|langchain|transformers|torch)" 2>/dev/null || \
   files_contain "*.ts" "(openai|@anthropic|langchain)" 2>/dev/null || \
   files_contain "*.js" "(openai|anthropic|langchain)" 2>/dev/null || \
   files_contain "*.json" "(openai|anthropic-ai|langchain)" 2>/dev/null; then
  has_ai=true
fi

if [[ "$has_ai" == "true" ]]; then
  # AI-001: API keys not hardcoded
  if files_contain "*.py" "(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]+)" 2>/dev/null || \
     files_contain "*.ts" "(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]+)" 2>/dev/null || \
     files_contain "*.js" "(sk-[a-zA-Z0-9]{20,}|sk-ant-[a-zA-Z0-9]+)" 2>/dev/null; then
    fail "AI-001" "LLM API key hardcoded in source code" "critical" \
      "API keys should never be in source code" \
      "Use environment variables or a secrets manager"
  else
    pass "AI-001" "No hardcoded LLM API keys found"
  fi

  # AI-002: Prompt injection defense
  if files_contain "*.py" "(sanitize|validate|filter).*(input|prompt|user)" 2>/dev/null || \
     files_contain "*.ts" "(sanitize|validate|filter).*(input|prompt|user)" 2>/dev/null || \
     files_contain "*.js" "(sanitize|validate|filter).*(input|prompt|user)" 2>/dev/null; then
    pass "AI-002" "Input sanitization/validation detected for AI prompts"
  else
    warn "AI-002" "No prompt input validation detected" \
      "Add input sanitization before sending user input to LLM APIs (OWASP LLM01)"
  fi

  # AI-003: Output validation
  if files_contain "*.py" "(validate|sanitize|check).*(output|response|result|completion)" 2>/dev/null || \
     files_contain "*.ts" "(validate|sanitize|check).*(output|response|result|completion)" 2>/dev/null || \
     files_contain "*.js" "(validate|sanitize|check).*(output|response|result|completion)" 2>/dev/null; then
    pass "AI-003" "LLM output validation detected"
  else
    warn "AI-003" "No LLM output validation detected" \
      "Validate/sanitize LLM outputs before use (OWASP LLM05)"
  fi

  # AI-004: Rate limiting on AI endpoints
  if files_contain "*.py" "rate.?limit|throttl|RateLimiter" 2>/dev/null || \
     files_contain "*.ts" "rate.?limit|throttl|RateLimit" 2>/dev/null || \
     files_contain "*.js" "rate.?limit|throttl|RateLimit" 2>/dev/null; then
    pass "AI-004" "Rate limiting detected for AI endpoints"
  else
    warn "AI-004" "No rate limiting detected for AI endpoints" \
      "Add rate limiting to prevent unbounded consumption (OWASP LLM10)"
  fi

  # AI-005: Token/cost budget enforcement
  if files_contain "*.py" "max_tokens|token.?budget|cost.?limit" 2>/dev/null || \
     files_contain "*.ts" "max_tokens|maxTokens|token.?budget" 2>/dev/null || \
     files_contain "*.js" "max_tokens|maxTokens|token.?budget" 2>/dev/null; then
    pass "AI-005" "Token/cost limits configured"
  else
    warn "AI-005" "No token/cost budget enforcement detected" \
      "Set max_tokens and monitor costs to prevent resource exhaustion"
  fi

  # AI-006: System prompt not exposed
  if files_contain "*.py" "system.?prompt|system_message" 2>/dev/null || \
     files_contain "*.ts" "system.?[Pp]rompt|systemMessage" 2>/dev/null; then
    # Check if system prompt is in a separate config vs hardcoded
    if files_contain "*.py" "SYSTEM_PROMPT\s*=\s*\"\"\"" 2>/dev/null || \
       files_contain "*.ts" "SYSTEM_PROMPT\s*=\s*['\`]" 2>/dev/null; then
      warn "AI-006" "System prompt hardcoded in source" \
        "Move system prompts to config files. Don't include secrets in system prompts (OWASP LLM07)"
    else
      pass "AI-006" "System prompt management appears appropriate"
    fi
  else
    skip "AI-006" "System prompt exposure" "No system prompt patterns found"
  fi

  # AI-007: No eval() of LLM output
  if files_contain "*.py" "eval\(.*completion\|eval\(.*response\|exec\(.*completion" 2>/dev/null || \
     files_contain "*.js" "eval\(.*completion\|eval\(.*response" 2>/dev/null; then
    fail "AI-007" "eval()/exec() used on LLM output" "critical" \
      "Executing LLM output as code enables arbitrary code execution" \
      "Never eval() LLM responses. Parse and validate structured output instead"
  else
    pass "AI-007" "No eval()/exec() of LLM output detected"
  fi

  # AI-008: RAG security — document source validation
  if files_contain "*.py" "(RAG|retriev|vector.?store|embedding|chroma|pinecone|weaviate)" 2>/dev/null || \
     files_contain "*.ts" "(RAG|retriev|vectorStore|embedding)" 2>/dev/null; then
    warn "AI-008" "RAG system detected — verify document source validation" \
      "Sanitize documents before embedding and validate retrieval sources (OWASP LLM08)"
  else
    skip "AI-008" "RAG security" "No RAG/vector store patterns found"
  fi

  # AI-009: Agent tool permissions
  if files_contain "*.py" "(tool|function).*(call|use|invoke|execute)" 2>/dev/null || \
     files_contain "*.ts" "(tool|function).*(call|use|invoke|execute)" 2>/dev/null; then
    warn "AI-009" "AI agent tool usage detected — verify least privilege" \
      "Restrict agent tool access to minimum required. Add human-in-the-loop for destructive actions (OWASP LLM06)"
  else
    skip "AI-009" "Agent tool permissions" "No tool-use patterns found"
  fi
else
  skip "AI-001" "LLM API key check" "No AI/LLM code detected"
  skip "AI-002" "Prompt injection defense" "No AI/LLM code detected"
  skip "AI-003" "LLM output validation" "No AI/LLM code detected"
  skip "AI-004" "AI rate limiting" "No AI/LLM code detected"
  skip "AI-005" "Token budget" "No AI/LLM code detected"
  skip "AI-006" "System prompt exposure" "No AI/LLM code detected"
  skip "AI-007" "eval of LLM output" "No AI/LLM code detected"
  skip "AI-008" "RAG security" "No AI/LLM code detected"
  skip "AI-009" "Agent tool permissions" "No AI/LLM code detected"
fi
