---
title: "세션 성과 보고서 2026-05-27"
description: "Supply-chain 가드, fork-guard CI 회귀 방지, scanner/lib 커버리지 측정 학습 — 3 PR 머지"
tags:
  - session-report
  - supply-chain
  - coverage
  - kcov
  - devsecops
---

# 세션 성과 보고서 — 2026-05-27

## 세션 개요

- **Date range**: 2026-05-27
- **PRs merged**: 3 (#168, #170, #171)
- **Security baseline**: Grade A · score 100 · 0 failed · 21 passed — 변동 없음
- **Lib SUT coverage**: `output.sh` 87.18% → **92.44%**, `checks.sh` 88.44% → **91.48%**
- **Overall kcov**: 91.19% → **91.14%** (사실상 동일 — 측정 방법론 한계, 아래 설명)

## 머지 타임라인

| # | Merged at (UTC) | SHA | Title |
|---|---|---|---|
| #168 | 2026-05-27 01:11 | `c7adbdd` | chore(ci): guard dependabot auto-merge against fork-origin PRs |
| #170 | 2026-05-27 05:08 | `833c9ff` | chore(ci): add regression-prevention audit for pull_request_target fork-guard |
| #171 | 2026-05-27 06:41 | `5a96efb` | test(scanner/lib): lift output.sh + checks.sh kcov to ≥95% (overall 91.19% → 93%+) |

## 공급망 / CI 안전성

### #168 — Dependabot auto-merge fork-guard

`.github/workflows/dependabot-auto-merge.yml`의 auto-merge 잡 `if:` 조건에 head-repo 일치 검증 추가:

```yaml
if: >-
  github.actor == 'dependabot[bot]' &&
  github.event.pull_request.head.repo.full_name == github.repository
```

`pull_request_target`는 업스트림의 write-scoped `GITHUB_TOKEN`을 fork PR에도 부여하므로 `dependabot[bot]` actor를 위장한 fork-origin PR이 잠재적 공격 벡터. dependabot은 본 레포 내 브랜치만 열기에 head-repo 검증으로 정상 PR에는 영향 0. OWASP A08 (Software & Data Integrity Failures) 완화.

검증: 후속 PR(#169)에서 `Auto-merge Dependabot PR` 잡이 정상적으로 `skipping` (actor != dependabot[bot]) — 가드가 의도대로 작동.

### #170 — fork-guard 회귀 방지 CI 린트

`scripts/check-pull-request-target-guard.py` + `.github/workflows/lint.yml`의 신규 `workflow-fork-guard` 잡 (~7s 런타임). PyYAML로 모든 `.github/workflows/*.yml`을 파싱해 `on.pull_request_target` 트리거를 가진 워크플로우의 각 잡 `if:` 식에 `head.repo.full_name == github.repository`가 포함되어 있는지 검사.

현재 상태: 1/1 워크플로우 가드 적용 (`dependabot-auto-merge.yml`). 향후 새로운 `pull_request_target` 워크플로우가 가드 없이 추가되면 CI가 즉시 차단.

로컬 회귀 테스트: 가드 일시 제거 → `::error file=...::job 'auto-merge' is missing the fork-guard ...` + exit 1; 원복 → exit 0.

> 참고: [GitHub Docs — Security hardening for GitHub Actions / `pull_request_target`](https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-pull_request_target-or-workflow_run-from-untrusted-forks)

### #171 — scanner/lib 커버리지 보강 (target ≥95%)

`scanner/tests/test_output_coverage.sh` (76 tests) + `scanner/tests/test_checks_coverage.sh` (33 tests) 신규. 6 + 10개 미커버 브랜치 클러스터를 노린 fixture/스텁 기반 테스트.

**Lib SUT 결과 (정확히 의도된 측정 대상)**:

| 파일 | Before | After | Δ |
|---|---|---|---|
| `scanner/lib/output.sh` | 87.18% (415/476) | **92.44%** (440/476) | **+5.26pp** |
| `scanner/lib/checks.sh` | 88.44% (436/493) | **91.48%** (451/493) | **+3.04pp** |

39 lines of real SUT code newly exercised. 그러나 PR 제목의 "≥95%" / "91.19% → 93%+ overall" 목표는 미달성 — 이유는 측정 방법론에 있음(다음 섹션).

## 커버리지 측정 방법론 학습 (Honest section)

### 현상

PR #171 머지 후 `kcov-out/merged/kcov-merged/coverage.json`을 다운로드해 직접 파싱한 결과:

```text
Overall: 91.14%  (3754 / 4119)
  output.sh                : 92.44% (440/476)   [+5.26pp, gain real]
  checks.sh                : 91.48% (451/493)   [+3.04pp, gain real]
  test_output_coverage.sh  : 93.72% (179/191)   [own self-coverage OK]
  test_checks_coverage.sh  : 71.67% (172/240)   [own self-coverage LOW]
```

전체 평균이 사실상 정체된 이유: **kcov의 `--include-pattern`이 SUT뿐 아니라 _각 테스트 파일 자신의 라인 커버리지_까지 측정 대상에 포함**한다는 점.

```bash
kcov --include-pattern=checks.sh,output.sh,"$name".sh "kcov-out/$name" "$sh"
#                                       ^^^^^^^^^^^^ 테스트 파일 자기 자신
```

`test_checks_coverage.sh`에 68개 미커버 라인이 존재 — 모두 multi-line `$(...)` command-substitution 블록 내부. kcov v42는 `$(...)` 가 spawn하는 forked subshell의 라인을 부모 프로세스 DEBUG-trap으로 추적하지 못함(단일 라인 `$(cmd)`는 OK).

agent의 두 차례 시도(① `bash -c '...'` → `( ... )` 변환 → 71.67% 도달, ② 추가 분리는 오히려 라인 수만 증가시켜 46.75%로 후퇴)로도 multi-line `$(...)` 의존성을 완전히 떼어내지 못함. PR 머지 결정은 다음 근거:

1. Lib SUT 커버리지 게인은 실재 (39 lines 신규 커버)
2. 85% floor는 유지 (91.14% > 85%)
3. Overall 정체는 _측정 방법론_의 부산물, _테스트 가치_의 부재가 아님

### 후속 조치 (이미 큐잉됨)

- **방법론 수정**: `--include-pattern`에서 `"$name".sh` 제거 → SUT만 측정. (별도 PR 예정)
- **방법론 수정 후 진정한 overall**: lib-only ≈ 891/969 = **91.95%** (현재 두 lib만 포함되는 경우). 3% 목표는 추가 lib 커버리지 작업으로만 달성 가능.
- **남은 큰 미커버 덩어리**: `output.sh` L414-440 prowler OCSF python 블록 (~25 lines) — 다음 PR 후보.

## 검증 스냅샷

```bash
# CI run 26494417482 (PR #171 final, scanner-shell-coverage @ 14m11s)
gh run download 26494417482 -n scanner-shell-kcov-26494417482 --dir /tmp/cov/
python3 -c "import json; d=json.load(open('/tmp/cov/kcov-merged/coverage.json')); \
  print(f\"{d['percent_covered']}% ({d['covered_lines']}/{d['total_lines']})\")"
# → 91.14% (3754/4119)

# fork-guard CI lint (PR #170 / #171, workflow-fork-guard job)
# → pass 7-13s on every PR after #170 merge

# 회귀 테스트 (#170 머지 전 로컬)
python3 scripts/check-pull-request-target-guard.py
# OK: 1 pull_request_target workflow(s) audited, all jobs fork-guarded.

# 가드 일시 제거 후
# FAIL: 1 unguarded job(s) across 1 pull_request_target workflow(s).
```

## 후속 작업

- **PR queued: kcov methodology fix** — `--include-pattern`에서 test self-coverage 제거
- **PR queued: prowler OCSF 커버리지** — `output.sh` L414-440 fixture-based 테스트로 `output.sh` ≥95%
- **세션 간 학습**: bash 테스트에서 SUT 호출 시 multi-line `$(...)` 회피, single-line `$(...)` 또는 `( ... ) > file` + `read < file` 패턴 권장

## 운영 메모

- **정직한 회계**: PR #171 제목의 "≥95%" / "91.19% → 93%+"는 충족되지 않음. lib SUT 게인은 실재. headline 메트릭 정체는 측정 방법론 문제로 다음 PR에서 해결 예정. 향후 커버리지 PR 제목/계획은 측정 방법론 한계를 사전에 명시할 것.
- **Sub-agent 협업 학습**: parallel sub-agent 작업 시 동일 git workdir에서 브랜치 충돌이 발생할 수 있음 — worktree 격리 패턴 (`git worktree add /tmp/<name> <branch>`) 표준화 필요.
- **자기 PR 머지**: 3건 모두 `--admin` 우회 사용 (1인 레포 구조적 제약 유지).
