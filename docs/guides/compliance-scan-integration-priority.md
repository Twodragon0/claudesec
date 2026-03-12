---
title: 컴플라이언스 스캔 통합 우선순위
description: ISMS-P, ISO, SOC2, PCI-DSS 등 컴플라이언스 준수 스캔 도구의 GitHub 검토 및 ClaudeSec 통합 우선순위
tags: [compliance, isms-p, iso27001, soc2, pci-dss, prowler, integration]
---

# 컴플라이언스 스캔 통합 우선순위

ISMS-P, ISO 27001, SOC2, PCI-DSS 등 컴플라이언스에 준수하는 보안 스캔을 ClaudeSec에서 통합·구성하기 위한 **우선순위**와 **Best Practices** 정리.

---

## 1. 현재 상태 요약

| 구분 | 상태 |
|------|------|
| **Prowler** | 이미 통합됨 (`scanner/checks/prowler/integration.sh`). AWS/Azure/GCP/K8s/GitHub 스캔 지원. |
| **CLI `--compliance`** | `iso27001`, `isms-p`, `soc2`, `pci-dss` 등 옵션 존재하나, **Prowler 실행 시 `--compliance` 인자로 전달되지 않음**. |
| **대시보드** | `dashboard-gen.py`에 ISO 27001, KISA ISMS-P, PCI-DSS 제어 매핑 존재. **SOC2**는 프레임워크 목록에 없음. |
| **문서** | `docs/compliance/` 에 iso27001, isms-p, nist-csf, iso42001 등 가이드 있음. |

**결론**: Prowler 한 도구만으로도 ISO 27001, SOC2, PCI-DSS, KISA ISMS-P를 지원한다. 우선 **Prowler에 `--compliance` 연동**을 완료하고, 대시보드·문서를 정리하는 것이 효율적이다.

---

## 2. GitHub 기반 컴플라이언스 스캔 도구 (참고)

| 도구 | 저장소 | 지원 프레임워크 | 비고 |
|------|--------|------------------|------|
| **Prowler** | [prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | CIS, NIST 800-53/CSF, FedRAMP, **PCI-DSS**, **ISO 27001**, **SOC2**, **KISA ISMS-P**, GDPR, HIPAA 등 25+ | **이미 ClaudeSec 통합**. 멀티클라우드·GitHub. |
| **Lynis** | [CISOfy/lynis](https://github.com/CISOfy/lynis) | HIPAA, ISO 27001, PCI-DSS (호스트 하드닝) | 호스트/OS 감사. 에이전트리스. |
| **CloudAudit** | [xtawb/cloudaudit](https://github.com/xtawb/cloudaudit) | CIS, NIST, SOC2, ISO 27001, PCI-DSS | AWS/GCP/Azure, AI 기반. |
| **Gestalt Security Framework** | [GestaltSecurity/Gestalt-Security-Framework](https://github.com/GestaltSecurity/Gestalt-Security-Framework) | NIST 800-53, ISO 27000, PCI-DSS, COBIT, CIS, SOC2 등 | 컨트롤 매핑·네비게이션용. 스캐너 아님. |
| **AuditKit** | (Community Edition) | SOC2, PCI-DSS, CMMC 등 | 오픈소스 컴플라이언스 스캐너. |

**Best practice**: 단일 스캐너(Prowler)로 최대한 커버하고, 호스트/OS 레벨이 필요할 때만 Lynis 등 보조 도구를 검토.

---

## 3. 통합 우선순위

### 우선순위 1 (즉시) — Prowler `--compliance` 연동 ✅ 구현 완료

- **목표**: `claudesec scan --compliance iso27001`(또는 `isms-p`, `soc2`, `pci-dss`) 실행 시 Prowler가 해당 프레임워크로 스캔하도록 연동.
- **구현 내용**:
  - `scanner/claudesec`: `load_config()`에서 `compliance:` 키 파싱(CLI 미지정 시 적용). `run_scan()` 및 `dashboard` 분기에서 `COMPLIANCE`를 `CLAUDESEC_COMPLIANCE`로 export.
  - `scanner/checks/prowler/integration.sh`: `_prowler_compliance_id()`로 CLI/설정값을 Prowler ID로 매핑(iso27001→iso27001_2022, isms-p/kisa→kisa_isms_p, soc2, pci-dss→pci_dss_v4, nist-csf, nist-800-53 등). `_prowler_scan()`에서 `CLAUDESEC_COMPLIANCE`가 있으면 `--compliance <id>`를 Prowler 인자에 추가.
- **근거**: 한 번의 연동으로 ISO/ISMS-P/SOC2/PCI-DSS 모두 활용 가능.

### 우선순위 2 (단기) — 대시보드 SOC2 반영

- **목표**: 대시보드 Compliance 탭에 SOC2 프레임워크 및 제어 매핑 추가.
- **작업**:
  - `scanner/lib/dashboard-gen.py`: `COMPLIANCE_FRAMEWORKS`에 SOC2 항목 추가.
  - `COMPLIANCE_CONTROL_MAP`에 SOC2 Trust Services Criteria 기반 제어 추가 (예: CC6.1, CC6.2, CC7.1 등). Prowler OCSF 결과의 `compliance` 필드와 매핑 가능한 키워드로 연결.
- **근거**: SOC2는 클라우드·SaaS 감사에서 요구 비중이 커서 대시보드에서 시각화할 필요가 있음.

### 우선순위 3 (단기) — 설정·템플릿 정리

- **목표**: `.claudesec.yml` 및 GitHub Actions 템플릿에서 컴플라이언스 프레임워크를 선택할 수 있게 함.
- **작업**:
  - `load_config()`에서 `compliance:` 키 읽어 `CLAUDESEC_COMPLIANCE` 설정.
  - `templates/prowler.yml`, `templates/security-scan-suite.yml` 등에 `compliance: iso27001` 또는 `soc2` 등 예시 추가.
  - `docs/compliance/` 에 SOC2 가이드 추가 (선택).
- **근거**: 재현 가능한 컴플라이언스 스캔과 CI/CD 통합을 위한 기본 설정.

### 우선순위 4 (중기) — 문서·인용 정리

- **목표**: 각 프레임워크별 “어떤 스캔으로 어떤 제어를 점검하는지” 문서화.
- **작업**:
  - `docs/compliance/isms-p.md`, `iso27001-2022.md` 등에 `claudesec scan --compliance isms-p` 및 Prowler 체크와의 대응 관계 명시.
  - 필요 시 `docs/compliance/soc2.md` 추가. (출처: AICPA TSC, `.cursor/rules/security-citations.mdc` 준수.)
- **근거**: 감사·인증 시 근거 제시와 팀 온보딩에 필요.

### 우선순위 5 (선택) — 보조 도구 검토

- **목표**: 호스트/OS 수준 점검이 필요한 경우 Lynis 등 추가 통합 검토.
- **작업**: Lynis 설치·실행 조건 정리, 별도 체크 스크립트(`scanner/checks/infra/` 또는 새 카테고리)에서 실행해 결과만 수집. 우선 Prowler 기반 컴플라이언스가 안정화된 후 진행.
- **근거**: Prowler가 클라우드·GitHub 중심이므로, OS/호스트는 별도 도구로 보완.

---

## 4. 프레임워크별 우선순위 (비즈니스 관점)

| 순위 | 프레임워크 | 대상 | ClaudeSec 반영 우선순위 |
|------|------------|------|--------------------------|
| 1 | **KISA ISMS-P** | 국내 의무·인증 대상 | Prowler 연동 시 `kisa_isms_p` 즉시 지원. 대시보드 이미 반영됨. |
| 2 | **ISO 27001:2022** | 전사 ISMS | Prowler `--compliance iso27001_2022` 연동. 대시보드 이미 반영됨. |
| 3 | **SOC2** | 클라우드·SaaS 고객 요구 | Prowler 연동 + 대시보드 SOC2 탭 추가. |
| 4 | **PCI-DSS** | 결제·카드 데이터 처리 | Prowler 연동. 대시보드 이미 반영됨. |

---

## 5. Best Practices 요약

1. **단일 스캐너 우선**: Prowler로 ISO/ISMS-P/SOC2/PCI-DSS를 먼저 일원화하고, 부족한 영역만 보조 도구 추가.
2. **환경변수·설정 일원화**: `--compliance`와 `.claudesec.yml`의 `compliance`를 동일한 값 체계로 통일 (예: `iso27001`, `isms-p`, `soc2`, `pci-dss`).
3. **Prowler 식별자 매핑**: CLI/설정 값과 Prowler 내부 프레임워크 이름(`--list-compliance` 출력)을 한 곳(스크립트 또는 설정)에서 매핑해 유지보수 비용 절감.
4. **보안 인용**: 컴플라이언스 가이드·대시보드 설명은 `.cursor/rules/security-citations.mdc`에 따라 OWASP/NIST/CIS/공식 표준 문서를 인용.
5. **민감 정보 금지**: `.cursor/rules/no-sensitive-paths.mdc` 준수. 예제에는 실제 경로·계정 ID·고객사명을 넣지 않음.

---

## 6. QueryPie Audit Points 대시보드 및 스캔 통합 ✅

[querypie/audit-points](https://github.com/querypie/audit-points)는 Harbor, Jenkins, Nexus, Okta, QueryPie, Scalr, IDEs 등 SaaS/DevSecOps 제품의 **감사 포인트(체크리스트)** 를 Markdown으로 공개한 저장소이다. ClaudeSec에서 **해당 프로젝트에 맞게** Audit Points를 참고하여 스캔·대시보드에 반영한다.

### 6.1 프로젝트 맞춤 스캔

- **제품 감지**: `scanner/lib/audit-points-scan.py`가 저장소 내 파일/디렉터리로 적용 제품을 판별한다.
  - Jenkins → `Jenkinsfile`, `.jenkins`, `jenkins.yaml` 등
  - Harbor → `harbor.yml`, `.harbor`
  - Nexus → `pom.xml`, `.nexus` 또는 빌드 파일 내 nexus 언급
  - Okta / QueryPie / Scalr → 해당 설정 파일 또는 키워드
  - IDEs → `.vscode`, `.idea`
- **스캔 실행**: `claudesec scan -c saas` 시 `scanner/checks/saas/audit-points.sh`가 실행되며, 감지된 제품과 체크리스트 항목 수를 스캔 결과에 보고하고, `.claudesec-audit-points/detected.json`에 기록한다.
- **캐시**: 체크리스트 메타는 `scan_dir/.claudesec-audit-points/cache.json`에 유지(24시간 TTL). 캐시가 없으면 대시보드 생성 또는 스캔 시 GitHub API로 채운다.

### 6.2 대시보드

- **Audit Points 탭**: `detected.json`이 있으면 상단에 **Relevant to this project** 카드로 감지된 제품별 체크리스트 링크를 표시한다. 이어서 **All products** 카드에서 querypie/audit-points 전체 제품 목록을 열람·링크할 수 있다.
- **용도**: 자동 검사 결과와 함께, 해당 프로젝트에 적용되는 Audit Points를 수동 체크리스트로 참고.

---

## 7. 참고 자료

- [QueryPie Audit Points](https://github.com/querypie/audit-points) — SaaS/DevSecOps 감사 포인트 공유 저장소
- [Prowler Compliance (공식 문서)](https://docs.prowler.com/user-guide/cli/tutorials/compliance)
- [Prowler Hub — Compliance](https://hub.prowler.com/compliance)
- [KISA ISMS-P 소개](https://isms.kisa.or.kr/main/ispims/intro/)
- [PCI-DSS 문서](https://www.pcisecuritystandards.org/document_library/?category=pcidss)
- [AICPA SOC 2](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome) (SOC2 인용 시)
