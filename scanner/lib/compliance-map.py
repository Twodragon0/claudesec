"""
ClaudeSec — Compliance framework mapping (lightweight standalone module).

Extracted from dashboard-gen.py so that output.sh can load compliance
logic without importing the full 5000+ line dashboard module.
"""

COMPLIANCE_CONTROL_MAP = {
    "ISO 27001:2022": [
        {
            "control": "A.5.1",
            "name": "Information security policy",
            # governance/legal — no automated NIST 800-53A Test method
            "desc": "Policies documented, shared, and reviewed",
            "action": "Document policy, periodic review, staff training and approval.",
            "checks": ["security_policy"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "A.8.2",
            "name": "Access control",
            "desc": "Access to resources and systems restricted by role and need",
            "action": "Apply RBAC, branch protection, PR approval; minimize admin rights.",
            "checks": ["branch_protection", "require_approval", "admin"],
            "status": "",
        },
        {
            "control": "A.8.5",
            "name": "Secure authentication",
            "desc": "Strong authentication (MFA, SSO) in use",
            "action": "Adopt MFA and SSO; strengthen password policy and session management.",
            "checks": ["mfa", "two_factor", "_sso", "authentication"],
            "status": "",
        },
        {
            "control": "A.8.9",
            "name": "Configuration management",
            "desc": "Config and defaults managed per security baseline",
            "action": "Apply hardening guides; change defaults; disable unnecessary services.",
            "checks": ["configuration", "misconfigur", "default"],
            "status": "",
        },
        {
            "control": "A.8.24",
            "name": "Cryptography",
            "desc": "Encryption and key management for data in transit and at rest",
            "action": "Use TLS and KMS; store secrets in secret manager; key rotation.",
            "checks": ["encrypt", "tls", "ssl", "secret"],
            "status": "",
        },
        {
            "control": "A.8.28",
            "name": "Secure coding",
            "desc": "Secure coding and SAST for vulnerability management",
            "action": "Adopt CodeQL/SAST, code review; prevent injection and XSS.",
            "checks": ["code_scanning", "injection", "codeql"],
            "status": "",
        },
        {
            "control": "A.8.8",
            "name": "Technical vulnerability management",
            "desc": "Dependency, CVE detection, and patching in place",
            "action": "Dependabot and CVE scanning; patch policy and SBOM.",
            "checks": ["dependabot", "cve", "vulnerab", "outdated"],
            "status": "",
        },
    ],
    "KISA ISMS-P": [
        # ── 1. 관리체계 수립 및 운영 ──
        {
            "control": "1.1.1",
            "name": "경영진의 참여 (Management commitment)",
            # governance — no automated NIST 800-53A Test method
            "desc": "최고경영자의 정보보호 및 개인정보보호 관리체계 수립·운영 참여",
            "action": "정보보호 정책 승인; 연간 보안 계획 수립; 경영진 검토 보고 체계 마련.",
            "checks": ["security_policy", "governance"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "1.2.1",
            "name": "정보자산 식별 (Asset identification)",
            "desc": "정보자산을 식별하고 중요도에 따라 분류·관리",
            "action": "자산 목록 관리; 자산 분류 체계; 담당자 지정 및 주기적 현행화.",
            "checks": ["inventory", "asset", "resource", "discovery"],
            "status": "",
        },
        {
            "control": "1.2.2",
            "name": "위험 평가 (Risk assessment)",
            "desc": "정보자산에 대한 위험을 평가하고 관리 계획 수립",
            "action": "연간 위험 평가; 위험 수용 기준; 잔여 위험 관리 및 경영진 승인.",
            "checks": ["vulnerab", "risk", "assessment", "scan"],
            "status": "",
        },
        # ── 2. 보호대책 요구사항 ──
        {
            "control": "2.1.1",
            "name": "정책의 유지관리 (Policy management)",
            # governance — no automated NIST 800-53A Test method
            "desc": "정보보호 및 개인정보보호 정책·지침 수립, 승인, 이행",
            "action": "정책 문서화; 연 1회 이상 검토; 전 직원 숙지 교육.",
            "checks": ["security_policy", "governance"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "2.2.1",
            "name": "주요 직무자 지정·감독 (Key personnel)",
            "desc": "주요 직무자를 지정하고 직무 분리 및 상호 감독",
            "action": "핵심 직무자 지정; 직무 분리(SoD); 퇴직 시 권한 즉시 회수.",
            "checks": ["admin", "permission", "account", "user", "iam"],
            "status": "",
        },
        {
            "control": "2.2.4",
            "name": "보안 인식 교육 (Security awareness)",
            # human/training — no automated NIST 800-53A Test method
            "desc": "정보보호 및 개인정보보호 교육 실시",
            "action": "연 1회 이상 교육; 교육 이수 기록 관리; 직무별 맞춤 교육.",
            "checks": ["training", "awareness", "education"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "2.5.1",
            "name": "사용자 계정 관리 (Account management)",
            "desc": "사용자 등록·변경·삭제 절차 수립 및 이행",
            "action": "계정 등록 승인; 미사용 계정 비활성화; 퇴직자 즉시 삭제.",
            "checks": ["account", "user", "iam", "inactive", "disabled"],
            "status": "",
        },
        {
            "control": "2.5.2",
            "name": "사용자 식별 (User identification)",
            "desc": "개인별 고유한 사용자 계정 부여",
            "action": "공용 계정 금지; 개인별 고유 ID 부여; 특수권한 계정 별도 관리.",
            "checks": ["authentication", "identity", "shared_account", "root"],
            "status": "",
        },
        {
            "control": "2.5.3",
            "name": "사용자 인증 (User authentication)",
            "desc": "안전한 인증 수단 사용 (MFA, SSO 등)",
            "action": "MFA 적용; SSO 통합; 비밀번호 복잡도 및 주기적 변경.",
            "checks": ["mfa", "two_factor", "_sso", "authentication", "password"],
            "status": "",
        },
        {
            "control": "2.5.4",
            "name": "비밀번호 관리 (Password management)",
            "desc": "비밀번호 작성규칙, 변경주기, 이력관리 등 안전한 비밀번호 관리 (2023.10 신설)",
            "action": "비밀번호 복잡도 정책; 초기/임시 비밀번호 즉시 변경; 이전 비밀번호 재사용 제한.",
            "checks": ["password", "credential", "secret", "rotation"],
            "status": "",
        },
        {
            "control": "2.6.1",
            "name": "접근권한 관리 (Access control policy)",
            "desc": "접근권한 정책 수립 및 권한 최소 부여",
            "action": "RBAC 적용; 최소 권한 원칙; 주기적 권한 검토.",
            "checks": ["branch_protection", "access", "permission", "restrict", "rbac"],
            "status": "",
        },
        {
            "control": "2.6.2",
            "name": "정보시스템 접근 (System access control)",
            "desc": "정보시스템 접근 통제 및 인증·권한 관리",
            "action": "서버·DB 접근통제; 관리자 접근 이력 관리; 원격접근 보안.",
            "checks": ["mfa", "authentication", "_sso", "two_factor", "admin"],
            "status": "",
        },
        {
            "control": "2.6.3",
            "name": "응용프로그램 접근 (Application access, 2023.10 신설)",
            "desc": "응용프로그램 및 데이터에 대한 접근통제",
            "action": "애플리케이션 레벨 인증; API 접근 토큰 관리; 세션 관리.",
            "checks": ["token", "session", "application", "oauth"],
            "status": "",
        },
        {
            "control": "2.6.7",
            "name": "인터넷 접속 통제 (Internet access control)",
            "desc": "비인가 인터넷 접속 통제 및 모니터링",
            "action": "네트워크 세그멘테이션; 방화벽 정책; 웹 필터링; VPN.",
            "checks": ["firewall", "network", "segmentation", "vpc", "security_group"],
            "status": "",
        },
        {
            "control": "2.7.1",
            "name": "암호정책 적용 (Cryptographic policy)",
            "desc": "암호화 대상 선정, 안전한 암호 알고리즘 사용, 키 관리",
            "action": "TLS 1.2+; AES-256 이상; KMS 키 관리; 인증서 갱신 자동화.",
            "checks": ["encrypt", "tls", "ssl", "secret", "kms", "certificate"],
            "status": "",
        },
        {
            "control": "2.7.2",
            "name": "암호키 관리 (Key management)",
            "desc": "암호키의 안전한 생성·저장·분배·파기 관리",
            "action": "HSM/KMS 활용; 키 순환 주기 설정; 키 분리 보관; 키 파기 절차.",
            "checks": ["kms", "key_rotation", "secret_manager"],
            "status": "",
        },
        {
            "control": "2.8.1",
            "name": "보안 요구사항 정의 (Security requirements)",
            "desc": "정보시스템 도입·개발 시 보안 요구사항 명세",
            "action": "보안 요구사항 체크리스트; 위협 모델링; 보안 설계 검토.",
            "checks": ["security_policy", "requirement", "design"],
            "status": "",
        },
        {
            "control": "2.8.4",
            "name": "시큐어 코딩 (Secure coding)",
            "desc": "시큐어 코딩 표준 준수 및 소스코드 검증",
            "action": "SAST/CodeQL 적용; 코드 리뷰 필수; OWASP Top 10 대응; 인젝션 방지.",
            "checks": ["code_scanning", "injection", "codeql", "xss"],
            "status": "",
        },
        {
            "control": "2.8.6",
            "name": "시험과 운영 환경 분리 (Environment separation)",
            "desc": "개발·시험·운영 환경 분리 및 운영 데이터 보호",
            "action": "환경 분리; 운영 데이터 비식별 처리 후 테스트 사용; 접근통제 분리.",
            "checks": ["environment", "staging", "production", "namespace"],
            "status": "",
        },
        {
            "control": "2.9.1",
            "name": "변경관리 (Change management)",
            "desc": "정보시스템 변경 요청·검토·승인·이행·기록",
            "action": "PR 기반 변경 승인; 변경 이력 추적; 롤백 절차 수립.",
            "checks": ["review", "_approval", "branch_protection", "codeowners", "status_checks", "force_push", "signed_commits"],
            "status": "",
        },
        {
            "control": "2.9.3",
            "name": "로그 및 접근기록 관리 (Logging)",
            "desc": "정보시스템 접근·이용 기록 관리 및 보관",
            "action": "접근 로그 6개월 이상 보관; CloudTrail/감사 로그 활성화; 로그 무결성 보장.",
            "checks": ["logging", "audit", "log_maxage", "cloudtrail", "retention"],
            "status": "",
        },
        {
            "control": "2.9.4",
            "name": "백업 관리 (Backup management)",
            "desc": "주요 정보의 백업 및 복구 절차 수립·이행",
            "action": "주기적 백업; 복구 테스트; 백업 데이터 암호화 및 격리 보관.",
            "checks": ["backup", "recovery", "snapshot", "restore"],
            "status": "",
        },
        {
            "control": "2.10.1",
            "name": "보안시스템 운영 (Security system operations)",
            "desc": "방화벽, IDS/IPS, 백신 등 보안시스템 운영·관리",
            "action": "방화벽 정책 주기적 검토; EDR/AV 업데이트; IDS/IPS 모니터링.",
            "checks": ["firewall", "security_group", "antivirus"],
            "status": "",
        },
        {
            "control": "2.10.4",
            "name": "전자거래 및 핀테크 보안 (Fintech security)",
            "desc": "전자거래 시 데이터 무결성·기밀성 보장",
            "action": "전송구간 암호화; 거래 로그 보관; 부인방지 대책.",
            "checks": ["tls", "https", "certificate", "transaction"],
            "status": "",
        },
        {
            "control": "2.10.5",
            "name": "정보전송 보안 (Data transfer security)",
            "desc": "정보 전송 시 암호화 및 안전한 전송 채널 사용",
            "action": "TLS/SFTP 사용; 이메일 암호화; 안전한 파일 전송 절차.",
            "checks": ["tls", "ssl", "https", "encrypt", "transfer"],
            "status": "",
        },
        {
            "control": "2.10.7",
            "name": "패치 관리 (Patch management)",
            "desc": "운영체제, 응용프로그램 보안 패치 적용",
            "action": "Dependabot/CVE 모니터링; 긴급 패치 절차; SBOM 관리.",
            "checks": [
                "dependabot",
                "cve",
                "vulnerab",
                "outdated",
                "patch",
                "latest",
                "_upgrade",
                "supported_version",
                "extended_support",
                "managed_updates",
                "deprecated_engine",
                "system_updates",
            ],
            "status": "",
        },
        {
            "control": "2.10.8",
            "name": "악성코드 통제 (Malware control)",
            "desc": "악성코드 감염 예방·탐지·대응",
            "action": "EDR/SentinelOne 운영; 실시간 탐지; 격리 및 복구 절차.",
            "checks": ["malware", "antivirus", "sentinelone"],
            "status": "",
        },
        {
            "control": "2.11.1",
            "name": "사고 예방 및 대응체계 구축 (Incident response)",
            "desc": "침해사고 예방, 탐지, 대응, 복구 체계 수립",
            "action": "SIEM/모니터링; 대응 플레이북; 24시간 내 신고(정보통신망법 2024 개정); 사후 분석.",
            "checks": ["monitoring", "logging", "alert", "audit", "incident"],
            "status": "",
        },
        {
            "control": "2.11.2",
            "name": "취약점 점검 및 조치 (Vulnerability management)",
            "desc": "정기적 취약점 점검 및 조치 이행",
            "action": "분기별 취약점 점검; Prowler/OWASP 스캔; 조치 결과 보고.",
            "checks": ["vulnerab", "scan", "prowler", "pentest", "assessment"],
            "status": "",
        },
        {
            "control": "2.11.5",
            "name": "사고 분석 및 공유 (Post-incident analysis)",
            "desc": "침해사고 원인 분석 및 재발 방지 대책 수립",
            "action": "사고 보고서 작성; 원인 분석; 재발 방지 대책; 교훈 공유.",
            "checks": ["incident", "post_mortem", "analysis"],
            "status": "",
        },
        {
            "control": "2.12.1",
            "name": "재해복구 체계 구축 (Disaster recovery)",
            "desc": "IT 재해복구 계획 수립 및 훈련",
            "action": "DR 계획; RTO/RPO 정의; 연 1회 이상 복구 훈련; 백업 검증.",
            "checks": ["backup", "recovery", "disaster", "restore", "availability"],
            "status": "",
        },
        # ── 3. 개인정보 처리단계별 요구사항 (2023.10 개정 + 2025.3.13 개인정보보호법 3차 반영) ──
        {
            "control": "3.1.1",
            "name": "개인정보 수집·이용 (PII collection, 2023.10 개정)",
            "desc": "개인정보 수집 시 목적 명시, 동의 획득, 최소 수집 원칙",
            "action": "수집 목적 명시; 필수/선택 동의 분리; 최소 수집 원칙 이행; 법적 근거 확인.",
            "checks": ["personal_data", "pii", "consent", "privacy", "collection"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.1.3",
            "name": "주민등록번호 처리 제한 (SSN restriction)",
            "desc": "주민등록번호 수집 원칙적 금지, 법령 근거 시에만 처리",
            "action": "주민번호 수집 최소화; 대체 수단(CI/DI) 활용; 암호화 저장 필수.",
            "checks": ["pii", "ssn", "identification", "encrypt", "masking"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.1.4",
            "name": "민감정보·고유식별정보 제한 (Sensitive data, 2023.10 개정)",
            "desc": "민감정보 및 고유식별정보 처리 시 별도 동의·보호조치",
            "action": "별도 동의 획득; 암호화 필수; 접근 제한; 처리 현황 관리.",
            "checks": ["sensitive", "biometric", "encrypt", "pii"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.2.1",
            "name": "개인정보 현황관리 (PII inventory)",
            "desc": "보유 개인정보 현황 관리 및 처리 목적별 분류",
            "action": "개인정보 처리대장; 보유량·목적·보유기간 관리; 주기적 현행화.",
            "checks": ["pii", "inventory", "data_classification", "personal_data"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.2.5",
            "name": "가명정보 처리 (Pseudonymization, 2023.10 신설)",
            "desc": "가명정보 처리 시 안전조치 및 재식별 금지",
            "action": "가명처리 기준 수립; 결합 전문기관 활용; 재식별 금지 조치.",
            "checks": ["pseudonymization", "anonymization", "masking", "de_identification"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.3.1",
            "name": "제3자 제공 (Third-party sharing, 2023.10 개정)",
            "desc": "개인정보 제3자 제공 시 동의 및 계약 관리",
            "action": "제공 동의 획득; 제공 항목·목적 명시; 제공 이력 관리.",
            "checks": ["third_party", "sharing", "consent", "data_transfer"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.3.4",
            "name": "국외이전 (Cross-border transfer, 2023.10 개정)",
            "desc": "개인정보 국외이전 시 정보주체 동의 및 보호조치",
            "action": "국외이전 동의; 수탁자 보호조치 계약; 이전 현황 공개.",
            "checks": ["cross_border", "international", "gdpr"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.4.1",
            "name": "개인정보 파기 (PII deletion)",
            "desc": "보유기간 경과·목적 달성 시 지체 없이 파기",
            "action": "파기 절차; 복구 불가능한 방법(물리적 파괴, 데이터 삭제); 파기 기록 관리.",
            "checks": ["deletion", "retention", "destroy", "purge", "lifecycle"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.5.1",
            "name": "개인정보처리방침 공개 (Privacy policy disclosure)",
            "desc": "개인정보 처리방침 수립 및 공개",
            "action": "처리방침 웹사이트 게시; 필수 기재항목 확인; 변경 시 공지.",
            "checks": ["privacy_policy", "disclosure", "notice", "transparency"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.5.2",
            "name": "정보주체 권리보장 (Data subject rights, 2025.3.13 개정)",
            "desc": "열람·정정·삭제·처리정지·전송요구·자동화결정 거부 권리 보장",
            "action": "권리 행사 절차; 전송요구권(데이터이동권) 대응; 자동화 결정 거부·설명 요구권 대응; 10일 내 처리.",
            "checks": ["data_subject", "right_to_access", "right_to_delete", "portability", "automated_decision"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "3.5.3",
            "name": "이용내역 통지 (Usage notification)",
            "desc": "개인정보 이용내역을 정보주체에게 주기적 통지",
            "action": "연 1회 이상 이용내역 통지; 통지 내용(항목, 이용목적, 보유기간); 전자적 통지.",
            "checks": ["notification", "notice", "transparency", "reporting"],
            "assessable": False,
            "status": "",
        },
    ],
    # ISMS 간편인증 (2024 신설) — 소규모 기업 대상, 40개 항목으로 경량화
    # 기존 ISMS-P 102개에서 핵심 통제항목만 선별 (정보통신망법 제47조의7)
    "KISA ISMS Simple": [
        # governance — no automated NIST 800-53A Test method
        {"control": "S-1.1", "name": "관리체계 기반 마련", "desc": "정보보호 정책 수립 및 경영진 참여", "action": "정보보호 정책 승인; 담당자 지정; 예산 확보.", "checks": ["security_policy", "governance"], "assessable": False, "status": ""},
        {"control": "S-1.2", "name": "위험 관리", "desc": "자산 식별 및 위험 평가·관리", "action": "자산 목록 관리; 위험 평가; 위험 처리 계획.", "checks": ["inventory", "asset", "vulnerab", "risk"], "status": ""},
        # governance — no automated NIST 800-53A Test method
        {"control": "S-2.1", "name": "정보보호 정책", "desc": "정보보호 정책 수립·시행·검토", "action": "정책 문서화; 전 직원 숙지; 연 1회 이상 검토.", "checks": ["security_policy", "governance"], "assessable": False, "status": ""},
        {"control": "S-2.2", "name": "인적 보안", "desc": "직무 분리, 보안 서약, 교육", "action": "직무 분리(SoD); 입사/퇴사 절차; 연 1회 보안 교육.", "checks": ["admin", "permission", "training", "account"], "status": ""},
        {"control": "S-2.3", "name": "외부자 보안", "desc": "외부자(위탁, 협력사) 보안 관리", "action": "위탁 계약 시 보안 요구사항; 접근 통제; 주기적 점검.", "checks": ["third_party", "vendor", "external"], "status": ""},
        {"control": "S-2.4", "name": "사용자 인증 관리", "desc": "계정·비밀번호·인증 관리", "action": "MFA 적용; 비밀번호 복잡도; 미사용 계정 비활성화.", "checks": ["mfa", "authentication", "password", "account", "_sso"], "status": ""},
        {"control": "S-2.5", "name": "접근권한 관리", "desc": "최소 권한 부여 및 주기적 검토", "action": "RBAC; 권한 검토; 퇴직자 즉시 회수.", "checks": ["branch_protection", "access", "permission", "restrict", "rbac"], "status": ""},
        {"control": "S-2.6", "name": "네트워크 접근통제", "desc": "네트워크 영역 분리 및 접근 제어", "action": "방화벽; VPC/서브넷; Security Group 최소 오픈.", "checks": ["firewall", "network", "segmentation", "vpc", "security_group"], "status": ""},
        {"control": "S-2.7", "name": "암호화 적용", "desc": "전송·저장 시 암호화", "action": "TLS 1.2+; 저장 암호화(AES-256); KMS 키 관리.", "checks": ["encrypt", "tls", "ssl", "kms", "certificate"], "status": ""},
        {"control": "S-2.8", "name": "시큐어 코딩", "desc": "안전한 소프트웨어 개발", "action": "SAST/CodeQL; 코드 리뷰; OWASP Top 10 대응.", "checks": ["code_scanning", "injection", "codeql"], "status": ""},
        {"control": "S-2.9", "name": "변경 관리", "desc": "시스템 변경 승인·이행·기록", "action": "PR 기반 변경; 변경 이력 추적; 롤백 절차.", "checks": ["review", "_approval", "branch_protection", "codeowners", "status_checks", "force_push", "signed_commits"], "status": ""},
        {"control": "S-2.10", "name": "로그 관리", "desc": "접근·이용 기록 수집·보관", "action": "감사 로그 6개월 보관; CloudTrail 활성화; 무결성 보장.", "checks": ["logging", "audit", "cloudtrail", "retention"], "status": ""},
        {"control": "S-2.11", "name": "취약점 관리", "desc": "정기 취약점 점검 및 조치", "action": "Prowler/OWASP 스캔; 패치 관리; CVE 모니터링.", "checks": ["vulnerab", "scan", "prowler", "cve", "patch", "latest", "_upgrade", "owasp"], "status": ""},
        {"control": "S-2.12", "name": "침해사고 대응", "desc": "사고 탐지·대응·신고·복구", "action": "SIEM 모니터링; 24시간 내 신고(정보통신망법); 대응 플레이북.", "checks": ["monitoring", "alert", "incident", "logging"], "status": ""},
        {"control": "S-2.13", "name": "악성코드 대응", "desc": "악성코드 예방·탐지", "action": "EDR/AV 운영; 실시간 탐지; 격리 및 복구.", "checks": ["malware", "antivirus", "endpoint_protection", "antimalware", "wdatp"], "status": ""},
        {"control": "S-2.14", "name": "백업 및 복구", "desc": "주요 정보 백업 및 복구 절차", "action": "정기 백업; 복구 테스트; 백업 암호화.", "checks": ["backup", "recovery", "snapshot", "restore"], "status": ""},
        # PII/legal — no automated NIST 800-53A Test method
        {"control": "S-3.1", "name": "개인정보 수집·이용", "desc": "목적 명시, 동의 획득, 최소 수집", "action": "필수/선택 동의 분리; 최소 수집; 법적 근거 확인.", "checks": ["personal_data", "pii", "consent", "privacy"], "assessable": False, "status": ""},
        # PII/legal — no automated NIST 800-53A Test method
        {"control": "S-3.2", "name": "개인정보 보관·파기", "desc": "보유기간 준수 및 안전한 파기", "action": "보유기간 경과 시 파기; 복구 불가 방법; 파기 기록.", "checks": ["deletion", "retention", "destroy", "lifecycle"], "assessable": False, "status": ""},
        # PII/legal — no automated NIST 800-53A Test method
        {"control": "S-3.3", "name": "개인정보 제3자 제공", "desc": "동의 기반 제공 및 관리", "action": "제공 동의; 항목·목적 명시; 제공 이력 관리.", "checks": ["third_party", "sharing", "consent", "data_transfer"], "assessable": False, "status": ""},
        # PII/legal — no automated NIST 800-53A Test method
        {"control": "S-3.4", "name": "정보주체 권리 보장", "desc": "열람·정정·삭제·처리정지·전송요구·자동화결정 거부", "action": "권리 행사 절차; 전송요구권 대응; 10일 내 처리.", "checks": ["data_subject", "right_to_access", "right_to_delete", "portability"], "assessable": False, "status": ""},
    ],
    "PCI-DSS v4.0.1": [
        {
            "control": "Req 1",
            "name": "Network security controls",
            "desc": "Firewall, network segmentation, TLS",
            "action": "Firewall policy; DMZ and segmentation; enforce TLS.",
            "checks": ["firewall", "network", "tls"],
            "status": "",
        },
        {
            "control": "Req 2",
            "name": "Secure configuration",
            "desc": "Hardened system and service settings",
            "action": "Hardening; change default passwords; remove unnecessary services.",
            "checks": ["configuration", "default", "hardening", "benchmark"],
            "status": "",
        },
        {
            "control": "Req 3",
            "name": "Protect stored data",
            "desc": "Encryption and key management for cardholder data",
            "action": "Encrypt at rest; KMS and key rotation; consider tokenization.",
            "checks": ["encrypt", "kms", "key_rotation"],
            "status": "",
        },
        {
            "control": "Req 6",
            "name": "Secure software development",
            "desc": "Secure SDLC and vulnerability management",
            "action": "SAST and dependency checks; patching and code review.",
            "checks": ["code_scanning", "injection", "vulnerab"],
            "status": "",
        },
        {
            "control": "Req 7",
            "name": "Access restriction",
            "desc": "Access only for those who need it",
            "action": "RBAC and least privilege; branch protection and approval policy.",
            "checks": ["branch_protection", "permission", "restrict", "admin"],
            "status": "",
        },
        {
            "control": "Req 8",
            "name": "User identification and authentication",
            "desc": "Strong authentication and account management",
            "action": "MFA; password policy; account lockout and session management.",
            "checks": ["mfa", "authentication", "two_factor", "_sso"],
            "status": "",
        },
        {
            "control": "Req 10",
            "name": "Logging and monitoring",
            "desc": "Logs and monitoring for access, change, and incidents",
            "action": "Collect and retain audit logs; detection and alerting; periodic review.",
            "checks": ["logging", "monitoring", "audit", "alert"],
            "status": "",
        },
    ],
    "NIST 800-53 Rev5": [
        {
            "control": "AC-2",
            "name": "Account management",
            "desc": "Manage system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts",
            "action": "Enforce account lifecycle management; periodic access review; disable inactive accounts.",
            "checks": ["account", "user", "admin", "permission", "iam"],
            "status": "",
        },
        {
            "control": "AC-6",
            "name": "Least privilege",
            "desc": "Employ the principle of least privilege, allowing only authorized accesses necessary for organizational missions",
            "action": "Implement RBAC; restrict admin privileges; review and minimize permissions regularly.",
            "checks": ["least_privilege", "rbac", "restrict", "permission", "branch_protection", "admin"],
            "status": "",
        },
        {
            "control": "AU-2",
            "name": "Event logging",
            "desc": "Identify events that the system is capable of logging in support of the audit function",
            "action": "Enable audit logging for all critical events; configure log retention and integrity checks.",
            "checks": ["logging", "audit", "log_maxage", "event_log", "monitoring"],
            "status": "",
        },
        {
            "control": "CA-7",
            "name": "Continuous monitoring",
            # stays assessable: monitoring/scan/vulnerability keywords carry real technical signal; only the strategy-doc half is unverifiable (accepted documented residual)
            "desc": "Develop a continuous monitoring strategy and implement a continuous monitoring program",
            "action": "Deploy SIEM/monitoring tools; continuous vulnerability scanning; automated alerts.",
            "checks": ["monitoring", "alert", "scan", "vulnerab", "continuous"],
            "status": "",
        },
        {
            "control": "CM-6",
            "name": "Configuration settings",
            "desc": "Establish and document configuration settings for components using security configuration checklists",
            "action": "Apply CIS benchmarks; enforce secure defaults; automate configuration drift detection.",
            "checks": ["configuration", "benchmark", "hardening", "default", "baseline"],
            "status": "",
        },
        {
            "control": "IA-2",
            "name": "Identification and authentication",
            "desc": "Uniquely identify and authenticate organizational users and processes",
            "action": "Enforce MFA for all users; implement SSO; strong password and session policies.",
            "checks": ["mfa", "authentication", "two_factor", "_sso", "identity"],
            "status": "",
        },
        {
            "control": "RA-5",
            "name": "Vulnerability monitoring and scanning",
            "desc": "Monitor and scan for vulnerabilities in the system and hosted applications",
            "action": "Run SAST/DAST scans; dependency vulnerability checks; prioritize by CVSS severity.",
            "checks": ["vulnerab", "code_scanning", "dependency", "cve"],
            "status": "",
        },
        {
            "control": "SC-8",
            "name": "Transmission confidentiality and integrity",
            "desc": "Protect the confidentiality and integrity of transmitted information",
            "action": "Enforce TLS 1.2+; certificate management; HSTS and secure transport headers.",
            "checks": ["tls", "ssl", "https", "certificate", "encrypt"],
            "status": "",
        },
        {
            "control": "SC-28",
            "name": "Protection of information at rest",
            "desc": "Protect the confidentiality and integrity of information at rest",
            "action": "Encrypt data at rest; KMS key management and rotation; secure backup storage.",
            "checks": ["encrypt", "kms", "key_rotation", "storage", "secret"],
            "status": "",
        },
        {
            "control": "SI-4",
            "name": "System monitoring",
            "desc": "Monitor the system to detect attacks, indicators of potential attacks, and unauthorized connections",
            "action": "Deploy IDS/IPS; network monitoring; real-time alerting and incident correlation.",
            "checks": ["monitoring", "detection", "alert", "intrusion", "anomaly"],
            "status": "",
        },
    ],
    "CIS Benchmarks": [
        {
            "control": "CIS-1.1",
            "name": "Inventory of authorized and unauthorized devices",
            "desc": "Maintain an accurate and up-to-date inventory of all technology assets",
            "action": "Automate asset discovery; tag and classify resources; remove unauthorized assets.",
            "checks": ["inventory", "asset", "resource", "discovery"],
            "status": "",
        },
        {
            "control": "CIS-4.1",
            "name": "Secure configuration for network infrastructure",
            "desc": "Establish and maintain secure network device configurations",
            "action": "Apply firewall rules; enforce network segmentation; disable unused ports and services.",
            "checks": ["firewall", "network", "segmentation"],
            "status": "",
        },
        {
            "control": "CIS-5.1",
            "name": "Account management policies",
            "desc": "Establish and maintain an account management process",
            "action": "Enforce MFA; regular access reviews; promptly disable departed user accounts.",
            "checks": ["mfa", "account", "authentication", "access", "admin"],
            "status": "",
        },
        {
            "control": "CIS-6.1",
            "name": "Audit log management",
            "desc": "Establish and maintain an audit log management process",
            "action": "Enable logging on all critical systems; define retention policies; protect log integrity.",
            "checks": ["logging", "audit", "log_maxage", "retention"],
            "status": "",
        },
        {
            "control": "CIS-7.1",
            "name": "Vulnerability management process",
            "desc": "Establish and maintain a vulnerability management process",
            "action": "Automate vulnerability scanning; track remediation SLAs; prioritize critical CVEs.",
            "checks": ["vulnerab", "scan", "patch", "cve", "remediation"],
            "status": "",
        },
        {
            "control": "CIS-8.1",
            "name": "Data protection",
            "desc": "Establish and maintain a data management process including encryption requirements",
            "action": "Classify data sensitivity; encrypt in transit and at rest; secret scanning enabled.",
            "checks": ["encrypt", "secret", "kms", "tls", "data_protection"],
            "status": "",
        },
        {
            "control": "CIS-K8s-1.1",
            "name": "API server secure configuration",
            "desc": "Ensure the API server is configured securely per CIS Kubernetes Benchmark",
            "action": "Enable audit logging; restrict anonymous auth; enforce RBAC; TLS for API server.",
            "checks": ["apiserver", "kube", "rbac", "anonymous", "kubelet"],
            "status": "",
        },
        {
            "control": "CIS-K8s-4.1",
            "name": "Worker node security",
            "desc": "Ensure worker node components are configured securely",
            "action": "Restrict kubelet permissions; enable read-only port protection; enforce TLS certificates.",
            "checks": ["kubelet", "worker", "tls_cert", "readonly"],
            "status": "",
        },
        {
            "control": "CIS-K8s-ArgoCD",
            "name": "ArgoCD RBAC and security configuration",
            "desc": "Verify ArgoCD RBAC policies, SSO integration, and project-level access restrictions",
            "action": "Enforce ArgoCD RBAC with least privilege; enable SSO; restrict project sources and destinations; disable anonymous access.",
            "checks": ["argocd", "argo", "gitops", "rbac", "_sso", "project"],
            "status": "",
        },
    ],
    # AICPA Trust Services Criteria (2017, revised 2022) — the nine Common
    # Criteria series. Named "SOC 2 (TSC)" rather than "SOC2" on purpose: see
    # test_soc2_framework_key_does_not_native_match_prowler_soc2 in
    # scanner/tests/test_compliance_map.py. Framework-level native matching
    # would pin all nine series to FAIL on any Prowler scan.
    "SOC 2 (TSC)": [
        {
            "control": "CC1",
            "name": "Control environment",
            # COSO governance — integrity, board oversight, org structure,
            # competence, accountability. No automated NIST 800-53A Test method.
            "desc": "Integrity, board oversight, organizational structure, competence, and accountability",
            "action": "Document org chart and security roles; background checks; annual performance and accountability review.",
            "checks": ["security_policy", "governance"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "CC2",
            "name": "Communication and information",
            # COSO governance — internal/external communication of control duties.
            "desc": "Security responsibilities communicated internally and to external parties",
            "action": "Publish SECURITY.md and disclosure contact; run security awareness training; brief the board periodically.",
            "checks": ["awareness", "training"],
            "assessable": False,
            "status": "",
        },
        {
            "control": "CC3",
            "name": "Risk assessment",
            "desc": "Risks to objectives identified and analyzed, including changes and fraud risk",
            "action": "Maintain a risk register; threat model changes; track dependency and CVE exposure with severity ratings.",
            "checks": ["vulnerab", "dependency", "dependabot", "scan", "cve"],
            "status": "",
        },
        # CC4 and CC5 both retain a high miss rate against Prowler's own SOC 2
        # mapping (75% and 72%), and BOTH are structural rather than a keyword
        # defect. Measured 2026-08-14 against the real 5.38 catalog:
        #
        #   CC5's 21 missed checks are ALL CloudWatch / Azure-Monitor alarm
        #   checks (`cloudwatch_changes_to_network_acls_alarm_configured`,
        #   `logging_log_metric_filter_and_alert_for_*_changes_enabled`).
        #   Prowler maps that same alarm family to CC4, CC5 AND CC7
        #   simultaneously. A keyword set cannot separate what the ground truth
        #   itself conflates.
        #
        # Two edits were proposed by review and both were REJECTED on measurement:
        #
        #   CC5 + `default`  -> recovers 0 of the 21 missed checks, while newly
        #                       lighting 158 corpus-wide. Pure dilution. (The
        #                       token's 169 corpus hits are real; none of them
        #                       are CC5's mapped checks.)
        #   CC4 + `alert`    -> recovers 3 of 24 (miss 85.7% -> 75.0%) but takes
        #                       CC4's corpus matches 137 -> 182 and its overlap
        #                       with CC7 from 38% -> 52% of CC4. Buying 3 checks
        #                       by making half of CC4 indistinguishable from CC7
        #                       is a bad trade for a per-criterion breakdown.
        #
        # Pinned in test_ci_compliance_keyword_guard.py so a future pass does not
        # re-propose either without re-measuring.
        {
            "control": "CC4",
            "name": "Monitoring activities",
            "desc": "Ongoing and separate evaluations confirm controls are present and operating",
            "action": "Run continuous control scans; internal audit and evidence review; track deficiency remediation to closure.",
            "checks": ["audit", "monitoring", "scan", "guardduty", "securityhub", "config_recorder"],
            "status": "",
        },
        {
            "control": "CC5",
            "name": "Control activities",
            "desc": "Control activities and general technology controls selected and deployed",
            "action": "Apply hardening baselines; enforce secure defaults; detect configuration drift automatically.",
            "checks": ["configuration", "misconfigur", "hardening", "benchmark"],
            "status": "",
        },
        {
            "control": "CC6",
            "name": "Logical and physical access controls",
            "desc": "Access restricted to authorized users; credentials and data protected at rest and in transit",
            "action": "Enforce MFA and SSO; least-privilege RBAC and periodic access review; TLS and KMS; enable secret scanning.",
            "checks": [
                "mfa",
                "two_factor",
                "_sso",
                "authentication",
                "rbac",
                "encrypt",
                "secret",
                "public_access",
                "publicly",
                "0.0.0.0",
                "security_group",
                "securitygroup",
                "ingress",
                "unrestricted",
            ],
            "status": "",
        },
        {
            "control": "CC7",
            "name": "System operations",
            "desc": "Anomalies and security incidents detected, evaluated, and responded to",
            "action": "Centralize logs with retention and integrity protection; real-time alerting; maintain and exercise an incident response plan.",
            "checks": ["logging", "incident", "detection", "alert", "anomaly", "cloudtrail", "flow_log", "log_file_validation"],
            "status": "",
        },
        {
            "control": "CC8",
            "name": "Change management",
            "desc": "Changes to infrastructure, data, software, and procedures are authorized, tested, and approved",
            "action": "Require PR approval and CODEOWNERS review; run SAST/CodeQL in CI; block merges on failing security checks.",
            "checks": ["branch_protection", "_approval", "codeowners", "status_checks", "force_push", "signed_commits", "code_scanning"],
            "status": "",
        },
        {
            "control": "CC9",
            "name": "Risk mitigation",
            # vendor/business-partner risk program — contractual and procedural
            # evidence a scanner cannot produce.
            "desc": "Risk mitigation activities for business disruption and vendor/business-partner relationships",
            "action": "Maintain a vendor inventory with security reviews and DPAs; define business continuity and insurance coverage.",
            "checks": ["governance", "third_party"],
            "assessable": False,
            "status": "",
        },
    ],
}


def _match_prowler_compliance(finding, framework_key):
    """Check if a prowler finding's native compliance data references a framework."""
    comp = finding.get("compliance", {})
    if not comp:
        return False
    fk = framework_key.lower()
    for key, val in comp.items():
        k = key.lower()
        if fk in k or k in fk:
            return True
        if isinstance(val, (list, str)) and any(
            fk in str(v).lower() for v in (val if isinstance(val, list) else [val])
        ):
            return True
    return False


_NATIVE_CACHE = None


def _native_mapping():
    """Prowler's own requirement->check data, loaded once. `{}` when unavailable.

    Import is deferred and failure is swallowed on purpose: compliance-map.py is
    loaded by output.sh via importlib in a bare scan, where a missing sibling or
    a missing Prowler install must not break the run.
    """
    global _NATIVE_CACHE
    if _NATIVE_CACHE is None:
        try:
            import importlib.util
            import os

            spec = importlib.util.spec_from_file_location(
                "prowler_native_map",
                os.path.join(
                    os.path.dirname(os.path.abspath(__file__)), "prowler_native_map.py"
                ),
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            _NATIVE_CACHE = module.load_all()
        except Exception:
            _NATIVE_CACHE = {}
    return _NATIVE_CACHE


def map_compliance(all_findings):
    """Map findings to compliance framework controls. Returns {framework: [ctrl_with_status]}.

    A control is matched by EXACT check-id membership when Prowler ships a
    mapping for it, and by keyword substring otherwise. Prowler's data is sparse
    — its KISA file maps only 26 of 101 requirements — so the keyword path is a
    fallback, not dead code. Each control reports which source decided it via
    `match_source`, so a reader can tell an exact mapping from an approximation.
    """
    native = _native_mapping()
    result = {}
    for framework, controls in COMPLIANCE_CONTROL_MAP.items():
        fw_native = native.get(framework, {})
        mapped = []
        for ctrl in controls:
            native_checks = fw_native.get(ctrl["control"])
            matching = []
            if native_checks:
                match_source = "prowler"
                for f in all_findings:
                    if str(f.get("check", "")) in native_checks:
                        matching.append(f)
            else:
                match_source = "keyword"
                for f in all_findings:
                    text = f"{f['check']} {f['title']} {f['message']}".lower()
                    keyword_match = any(kw in text for kw in ctrl["checks"])
                    native_match = _match_prowler_compliance(f, framework)
                    if keyword_match or native_match:
                        matching.append(f)
            if not ctrl.get("assessable", True):
                status = "N/A"
            else:
                status = "PASS" if len(matching) == 0 else "FAIL"
            mapped.append(
                {
                    **ctrl,
                    "status": status,
                    "count": len(matching),
                    "findings": matching[:5],
                    "match_source": match_source,
                }
            )
        result[framework] = mapped
    return result


def compliance_summary(compliance_map):
    """Return {framework: {pass, fail, na, total}} from map_compliance output.

    N/A controls are excluded from total (total = pass + fail).
    """
    summary = {}
    for fw, controls in compliance_map.items():
        p = sum(1 for c in controls if c["status"] == "PASS")
        f = sum(1 for c in controls if c["status"] == "FAIL")
        na = sum(1 for c in controls if c["status"] == "N/A")
        summary[fw] = {"pass": p, "fail": f, "na": na, "total": p + f}
    return summary
