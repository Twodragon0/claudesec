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
            "desc": "Policies documented, shared, and reviewed",
            "action": "Document policy, periodic review, staff training and approval.",
            "checks": ["security_policy"],
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
            "checks": ["mfa", "two_factor", "sso", "authentication"],
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
            "checks": ["code_scanning", "sast", "injection", "codeql"],
            "status": "",
        },
        {
            "control": "A.8.8",
            "name": "Technical vulnerability management",
            "desc": "Dependency, CVE detection, and patching in place",
            "action": "Dependabot and CVE scanning; patch policy and SBOM.",
            "checks": ["dependabot", "cve", "vulnerability", "outdated"],
            "status": "",
        },
    ],
    "KISA ISMS-P": [
        # ── 1. 관리체계 수립 및 운영 ──
        {
            "control": "1.1.1",
            "name": "경영진의 참여 (Management commitment)",
            "desc": "최고경영자의 정보보호 및 개인정보보호 관리체계 수립·운영 참여",
            "action": "정보보호 정책 승인; 연간 보안 계획 수립; 경영진 검토 보고 체계 마련.",
            "checks": ["security_policy", "policy", "governance"],
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
            "checks": ["vulnerability", "risk", "assessment", "scan"],
            "status": "",
        },
        # ── 2. 보호대책 요구사항 ──
        {
            "control": "2.1.1",
            "name": "정책의 유지관리 (Policy management)",
            "desc": "정보보호 및 개인정보보호 정책·지침 수립, 승인, 이행",
            "action": "정책 문서화; 연 1회 이상 검토; 전 직원 숙지 교육.",
            "checks": ["security_policy", "policy", "governance"],
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
            "desc": "정보보호 및 개인정보보호 교육 실시",
            "action": "연 1회 이상 교육; 교육 이수 기록 관리; 직무별 맞춤 교육.",
            "checks": ["training", "awareness", "education"],
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
            "checks": ["mfa", "two_factor", "sso", "authentication", "password"],
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
            "checks": ["mfa", "authentication", "sso", "two_factor", "admin"],
            "status": "",
        },
        {
            "control": "2.6.3",
            "name": "응용프로그램 접근 (Application access, 2023.10 신설)",
            "desc": "응용프로그램 및 데이터에 대한 접근통제",
            "action": "애플리케이션 레벨 인증; API 접근 토큰 관리; 세션 관리.",
            "checks": ["api", "token", "session", "application", "oauth"],
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
            "checks": ["kms", "key_rotation", "hsm", "secret_manager"],
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
            "checks": ["code_scanning", "sast", "injection", "codeql", "xss"],
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
            "checks": ["require_approval", "review", "pull_request", "change"],
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
            "checks": ["firewall", "security_group", "waf", "endpoint", "antivirus"],
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
            "checks": ["dependabot", "cve", "vulnerability", "outdated", "patch"],
            "status": "",
        },
        {
            "control": "2.10.8",
            "name": "악성코드 통제 (Malware control)",
            "desc": "악성코드 감염 예방·탐지·대응",
            "action": "EDR/SentinelOne 운영; 실시간 탐지; 격리 및 복구 절차.",
            "checks": ["malware", "antivirus", "endpoint", "edr", "sentinelone"],
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
            "checks": ["vulnerability", "scan", "prowler", "pentest", "assessment"],
            "status": "",
        },
        {
            "control": "2.11.5",
            "name": "사고 분석 및 공유 (Post-incident analysis)",
            "desc": "침해사고 원인 분석 및 재발 방지 대책 수립",
            "action": "사고 보고서 작성; 원인 분석; 재발 방지 대책; 교훈 공유.",
            "checks": ["incident", "forensic", "post_mortem", "analysis"],
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
            "status": "",
        },
        {
            "control": "3.1.3",
            "name": "주민등록번호 처리 제한 (SSN restriction)",
            "desc": "주민등록번호 수집 원칙적 금지, 법령 근거 시에만 처리",
            "action": "주민번호 수집 최소화; 대체 수단(CI/DI) 활용; 암호화 저장 필수.",
            "checks": ["pii", "ssn", "identification", "encrypt", "masking"],
            "status": "",
        },
        {
            "control": "3.1.4",
            "name": "민감정보·고유식별정보 제한 (Sensitive data, 2023.10 개정)",
            "desc": "민감정보 및 고유식별정보 처리 시 별도 동의·보호조치",
            "action": "별도 동의 획득; 암호화 필수; 접근 제한; 처리 현황 관리.",
            "checks": ["sensitive", "biometric", "health", "encrypt", "pii"],
            "status": "",
        },
        {
            "control": "3.2.1",
            "name": "개인정보 현황관리 (PII inventory)",
            "desc": "보유 개인정보 현황 관리 및 처리 목적별 분류",
            "action": "개인정보 처리대장; 보유량·목적·보유기간 관리; 주기적 현행화.",
            "checks": ["pii", "inventory", "data_classification", "personal_data"],
            "status": "",
        },
        {
            "control": "3.2.5",
            "name": "가명정보 처리 (Pseudonymization, 2023.10 신설)",
            "desc": "가명정보 처리 시 안전조치 및 재식별 금지",
            "action": "가명처리 기준 수립; 결합 전문기관 활용; 재식별 금지 조치.",
            "checks": ["pseudonymization", "anonymization", "masking", "de_identification"],
            "status": "",
        },
        {
            "control": "3.3.1",
            "name": "제3자 제공 (Third-party sharing, 2023.10 개정)",
            "desc": "개인정보 제3자 제공 시 동의 및 계약 관리",
            "action": "제공 동의 획득; 제공 항목·목적 명시; 제공 이력 관리.",
            "checks": ["third_party", "sharing", "consent", "data_transfer"],
            "status": "",
        },
        {
            "control": "3.3.4",
            "name": "국외이전 (Cross-border transfer, 2023.10 개정)",
            "desc": "개인정보 국외이전 시 정보주체 동의 및 보호조치",
            "action": "국외이전 동의; 수탁자 보호조치 계약; 이전 현황 공개.",
            "checks": ["cross_border", "transfer", "international", "gdpr"],
            "status": "",
        },
        {
            "control": "3.4.1",
            "name": "개인정보 파기 (PII deletion)",
            "desc": "보유기간 경과·목적 달성 시 지체 없이 파기",
            "action": "파기 절차; 복구 불가능한 방법(물리적 파괴, 데이터 삭제); 파기 기록 관리.",
            "checks": ["deletion", "retention", "destroy", "purge", "lifecycle"],
            "status": "",
        },
        {
            "control": "3.5.1",
            "name": "개인정보처리방침 공개 (Privacy policy disclosure)",
            "desc": "개인정보 처리방침 수립 및 공개",
            "action": "처리방침 웹사이트 게시; 필수 기재항목 확인; 변경 시 공지.",
            "checks": ["privacy_policy", "disclosure", "notice", "transparency"],
            "status": "",
        },
        {
            "control": "3.5.2",
            "name": "정보주체 권리보장 (Data subject rights, 2025.3.13 개정)",
            "desc": "열람·정정·삭제·처리정지·전송요구·자동화결정 거부 권리 보장",
            "action": "권리 행사 절차; 전송요구권(데이터이동권) 대응; 자동화 결정 거부·설명 요구권 대응; 10일 내 처리.",
            "checks": ["data_subject", "right_to_access", "right_to_delete", "portability", "automated_decision"],
            "status": "",
        },
        {
            "control": "3.5.3",
            "name": "이용내역 통지 (Usage notification)",
            "desc": "개인정보 이용내역을 정보주체에게 주기적 통지",
            "action": "연 1회 이상 이용내역 통지; 통지 내용(항목, 이용목적, 보유기간); 전자적 통지.",
            "checks": ["notification", "notice", "transparency", "reporting"],
            "status": "",
        },
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
            "checks": ["code_scanning", "sast", "injection", "vulnerability"],
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
            "checks": ["mfa", "authentication", "two_factor", "sso"],
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
            "desc": "Develop a continuous monitoring strategy and implement a continuous monitoring program",
            "action": "Deploy SIEM/monitoring tools; continuous vulnerability scanning; automated alerts.",
            "checks": ["monitoring", "alert", "scan", "vulnerability", "continuous"],
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
            "checks": ["mfa", "authentication", "two_factor", "sso", "identity"],
            "status": "",
        },
        {
            "control": "RA-5",
            "name": "Vulnerability monitoring and scanning",
            "desc": "Monitor and scan for vulnerabilities in the system and hosted applications",
            "action": "Run SAST/DAST scans; dependency vulnerability checks; prioritize by CVSS severity.",
            "checks": ["vulnerability", "code_scanning", "sast", "dependency", "cve"],
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
            "checks": ["firewall", "network", "segmentation", "port"],
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
            "checks": ["vulnerability", "scan", "patch", "cve", "remediation"],
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
            "checks": ["kubelet", "worker", "node", "tls_cert", "readonly"],
            "status": "",
        },
        {
            "control": "CIS-K8s-ArgoCD",
            "name": "ArgoCD RBAC and security configuration",
            "desc": "Verify ArgoCD RBAC policies, SSO integration, and project-level access restrictions",
            "action": "Enforce ArgoCD RBAC with least privilege; enable SSO; restrict project sources and destinations; disable anonymous access.",
            "checks": ["argocd", "argo", "gitops", "rbac", "sso", "project"],
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


def map_compliance(all_findings):
    """Map findings to compliance framework controls. Returns {framework: [ctrl_with_status]}."""
    result = {}
    for framework, controls in COMPLIANCE_CONTROL_MAP.items():
        mapped = []
        for ctrl in controls:
            matching = []
            for f in all_findings:
                text = f"{f['check']} {f['title']} {f['message']}".lower()
                keyword_match = any(kw in text for kw in ctrl["checks"])
                native_match = _match_prowler_compliance(f, framework)
                if keyword_match or native_match:
                    matching.append(f)
            status = "PASS" if len(matching) == 0 else "FAIL"
            mapped.append(
                {
                    **ctrl,
                    "status": status,
                    "count": len(matching),
                    "findings": matching[:5],
                }
            )
        result[framework] = mapped
    return result


def compliance_summary(compliance_map):
    """Return {framework: {pass, fail, total}} from map_compliance output."""
    summary = {}
    for fw, controls in compliance_map.items():
        p = sum(1 for c in controls if c["status"] == "PASS")
        f = sum(1 for c in controls if c["status"] == "FAIL")
        summary[fw] = {"pass": p, "fail": f, "total": p + f}
    return summary
