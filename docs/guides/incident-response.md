---
title: 보안 인시던트 대응 플레이북
description: NIST SP 800-61r2 기반 ClaudeSec 프로젝트의 보안 인시던트 대응 절차 및 실무 템플릿
tags: [incident-response, nist, iso27035, security-operations, playbook]
---

# 보안 인시던트 대응 플레이북

이 플레이북은 NIST SP 800-61r2(컴퓨터 보안 인시던트 처리 가이드)를 기반으로 ClaudeSec 환경에서 발생하는 보안 인시던트를 체계적으로 처리하기 위한 절차를 정의한다.

**참고 표준:**

- [NIST SP 800-61r2](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf) — Computer Security Incident Handling Guide
- [NIST CSF 2.0](https://www.nist.gov/cyberframework) — Cybersecurity Framework, Respond (RS) Function
- [ISO/IEC 27035](https://www.iso.org/standard/78973.html) — Information Security Incident Management
- [SANS Incident Handler's Handbook](https://www.sans.org/white-papers/33901/) — Incident Handling Step-by-Step

---

## 인시던트 대응 생애주기 개요

NIST SP 800-61r2는 인시던트 대응을 4단계 생애주기로 정의한다.

```
준비  →  탐지 및 분석  →  억제·근절·복구  →  사후 활동
(Preparation)  (Detection & Analysis)  (Containment, Eradication, Recovery)  (Post-Incident Activity)
```

---

## 1단계: 준비 (Preparation)

> NIST SP 800-61r2 §3.1 / ISO 27035-2 §6 / NIST CSF 2.0 RS.MI

준비 단계는 인시던트가 발생하기 전에 팀, 도구, 프로세스를 갖추는 활동이다. SANS Incident Handler's Handbook은 준비가 전체 대응 역량의 가장 큰 결정 요소임을 강조한다.

### 1.1 대응 팀 구성 (CSIRT)

| 역할 | 책임 | 비고 |
|------|------|------|
| IR 리더 | 대응 전체 조율, 경영진 보고 | 상시 연락 가능 |
| 보안 분석가 | 탐지, 분석, 포렌식 | 최소 2인 |
| 시스템 관리자 | 억제 및 복구 작업 | 인프라 권한 보유 |
| 법무/컴플라이언스 | 규제 신고 판단 | 개인정보 인시던트 필수 |
| 커뮤니케이션 담당 | 내부·외부 공지 | PR 인시던트 대비 |

### 1.2 비상 연락처 목록

```yaml
# templates/ir-contacts.yml 참고 형식
contacts:
  ir_lead:
    name: ""
    phone: ""
    email: ""
    backup: ""
  security_analyst:
    name: ""
    phone: ""
    email: ""
  system_admin:
    name: ""
    phone: ""
    email: ""
  legal:
    name: ""
    phone: ""
    email: ""
  external:
    cert_kr: "https://www.krcert.or.kr"        # KrCERT/CC 침해사고 신고: 118
    kisa_privacy: "https://privacy.kisa.or.kr"  # 개인정보 침해 신고: 118
    police_cyber: "https://ecrm.cyber.go.kr"    # 경찰청 사이버범죄 신고
```

### 1.3 사전 준비 도구 및 환경

```bash
# 포렌식 수집 도구 사전 설치 확인
which tcpdump wireshark volatility3 osquery

# ClaudeSec 스캐너 초기화
./scanner/claudesec scan --category all --severity critical,high

# 로그 수집 경로 확인
ls -la /var/log/audit/ /var/log/syslog /var/log/auth.log 2>/dev/null

# 베이스라인 스냅샷 생성 (정상 상태 기록)
./scanner/claudesec scan --output baseline-$(date +%Y%m%d).json
```

### 1.4 사전 준비 체크리스트

- [ ] CSIRT 역할 및 연락처 최신화 (분기 1회)
- [ ] IR 도구 키트 접근 권한 확인
- [ ] 로그 보존 정책 시행 중 (최소 90일, 규제 환경 1년)
- [ ] 인시던트 대응 계획(IRP) 경영진 승인
- [ ] 모의 훈련 실시 (반기 1회)
- [ ] 클라우드/SaaS 플랫폼별 로그 활성화 확인
- [ ] 백업 무결성 검증 완료

---

## 2단계: 탐지 및 분석 (Detection & Analysis)

> NIST SP 800-61r2 §3.2 / ISO 27035-2 §7 / NIST CSF 2.0 RS.AN

### 2.1 인시던트 탐지 경로

| 탐지 경로 | 예시 |
|-----------|------|
| 자동 알람 | SIEM 룰, ClaudeSec 스캐너, IDS/IPS |
| 사용자 신고 | 이상 동작, 피싱 의심 이메일 |
| 외부 신고 | KrCERT, 버그 바운티, 파트너사 |
| 로그 검토 | 주기적 보안 검토 중 발견 |

### 2.2 이상 징후 식별

아래 명령으로 초기 이상 징후를 빠르게 확인한다.

```bash
# 비정상 네트워크 연결 확인
ss -tulpn | grep ESTABLISHED
netstat -an | grep -E "ESTABLISHED|SYN_RECV" | sort | uniq -c | sort -rn | head -20

# 최근 로그인 이력 확인
last -n 50
lastb -n 20  # 실패한 로그인 시도

# 비정상 프로세스 확인
ps auxf | grep -v "\[" | sort -k3 -rn | head -20

# 최근 수정된 파일 확인 (최근 24시간)
find /etc /usr/bin /usr/sbin -mtime -1 -type f 2>/dev/null

# ClaudeSec 긴급 스캔 실행
./scanner/claudesec scan --severity critical --output ir-scan-$(date +%Y%m%dT%H%M%S).json
```

### 2.3 인시던트 심각도 분류표

NIST SP 800-61r2 §3.2.6 및 ISO 27035의 심각도 분류 기준을 적용한다.

| 등급 | 레이블 | 기준 | 대응 시간 | 에스컬레이션 |
|------|--------|------|-----------|-------------|
| P1 | Critical | 서비스 전체 중단, 고객 데이터 대규모 유출, 랜섬웨어 감염, 공급망 침해 | 즉시 (15분 이내) | CISO + 경영진 |
| P2 | High | 부분 서비스 중단, 제한적 데이터 유출, 권한 탈취 확인, 내부 시스템 침해 | 1시간 이내 | IR 리더 + 팀장 |
| P3 | Medium | 서비스 저하, 의심스러운 활동 탐지, 취약점 악용 시도 | 4시간 이내 | 보안 팀 |
| P4 | Low | 정책 위반, 스캔 탐지, 단순 피싱 시도 | 24시간 이내 | 담당 분석가 |

**심각도 결정 요소 (ISO 27035 §8.3):**

```
영향 범위 × 데이터 민감도 × 서비스 영향 × 확산 가능성
```

### 2.4 초기 분석 절차

```bash
# 1. 인시던트 타임라인 수집
journalctl --since "2 hours ago" --output json > /tmp/ir-journal-$(date +%Y%m%dT%H%M%S).json

# 2. 인증 로그 집중 분석
grep -E "(Failed|Accepted|Invalid)" /var/log/auth.log | \
  awk '{print $1,$2,$3,$9,$11}' | sort | uniq -c | sort -rn

# 3. 의심 IP 조회
# ABUSEIPDB, VirusTotal, Shodan 등 활용
curl -sG "https://api.abuseipdb.com/api/v2/check" \
  --data-urlencode "ipAddress=<의심_IP>" \
  -H "Key: ${ABUSEIPDB_API_KEY}" \
  -H "Accept: application/json" | jq '.data.abuseConfidenceScore'

# 4. 네트워크 트래픽 덤프 (필요 시)
tcpdump -i eth0 -w /tmp/capture-$(date +%Y%m%dT%H%M%S).pcap -G 300 -W 1
```

---

## 3단계: 억제, 근절, 복구 (Containment, Eradication, Recovery)

> NIST SP 800-61r2 §3.3 / ISO 27035-2 §8 / NIST CSF 2.0 RS.MI, RC.RP

### 3.1 억제 (Containment)

억제 전략은 단기(즉각 대응)와 장기(완전 복구까지 유지)로 나뉜다 (NIST SP 800-61r2 §3.3.1).

**단기 억제:**

```bash
# 의심 호스트 네트워크 격리 (iptables)
SUSPECT_IP="192.168.1.100"
iptables -I INPUT -s "${SUSPECT_IP}" -j DROP
iptables -I OUTPUT -d "${SUSPECT_IP}" -j DROP

# 의심 계정 즉시 잠금
usermod -L <의심_계정>
# AWS IAM 계정 비활성화
aws iam update-login-profile --user-name <계정명> --password-reset-required
aws iam deactivate-mfa-device --user-name <계정명> --serial-number <MFA_ARN>

# 의심 세션 강제 종료
pkill -u <의심_계정>
who | grep <의심_계정>
```

**증거 보전 (포렌식 복사본 생성):**

```bash
# 메모리 덤프 (LiME 또는 avml 사용)
sudo avml /tmp/memory-$(date +%Y%m%dT%H%M%S).lime

# 디스크 이미지 생성 (쓰기 금지 마운트)
dd if=/dev/sda bs=4M | gzip > /mnt/ir-storage/disk-$(date +%Y%m%dT%H%M%S).img.gz

# 해시값 기록 (증거 무결성)
sha256sum /tmp/memory-*.lime /mnt/ir-storage/disk-*.img.gz > /mnt/ir-storage/evidence-hashes.txt
```

### 3.2 근절 (Eradication)

```bash
# 악성 파일 탐색 및 제거
find / -name "*.sh" -newer /tmp/ir-reference -perm /111 2>/dev/null | \
  xargs -I{} sha256sum {} | tee /tmp/suspicious-files.txt

# 크론잡 검토
crontab -l
cat /etc/cron* /var/spool/cron/crontabs/* 2>/dev/null

# 루트킷 스캔
rkhunter --check --skip-keypress
chkrootkit

# 패키지 무결성 검증 (RPM 기반)
rpm -Va --nosize --nomd5 2>/dev/null | grep "^..5"
# 패키지 무결성 검증 (Debian 기반)
dpkg --verify 2>/dev/null | grep -v "^$"

# ClaudeSec 전체 재스캔
./scanner/claudesec scan --category all --severity critical,high \
  --output post-eradication-scan-$(date +%Y%m%dT%H%M%S).json
```

### 3.3 복구 (Recovery)

```bash
# 백업에서 복원 전 무결성 확인
sha256sum -c backup-checksums.txt

# 서비스 복원 순서 (의존성 순)
systemctl start postgresql
systemctl start redis
systemctl start application

# 복원 후 헬스체크
./scripts/health-check.sh --full

# 복원 후 보안 스캔 재실행
./scanner/claudesec scan --category all \
  --output post-recovery-scan-$(date +%Y%m%dT%H%M%S).json

# 모니터링 강화 설정 (72시간 집중 관찰)
# SIEM 알람 임계값 하향, 로그 샘플링 증가
```

**복구 기준 (NIST SP 800-61r2 §3.3.4):**

- 시스템 정상 동작 확인
- 보안 스캔 결과 이전 베이스라인 수준 이하
- 감염 경로 차단 확인
- 모니터링 강화 유지 중

---

## 4단계: 사후 활동 (Post-Incident Activity)

> NIST SP 800-61r2 §3.4 / ISO 27035-2 §9 / NIST CSF 2.0 RS.IM

### 4.1 사후 검토 회의 (Post-Incident Review)

인시던트 종료 후 2주 이내에 실시한다 (SANS Incident Handler's Handbook §7).

**회의 의제:**

1. 인시던트 타임라인 재구성
2. 대응 과정의 잘된 점과 개선점
3. 탐지 격차 분석 (MTTD, MTTR 측정)
4. 재발 방지 조치 도출
5. 플레이북 업데이트 사항 확인

### 4.2 인시던트 보고서 필수 항목

```markdown
# 인시던트 보고서

## 기본 정보
- 인시던트 ID: IR-YYYY-NNNN
- 심각도: P1 / P2 / P3 / P4
- 탐지 일시:
- 종료 일시:
- MTTD (평균 탐지 시간):
- MTTR (평균 복구 시간):

## 인시던트 요약
<!-- 2~3문장으로 간결하게 -->

## 타임라인
| 일시 | 이벤트 | 조치 |
|------|--------|------|
|      |        |      |

## 근본 원인 분석
<!-- 5 Whys 또는 피쉬본 다이어그램 활용 -->

## 영향 범위
- 영향받은 시스템:
- 영향받은 사용자 수:
- 데이터 유출 여부:

## 대응 조치 요약

## 재발 방지 조치
| 조치 항목 | 담당자 | 완료 기한 | 상태 |
|-----------|--------|-----------|------|
|           |        |           |      |

## 교훈 (Lessons Learned)
```

### 4.3 개선 조치 추적

```bash
# ClaudeSec 스캐너에 신규 탐지 룰 추가 확인
./scanner/claudesec scan --list-rules | grep -i "새로운_패턴"

# 개선 사항 GitHub 이슈 등록
gh issue create \
  --title "IR-YYYY-NNNN: 재발 방지 조치 - <항목명>" \
  --label "security,incident-response" \
  --body "인시던트 보고서 기반 개선 조치 추적"

# 베이스라인 업데이트
./scanner/claudesec scan --output baseline-$(date +%Y%m%d)-post-ir.json
```

---

## 실무 템플릿

### 에스컬레이션 매트릭스

| 상황 | 즉시 연락 | 30분 내 연락 | 다음 근무일 |
|------|-----------|-------------|------------|
| P1 — 서비스 전체 중단 | CISO, CTO, CEO | 법무, 홍보 | 전 직원 공지 |
| P1 — 개인정보 대규모 유출 | CISO, CPO, 법무 | KISA (118), 경영진 | 개인정보보호위원회 신고 (72시간 이내) |
| P2 — 권한 탈취 확인 | IR 리더, 시스템 관리자 | CISO | 팀장 |
| P2 — 부분 데이터 유출 | IR 리더, 법무 | CISO | 영향받은 고객 통보 검토 |
| P3 — 의심 활동 탐지 | 보안 분석가 | IR 리더 | — |
| P4 — 정책 위반 | 담당 분석가 | — | 팀장 |

**개인정보 유출 규제 신고 기한 (법적 의무):**

- 개인정보보호법 제34조: 72시간 이내 개인정보보호위원회 신고
- GDPR 적용 대상: 72시간 이내 감독기관 신고

### 인시던트 대응 체크리스트

```markdown
## Phase 1: 탐지 및 초기 대응 (0~30분)
- [ ] 인시던트 접수 및 기록 시작 (IR-YYYY-NNNN 채번)
- [ ] 초기 심각도 분류 (P1~P4)
- [ ] IR 리더에게 알림 발송
- [ ] 에스컬레이션 매트릭스에 따라 관계자 통보
- [ ] 인시던트 대응 채널 개설 (Slack #ir-YYYY-NNNN)
- [ ] 초기 스크린샷 및 로그 보전 시작

## Phase 2: 억제 (30분~2시간)
- [ ] 영향받은 시스템 식별 및 격리
- [ ] 의심 계정 비활성화
- [ ] 포렌식 증거 보전 (메모리, 디스크 이미지)
- [ ] 외부 노출 경로 차단 (방화벽, ACL)
- [ ] 백업 무결성 확인

## Phase 3: 분석 (병행 진행)
- [ ] 공격 벡터 파악
- [ ] 영향 범위 확정
- [ ] IOC (침해 지표) 목록 작성
- [ ] 타임라인 재구성

## Phase 4: 근절 및 복구
- [ ] 악성 파일/계정/설정 제거
- [ ] 취약점 패치 적용
- [ ] 패스워드/시크릿 전체 교체
- [ ] 정상 시스템에서 복원
- [ ] 복원 후 보안 스캔 실행
- [ ] 서비스 정상화 확인

## Phase 5: 사후 활동
- [ ] 인시던트 보고서 초안 작성 (24시간 이내)
- [ ] 사후 검토 회의 일정 잡기 (2주 이내)
- [ ] 재발 방지 조치 GitHub 이슈 등록
- [ ] 플레이북 업데이트
- [ ] 법적 신고 완료 확인 (해당 시)
- [ ] 최종 보고서 경영진 보고
```

### 침해 지표(IOC) 수집 템플릿

```yaml
# ir-ioc-YYYY-NNNN.yml
incident_id: IR-YYYY-NNNN
collected_at: ""
collected_by: ""

network:
  malicious_ips: []
  malicious_domains: []
  c2_urls: []

file:
  malicious_hashes_sha256: []
  malicious_filenames: []
  malicious_paths: []

account:
  compromised_usernames: []
  suspicious_api_keys: []

behavior:
  attack_patterns: []   # MITRE ATT&CK TTP ID 목록
  persistence_mechanisms: []
```

---

## 참고 자료

| 자료 | 링크 |
|------|------|
| NIST SP 800-61r2 | <https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf> |
| NIST CSF 2.0 Respond Function | <https://www.nist.gov/cyberframework> |
| ISO/IEC 27035 | <https://www.iso.org/standard/78973.html> |
| SANS Incident Handler's Handbook | <https://www.sans.org/white-papers/33901/> |
| MITRE ATT&CK | <https://attack.mitre.org> |
| KrCERT/CC 침해사고 신고 | <https://www.krcert.or.kr> |
| 개인정보보호위원회 | <https://www.pipc.go.kr> |
| OWASP Incident Response | <https://owasp.org/www-community/Incident_Response> |

## 관련 문서

- [컴플라이언스 매핑](./compliance-mapping.md)
- [워크플로우 컴포넌트](./workflow-components.md)
- [ClaudeSec 시작하기](./getting-started.md)
