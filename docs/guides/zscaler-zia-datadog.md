---
title: Zscaler ZIA NSS → Datadog Log Streaming
description: Configure Zscaler NSS to stream security logs to Datadog for SIEM visibility
tags: [zscaler, datadog, nss, siem, logging]
---

# Zscaler ZIA NSS → Datadog Log Streaming

Resolves **SAAS-ZIA-006 HIGH**: "Zscaler NSS log streaming not configured"

## Overview

Zscaler NSS (Nanolog Streaming Service) streams ZIA security logs to external SIEMs.
Without NSS, security events (web blocks, malware, DLP) are only visible in the ZIA portal
with limited retention.

## Architecture

```
ZIA Cloud ──NSS──► NSS VM (on-prem/cloud) ──syslog/HTTPS──► Datadog Log Intake
                                                              ↓
                                                         Datadog SIEM
                                                         (dashboards, alerts)
```

## Option A: NSS + Datadog Agent (Recommended)

### 1. Deploy NSS VM

- Download NSS VM image from ZIA Admin Portal > Administration > Nanolog Streaming Service
- Deploy in your network (VMware, Hyper-V, or cloud)
- Register NSS VM with ZIA cloud

### 2. Configure NSS Feed in ZIA

1. ZIA Admin > Administration > Nanolog Streaming Service > NSS Feeds
2. Add NSS Feed:
   - **Feed Name**: `datadog-web-logs`
   - **NSS Type**: NSS for Web
   - **Log Type**: Web Log
   - **Feed Output Type**: Custom
   - **Custom format** (JSON for Datadog):

```
\{"sourcetype":"zscalernss-web","event":\{"datetime":"%s{time}","user":"%s{elogin}","department":"%s{edepartment}","action":"%s{action}","urlclass":"%s{urlclass}","url":"%s{eurl}","hostname":"%s{ehost}","status":"%s{statuscode}","reqsize":"%d{reqsize}","respsize":"%d{respsize}","serverip":"%s{sip}","dlpeng":"%s{dlpeng}","dlpdict":"%s{dlpdict}","location":"%s{elocation}","threatname":"%s{threatname}"\}\}
```

1. **Status**: Enabled
1. Save and activate

### 3. Configure Datadog Agent on NSS VM

```bash
# Install Datadog Agent
DD_API_KEY=<your-dd-api-key> DD_SITE=datadoghq.com \
  bash -c "$(curl -L https://install.datadoghq.com/scripts/install_script_agent7.sh)"

# Configure syslog listener
cat > /etc/datadog-agent/conf.d/tcp_log.d/conf.yaml <<'YAML'
logs:
  - type: tcp
    port: 514
    service: zscaler-zia
    source: zscaler
    tags:
      - "env:production"
      - "team:security"
YAML

# Restart agent
sudo systemctl restart datadog-agent
```

### 4. Verify in Datadog

```
Datadog > Logs > source:zscaler
```

## Option B: ZIA API Log Export (No NSS VM)

If NSS VM deployment is not feasible, use the ZIA API to pull logs periodically:

```bash
# In ~/.claudesec.env
ZSCALER_API_KEY=<your-api-key>
ZSCALER_API_ADMIN=<admin-email>
ZSCALER_API_PASSWORD=<password>
ZSCALER_BASE_URL=https://zsapi.zscaler.net

# Pull and forward to Datadog
DD_API_KEY=<dd-api-key> DD_SITE=datadoghq.com \
  python3 scripts/zscaler-log-forward.py
```

> **Note**: API-based log export has rate limits and is best for low-volume environments.
> NSS is the recommended approach for production.

## Verification

After configuration, run the ClaudeSec scanner:

```bash
./scanner/claudesec scan -c saas
```

**SAAS-ZIA-006** should change from FAIL to PASS once NSS feeds are detected.

## References

- [Zscaler NSS Deployment Guide](https://help.zscaler.com/zia/about-nanolog-streaming-service)
- [Datadog Zscaler Integration](https://docs.datadoghq.com/integrations/zscaler_internet_access/)
- [ZIA API Documentation](https://help.zscaler.com/zia/api)
