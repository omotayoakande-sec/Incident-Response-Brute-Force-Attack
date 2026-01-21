# Incident-Response-Brute-Force-Attack
Hands-on incident response case study investigating brute-force login attempts using Microsoft Sentinel and Microsoft Defender for Endpoint, aligned to the NIST 800-61 incident response lifecycle.
# 🛡️ Incident Response — Brute Force Login Attempts (Microsoft Sentinel + MDE)

📌 **Target Role:** SOC Analyst (Mid-level)  
🧱 **Framework:** NIST 800-61 (Preparation → Detection/Analysis → Containment/Eradication/Recovery → Post-Incident)

📎 **Diagram attached:** `diagrams/sentinel-mde-bruteforce-flow.png`  
(Shows: Internet → Endpoint(s) → MDE telemetry → Sentinel analytics rule → Incident → Response actions)



---

## 1) Executive Summary
**What happened:**  
A detection rule identified repeated failed login attempts consistent with brute-force behavior.

**Impact:**  
- Confirmed: [True Positive / Benign / Simulated]
- Successful logons observed: [Yes/No]
- Affected assets: [count + names]
- Attacker indicators: [RemoteIP list / geo / ASN]

**Outcome:**  
Actions taken included endpoint containment and control hardening (e.g., NSG restrictions, policy changes).

---

## 2) Environment
- SIEM: Microsoft Sentinel
- EDR: Microsoft Defender for Endpoint (MDE)
- Log sources: DeviceLogonEvents
- Network controls: NSG / Firewall rules

---

## 3) Detection Rule (KQL)
See: `queries/02_detection.kql`

**Analytics Rule Settings**
- Severity: [Low/Med/High]
- Schedule: query every [x] hours, lookback [x] hours
- Entity mappings: RemoteIP, DeviceName
- MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)

---

## 4) Investigation Timeline (What I did and why)
### Step A — Validate the alert
- Why: Ensure it’s not noisy authentication failures.

### Step B — Identify all attacker IPs and attempt volume
- Why: Expand scope beyond the alert’s initial entities.

### Step C — Identify additional impacted devices
- Why: Determine lateral targeting across endpoints.

### Step D — Check for successful logons
- Why: Confirm compromise vs attempted intrusion.

Evidence: `evidence/screenshots/` and `evidence/exported-logs/`

---

## 5) Findings (What I discovered)
- Total attacker IPs: [#]
- Max attempts from a single IP: [#]
- Additional devices impacted: [list]
- Successful logons: [Yes/No]
- Notes on patterns: [spray vs brute-force, time windows, targeted accounts]

---

## 6) Containment, Eradication & Recovery
### Containment
- Isolated devices in MDE: [list]
- Blocked/limited traffic: [controls]

### Eradication
- Persistence found: [Yes/No]
- Malware found: [Yes/No]
- Actions: [AV scan, investigation package, cleanup]

### Recovery
- Re-enabled access after validation: [criteria]
- Monitoring improvements: [rule tuning, watchlists]

---

## 7) Recommendations
- Account lockout/MFA policies
- Geo-blocking / throttling
- NSG tightening / exposure review
- Expand monitoring to all internet-exposed assets

---

## 8) Reflection (Learning Outcomes)
- What I learned about KQL, scoping, and IR decision-making
- What I would do differently next time


// Brute-force detection (failed logons threshold)
DeviceLogonEvents
| where ActionType == "LogonFailed"
| summarize FailedCount = count() by DeviceName, RemoteIP
| where FailedCount >= 5
| order by FailedCount desc


// Expand attacker IP list from initially affected devices
let SuspectedDevices = dynamic(["<device-1>", "<device-2>"]);
let attackerIPs =
    DeviceLogonEvents
    | where DeviceName has_any (SuspectedDevices)
    | where ActionType == "LogonFailed"
    | summarize by RemoteIP;

DeviceLogonEvents
| where RemoteIP in (attackerIPs)
| summarize AttemptCount=count() by DeviceName, RemoteIP, ActionType
| order by AttemptCount desc


let SuspectedDevices = dynamic(["<device-1>", "<device-2>"]);
let attackerIPs =
    DeviceLogonEvents
    | where DeviceName has_any (SuspectedDevices)
    | where ActionType == "LogonFailed"
    | summarize by RemoteIP;

DeviceLogonEvents
| where RemoteIP in (attackerIPs)
| summarize Events=count() by ActionType
