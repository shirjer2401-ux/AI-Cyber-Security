# Lab a.1

## 4. Setup, clean baseline, and verification:

```bash
PS C:\Users\97254\HIT-ai-cybersecurity-labs\labs\lab1a-mitre-soc> docker version
Client:
 Version:           29.9.2
 API version:       1.56
 Go version:        go1.26.10
 Git commit:        a82e528
 Built:             Tue Oct 20 19:44:07 2026
 OS/Arch:           windows/amd64
 Context:           desktop-linux

Server: Docker Desktop 4.97.0 (244584)
 Engine:
  Version:          29.9.2
  API version:      1.56 (minimum version 1.40)
  Go version:       go1.26.10
  Git commit:       0367cbe
  Built:            Tue Oct 20 18:45:02 2026
  OS/Arch:          linux/amd64
  Experimental:     false
```

```bash
PS C:\Users\97254\HIT-ai-cybersecurity-labs\labs\lab1a-mitre-soc> docker compose ps
NAME                 IMAGE                     COMMAND                  SERVICE     CREATED          STATUS          PORTS
lab1a-dashboard      lab1a-mitre-soc-dashboard "python /app/dashboa…"   dashboard   13 seconds ago   Up 9 seconds    0.0.0.0:8000->8000/tcp, [::]:8000->8000/tcp
mitre-log-detector   lab1a-mitre-soc-detector  "python /app/detecto…"   detector    15 seconds ago   Up 9 seconds    
PS C:\Users\97254\HIT-ai-cybersecurity-labs\labs\lab1a-mitre-soc>
```

### Lab 1a SOC Dashboard
Cyclic detection with periodic MITRE ATT&CK STIX refresh  
**Last detector scan:** 2026-11-01T14:28:35.958552+00:00  
**STIX status:** Loaded  
**STIX source:** enterprise-attack-mini.json  
**Techniques loaded:** 2  
**STIX loaded at:** 2026-11-01T14:16:38.387423+00:00  

* **Total findings:** 2
* **High severity:** 1
* **Medium severity:** 1

#### Detection Findings

| # | Activity | Source IP | MITRE ATT&CK | Tactic | Severity | STIX lookup | Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | Possible network service discovery | 172.18.0.7 | T1046 - Network Service Discovery | Discovery | Medium | Resolved from STIX | 2026-07-11T09:04:20 INFO Network scan detected from 172.18.0.7 against ports 22,80,443,3306 |
| 2 | Possible brute-force login attempt | 172.18.0.5 | T1110 - Brute Force | Credential Access | High | Resolved from STIX | 3 failed password events were detected from 172.18.0.5. |

With the clean baseline log, the dashboard initially reported a total finding count of 2[cite: 6]:
1. One High-severity finding for MITRE technique T1110 (Brute Force) from source IP 172.18.0.5[cite: 6].
2. One Medium-severity finding for MITRE technique T1046 (Network Service Discovery) from source IP 172.18.0.7[cite: 6].

---

## 5. Activity A:

| evidence | rule | technique | tactic | uncertainty |
| :--- | :--- | :--- | :--- | :--- |
| 3 failed password events were detected from 172.18.0.5. | At least 3 failed password events from the same source IP | T1110 (Brute Force) | Credential Access | The rule counts events without a time window and does not prove successful access or confirmed adversary intent. Failed password attempts may result from a user typo or a misconfigured internal script. |
| INFO Network scan detected from 172.18.0.7 against ports 22,80,443,3306 | The log contains 'network scan detected'. | T1046 (Network Service Discovery) | Discovery | The detector relies solely on explicit string matching within log entries rather than independent packet-level traffic flow inference. |

---

## 6. Activity B:

### Identification in detector.py:
* **FAILED_PASSWORD_THRESHOLD:** Set to 3. Defines the minimum number of failed attempts required from a single IP before raising a T1110 alert[cite: 7]. 
* **SCAN_INTERVAL_SECONDS:** Set to 5 seconds. Controls how often the detection loop re-evaluates security.log[cite: 7]. 
* **Candidate Technique Assignment:** detector.py iterates over aggregated IP failure counts (count >= 3 → assigns "T1110") and string-matches "network scan detected" (→ assigns "T1046")[cite: 7]. 

### Explanation:
* **Lack of Context & Time Windows:** Rule T1110 counts total failures without a time window or context, meaning legitimate password typos or a misconfigured automation script can easily cross the threshold[cite: 7]. 
* **No Proof of Success:** A match for T1110 indicates authentication failure, not a breach[cite: 7]. 
* **Static String Matching:** Rule T1046 triggers on log text rather than verified network packet inspection[cite: 7]. 
* **Candidate Finding vs. Incident:** Deterministic rules only generate candidate findings (alerts) for SOC analysis; human investigation is required to establish true malicious intent[cite: 7].

---

## 7. Activity C:

* **C1 — Below the threshold:**  
  One failed password log entry for source IP 172.18.0.5 was deleted from security.log, leaving only two failure records[cite: 8]. As predicted, the total finding count on the dashboard dropped from 2 to 1 because the T1110 Brute Force detection rule was no longer triggered, while the T1046 Network Service Discovery finding remained active[cite: 8]. This occurs because detector.py strictly enforces a hardcoded threshold of 3 failures (FAILED_PASSWORD_THRESHOLD = 3); since only 2 events were recorded for that IP, the rule condition evaluated to false and the candidate finding was cleared[cite: 8].

* **C2 — Three failures from three different IP addresses:**  
  The three failed password log lines were modified to originate from three distinct source IP addresses (172.18.0.5, 172.18.0.6, and 172.18.0.8)[cite: 8]. As predicted, no T1110 Brute Force finding was generated, and the dashboard displayed only 1 active finding (T1046)[cite: 8]. This occurs because detector.py groups authentication failures strictly by individual source IP; since each IP accumulated only a single failed attempt, none of the individual addresses crossed the required threshold of 3 failures[cite: 8].

* **C3 — Threshold crossing from one new IP:**  
  Three synthetic failed-password records originating from a new source IP address (192.0.2.55) were appended to security.log[cite: 8]. As predicted, after the next scan cycle, a new High-severity T1110 (Brute Force) finding was generated specifically for 192.0.2.55, increasing the total finding count[cite: 8]. This demonstrates that detector.py dynamically processes newly added log entries and triggers candidate findings as soon as any individual source IP reaches or exceeds the threshold of 3 authentication failures[cite: 8].

* **C4 — Add a second network-scan record:**  
  A synthetic network scan entry originating from source IP 192.0.2.77 was appended to security.log[cite: 8]. As predicted, an additional Medium-severity T1046 (Network Service Discovery) finding appeared on the dashboard, bringing the total finding count to 3[cite: 8]. This result highlights that rule T1046 relies strictly on naive string matching for the text phrase "Network scan detected" across individual log entries rather than inferring scanning behavior from raw network connection flows[cite: 8].

---

## 8. Activity D — MITRE knowledge and simulator:

Upon running the simulation profile, the dashboard's total finding count dynamically increased to 8 (2 High severity, 6 Medium severity)[cite: 8]. New active source IPs injected by the simulator included 172.18.0.33, 172.18.0.31, 172.18.0.32, and 172.18.0.23[cite: 8]. 
- T1110 (Brute Force) findings were triggered by IPs crossing the 3-failure threshold, specifically 192.0.2.55 (3 failures) and 172.18.0.23 (5 failures)[cite: 8].
- T1046 (Network Service Discovery) findings were triggered by explicit "Network scan detected" log strings from IPs 172.18.0.7, 192.0.2.77, 172.18.0.33, 172.18.0.31, and 172.18.0.32 (which generated two separate scan records)[cite: 8].

Finding counts did not remain stable but grew over time as security.log continuously expanded[cite: 9]. This activity is inherently less reproducible than controlled experiments C1–C4 because event injection occurs asynchronously in real time relative to detector.py's fixed 5-second polling loop, making finding counts highly dependent on exact timing[cite: 9].

---

## SOC Narrative:

* **Observed Facts:** Analysis of the security log revealed two candidate findings generated by detector.py[cite: 9]. First, three consecutive failed login attempts were recorded from source IP 172.18.0.5, crossing the detection threshold and triggering a High-severity T1110 (Brute Force) alert[cite: 9]. Second, an explicit log entry containing "Network scan detected" from source IP 172.18.0.7 triggered a Medium-severity T1046 (Network Service Discovery) alert[cite: 9].

* **Analyst Interpretation:** These alerts indicate suspicious activity that may suggest reconnaissance or credential-guessing[cite: 9]. Crucially, authentication failures alone do not confirm successful unauthorized access or system compromise[cite: 9]. The observed failures could also stem from user typos or misconfigured scripts[cite: 9]. Therefore, these findings represent preliminary candidate alerts rather than confirmed security incidents, requiring further contextual investigation before escalation[cite: 9].
