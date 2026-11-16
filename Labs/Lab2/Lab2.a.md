# Laboratory 2a: Morpheus Lite — Human–AI Decision-Making in an AI-Augmented SOC

---

## 3. Select and Synchronize a Case

| Case field | Your observation |
| :--- | :--- |
| **`alert_id`** | `alert-0-214` |
| **`correlation_id`** | `50608476-4a9e-4956-9845-c7c37b21445c` |
| **Scenario / event type** | `login` |
| **Risk score / severity** | `80` / Medium risk (Fingerprint Z-score: `4.0319`) |
| **User / host** | `alice` / `web-01` |
| **Inference provider** | `ollama` (`llama3`) |
| **RAI approval required** | `false` (No) |
| **Current human decision** | `pending` |

---

## 4. Trace the Case Through Redpanda

| Topic | What to locate / record |
| :--- | :--- |
| **`raw.logs`** | **Offset `214`, Partition `0`** (`16.11.2026, 14:20:33`): Located via `correlation_id: 50608476-4a9e-4956-9845-c7c37b21445c` (`event_id: d4cb88ac-1144-479f-8958-e04f3977252a`; no `alert_id` yet). Original telemetry: `user: alice`, `host: web-01`, `event_type: login`, `country: US`, elevated `failed_logins` & `bytes_out`. |
| **`morpheus.alerts`** | **Offset `30`, Partition `0`** (`16.11.2026, 14:20:33`): `alert_id: alert-0-214`, `correlation_id: 50608476-4a9e-4956-9845-c7c37b21445c`, `risk_score: 80` (Medium risk), `fingerprint_z: 4.0319`, Isolation Forest prediction `1`. |
| **`agent.investigations`** | **Offset `11`, Partition `0`** (`16.11.2026, 14:46:58`): Investigation findings for `alert-0-214` (`correlation_id: 50608476-4a9e-4956-9845-c7c37b21445c`) linking user fingerprint deviation (`z=4.0319`) on `web-01` (`alice`) to MITRE ATT&CK `TA0006` (Credential Access), `TA0010` (Exfiltration), and `TA0004` (Privilege Escalation). |
| **`agent.explanations`** | **Offset `11`, Partition `0`** (`16.11.2026, 14:46:58`): `agent: "ollama XAI Agent"`, `provider: ollama (llama3)`, `alert_id: alert-0-214`. Plain-language XAI analysis recommending `increase_monitoring`. |
| **`audit.rai`** | Indexed by `correlation_id` (`50608476-4a9e-4956-9845-c7c37b21445c`) rather than `alert_id`: `agent: "RAI Policy Agent"`, `allowed: true`, `recommended_action: "increase_monitoring"`, `human_approval_required: false`, `policy_note: "Medium risk. Automated destructive actions are blocked."`, `policy_evidence_count: 1`. |
| **`agent.meta_ai`** | Indexed by `correlation_id` (`50608476-4a9e-4956-9845-c7c37b21445c`) rather than `alert_id`: `agent: "Meta-AI Supervisory Agent"`, `approved: true`, `disposition: "approve"`, `issues: []`, `questions_or_requests: []`, `uncertainty: 0.2`, `reflection: "Decision is sufficiently supported for governed continuation."` |
| **`human.decisions`** | **Offset `0`, Partition `0`**: `alert_id: alert-0-214`, `correlation_id: 50608476-4a9e-4956-9845-c7c37b21445c`, `decision: "approve"`, `recommended_action: "increase_monitoring"`, recorded with full evidence-backed justification. |

**Question:** Why is `alert_id` useful for selecting one dashboard case, while `correlation_id` may be useful for tracing related backend events?  
**Answer:** `alert_id` (`alert-0-214`) uniquely identifies a single generated security alert so the analyst can select, synchronize, and track one specific case across the dashboard views (*All Cases*, *Active Alert*, *Human Decision Queue*, and *Case Details*). In contrast, `correlation_id` (`50608476-4a9e-4956-9845-c7c37b21445c`) is a shared trace UUID propagated throughout the entire backend pipeline—from raw ingestion (`raw.logs`, before any `alert_id` is assigned) through detection and multi-agent audit topics (`audit.rai`, `agent.meta_ai`)—allowing end-to-end event tracing across asynchronous Kafka topics.

### Evidence Verification Record
* **Original telemetry:** Checked; Supported
* **Detector alert:** Checked; Supported
* **XAI claim:** Checked; Underlying metrics supported, analytical interpretations uncertain.
* **RAI rule:** Checked; Supported
* **Meta-AI concern:** Checked; Supported
* **Independent corroboration (if available):** Unavailable

---

## 5. Analyze Evidence Before Deciding

### 5.1 Detection Evidence

| Evidence item / source | Observed fact | Supports recommendation? | Independently checked? |
| :--- | :--- | :--- | :--- |
| **Original telemetry** | `raw.logs` (Offset `214`, `14:20:33`): `login` event by `user: alice` on `host: web-01` from `country: US`, showing elevated `failed_logins` and high outbound data volume (`bytes_out`). | **Yes** | **Yes** (verified in Redpanda Console `raw.logs` via `correlation_id: 50608476-4a9e-4956-9845-c7c37b21445c`) |
| **Detector alert** | `morpheus.alerts` (Offset `30`): `alert-0-214` triggered with `risk_score: 80` (Medium risk), `fingerprint_z: 4.0319` (significant behavioral deviation), and Isolation Forest anomaly prediction `1`. | **Yes** | **Yes** (verified in Redpanda Console `morpheus.alerts` and Dashboard Evidence) |
| **Additional source (if available)** | No external/out-of-band log source (e.g., separate firewall, IdP, or EDR logs) is available in this baseline lab environment beyond the Redpanda pipeline. | **Uncertain** | **No** (Unavailable in lab setup) |

* **Q1 Evidence completeness:** Good.
* **Q2 Confidence that evidence supports the alert (before XAI):** High.
* **Q3 Strongest evidence and missing evidence:**
  * **Strongest evidence:** The user-specific behavioral fingerprint deviation (`z-score = 4.0319`), together with the elevated `failed_logins` and `bytes_out` values for `alice` on `web-01` in `raw.logs`, corroborated by the Isolation Forest anomaly prediction (`1`).
  * **Missing evidence:** Independent external verification sources (such as IdP/SSO authentication logs or firewall logs) to verify whether the login from `US` was legitimate user activity or unauthorized access.

### 5.2 XAI: Evaluate Explanation Quality
* **Provider:** `ollama` (`llama3`)
* **Q4 Explanation understandable:** Strongly agree.
* **Q5 Explanation connects evidence to recommendation:** Agree.
* **Q6 Did XAI change your understanding?** **Yes** — The raw logs already showed unusual activity, including a fingerprint deviation and failed logins. The XAI explanation helped me understand how this activity could be related to MITRE ATT&CK tactics. It also explained why increased monitoring was recommended instead of immediately blocking the account.
* **Q7 Confidence after XAI:** High.
* **Q8 Did XAI introduce information not obvious in the original evidence?** **Yes** — The XAI agent mapped the raw anomaly features (`failed_logins`, `bytes_out`, `fingerprint_z = 4.0319`) to specific MITRE ATT&CK tactics (`TA0006`, `TA0010`, `TA0004`) and added an interpretive note that a `US` country label indicates user location. Verified against `raw.logs` (Offset `214`), `morpheus.alerts` (Offset `30`), and `agent.investigations` (Offset `11`): the underlying metrics (`z=4.0319`, `web-01`, `alice`, `US`, `failed_logins`, `bytes_out`) are accurate, while the MITRE tactics and geographic interpretation are analytical inferences rather than explicit fields in the raw log.
* **Q9 Change in trust:** Increased.
* **Q10 Did you independently verify the explanation?** Partially.

### 5.3 RAI: Evaluate Policy and Authorization
* **Q11 RAI assessment understandable:** Strongly agree.
* **Q12 RAI clarified risks of the recommendation:** Agree.
* **Q13 RAI added useful information beyond detector output:** Strongly agree.
* **Q14 Did RAI influence your thinking?** **Yes** — Seeing a `risk_score` of `80` initially made the alert seem serious. However, the RAI assessment clarified that it falls within the medium-risk range (`60–84`), where automated destructive actions, such as host isolation or account lockout, are blocked. Instead, `increase_monitoring` is recommended.
* **Policy constraint / approval requirement:** `allowed: true`, `recommended_action: "increase_monitoring"`, `human_approval_required: false` (since `risk_score = 80` is below the high-risk threshold of `85`, where isolation with mandatory human approval would apply). Policy constraint: `"Medium risk. Automated destructive actions are blocked."` (`policy_evidence_count: 1`). Note that `allowed: true` permits only this governed monitoring recommendation and does not authorize autonomous destructive remediation.

### 5.4 Meta-AI: Assess the AI Investigation
* **Q15 Meta-AI improved understanding:** Neutral.
* **Q16 Meta-AI identified useful limitations:** Disagree.
* **Q17 Meta-AI encouraged evidence verification:** Neutral.
* **Q18 Overall Meta-AI usefulness:** Slightly.
* **One limitation or challenge identified:** For `alert-0-214`, Meta-AI returned `approved: true` with empty `issues: []` and `questions_or_requests: []` (`uncertainty: 0.2`). Its reflection stated that the decision was sufficiently supported, but it did not mention the missing external logs (such as IdP/SSO or firewall logs). This showed that Meta-AI did not identify all the limitations in the available evidence, so human review was still important.

---

## 6. Make and Justify Your Human Decision

* **Selected decision:** `approve`
* **Confidence:** High
* **Justification:**
  > I approved the recommended action, `increase_monitoring`, for `alert-0-214` (`correlation_id: 50608476-4a9e-4956-9845-c7c37b21445c`). The `raw.logs` data (Offset `214`) showed a login event for user `alice` on `web-01` from the `US`, with elevated `failed_logins` and `bytes_out`. The event was also flagged as an anomaly by the Isolation Forest (`prediction = 1`), with `fingerprint_z = 4.0319` and a `risk_score` of `80`.
  >
  > The XAI agent linked this activity to several potential MITRE ATT&CK tactics (`TA0006`, `TA0010`, `TA0004`). However, these are interpretations and do not confirm that an attack actually occurred. There is still some uncertainty because no external IdP/SSO or firewall logs were available to verify the activity.
  >
  > According to the RAI policy, the recommended action was allowed, and human approval was not required for this medium-risk case. Automated destructive actions were blocked. Therefore, I decided to approve `increase_monitoring` because it allows further monitoring without taking unnecessary actions that could affect the user or system.
* **Sources used:**
  - [x] Detector
  - [x] XAI
  - [x] RAI
  - [x] Meta-AI
  - [ ] Independent evidence
  - [x] Own domain knowledge
* **Decision sovereignty reflection:**
  - [x] Multiple information sources contributed to my decision.
* **What most influenced your decision?** The combination of concrete behavioral telemetry evidence (`fingerprint_z = 4.0319`, elevated `failed_logins`, and `bytes_out` for `alice` on `web-01`) verified in `raw.logs`, together with the RAI policy guardrail blocking destructive actions below risk score `85` in favor of proportionate monitoring (`increase_monitoring`).

---

## 7. Verify Decision and Audit Trail

| Check | Pass / Fail / Not available |
| :--- | :--- |
| **Correct `alert_id`** | `Pass` |
| **Decision state updated** | `Pass` |
| **Decision event visible** | `Pass` |
| **Justification preserved** | `Pass` |
| **Timestamp recorded** | `Not available` |

---

## 8. Reflection and Educational Submission

1. **Which evidence most influenced your decision?**  
   The evidence that influenced my decision the most was the unusual login activity found in `raw.logs` (Offset `214`). The event involved user `alice` on `web-01`, with elevated `failed_logins` and `bytes_out`. The `fingerprint_z` score of `4.0319` and the Isolation Forest anomaly prediction (`1`) also supported the alert.

2. **Did you agree with the AI recommendation? Why or why not?**  
   Yes, I agreed with the recommendation to approve `increase_monitoring`. The activity was suspicious, but there was not enough independent evidence to confirm that the account had been compromised. Since the risk score was `80`, below the high-risk threshold of `85`, increased monitoring seemed like a reasonable response without immediately affecting the user's access.

3. **What did XAI explain well, and what was uncertain or unsupported?**  
   XAI helped explain which features triggered the alert, including the fingerprint deviation, `failed_logins` and `bytes_out`. It also connected the activity to possible MITRE ATT&CK tactics. However, these connections were not proof of an actual attack. The country field showed `US`, but this alone did not confirm the user's physical location. Additional logs would be needed to verify this information.

4. **Did RAI meaningfully constrain the recommended action?**  
   Yes. The RAI policy showed that the alert was classified as medium risk and recommended `increase_monitoring`. It also blocked automatic destructive actions, such as isolating the host or locking the account. This meant that the system could continue monitoring the suspicious activity without taking actions that might unnecessarily disrupt the service.

5. **Did Meta-AI challenge the recommendation or reveal an evidence gap?**  
   No. Meta-AI approved the decision and returned no issues or additional questions. However, it did not mention the lack of external authentication or firewall logs. I think this was an important limitation because the available evidence was not enough to fully confirm whether the login was malicious.

6. **What additional independent evidence could change your decision?**  
   Additional IdP/SSO authentication logs showing unusual login activity, MFA bypass attempts or an unknown device could make me reconsider the decision and choose to escalate the case. On the other hand, corporate VPN logs or travel records confirming that `alice` was legitimately in the `US` could indicate that the activity was not malicious.

7. **Where should human authority be strongest, and what could go wrong with automatic remediation?**  
   Human authority should be strongest when the risk is high, when the available evidence is unclear, and before taking actions that could affect users or important systems. For example, automatically isolating a server or locking an account based on a false positive could interrupt normal operations and prevent legitimate users from accessing their systems. This is why important decisions should still involve human review.
```[cite: 16]
