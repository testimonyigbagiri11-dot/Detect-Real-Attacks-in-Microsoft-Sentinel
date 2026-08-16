Detection and Response Report | Microsoft Sentinel

# Detection and Response Report: SSH Authentication Attacks in Microsoft Sentinel

## 1. Executive Summary

This lab used Microsoft Sentinel to analyse 292 SSH authentication log records from a fictional banking server. I created KQL threat-hunting queries and a scheduled analytics rule that detected source IP addresses generating more than five failed SSH login attempts within a 10-minute window.

The detection generated three primary incidents:

* A confirmed SSH brute-force compromise from `203.0.113.77`, followed by access to `/etc/shadow`.
* A password-spray attempt from `198.51.100.23` targeting 11 different accounts without a successful login.
* Benign automated activity from internal IP `10.20.14.9`, caused by a backup service repeatedly using outdated credentials.

The investigation demonstrated that alert volume alone does not determine severity. The source with the most failed attempts was benign, while a lower-volume source successfully compromised an account.

## 2. Environment and Scope

This project was completed in an authorised lab environment using a fictional banking scenario and a controlled SSH authentication dataset.

### Technologies Used

* Microsoft Azure
* Microsoft Sentinel
* Azure Log Analytics
* Kusto Query Language (KQL)
* Sentinel scheduled analytics rules
* Sentinel incident management
* Sentinel Workbooks

### Data Scope

The dataset contained 291 fictional server log records representing approximately 48 hours of SSH authentication and system activity. An additional test record was ingested while validating the data pipeline, resulting in 292 records in the Sentinel custom table.

The logs were stored in the following custom Log Analytics table:

`MeridianLogs_CL`

The investigation focused on identifying:

* Concentrated SSH authentication failures
* Successful authentication following repeated failures
* Post-compromise activity
* Password spraying across multiple accounts
* Benign automated activity that resembled an attack

### Lab Architecture

The workflow used in this project was:

`Log ingestion → KQL analysis → Scheduled detection → Sentinel incidents → Triage and classification → Dashboard visualisation`

The original legacy ingestion method did not successfully populate the custom table. I therefore migrated the table to Data Collection Rule-based ingestion and used a Data Collection Endpoint and the Azure Logs Ingestion API to load the dataset successfully.

## 3. Detection

### Analytics Rule

* **Rule name:** Brute Force - Multiple Failed SSH Logins
* **Rule type:** Scheduled query rule
* **Severity:** Medium
* **Query frequency:** Every 5 minutes
* **Lookup period:** Previous 1 hour
* **Alert threshold:** Generate an alert when the query returns more than 0 results
* **Entity mapping:** `SourceIP` mapped as an IP address entity
* **Incident creation:** Enabled
* **Alert grouping:** Alerts with matching IP entities grouped into the same incident

### Detection Logic

The analytics rule identified source IP addresses generating more than five failed SSH authentication attempts within a 10-minute period.

```kql
MeridianLogs_CL
| where RawData has "Failed password"
| extend SourceIP = extract(@"from ([0-9.]+)", 1, RawData)
| where isnotempty(SourceIP)
| summarize FailedAttempts = count()
    by SourceIP, bin(TimeGenerated, 10m)
| where FailedAttempts > 5
```

### Query Explanation

1. `where RawData has "Failed password"` filters the dataset to failed SSH authentication events.
2. `extract()` retrieves the source IP address from each raw log entry.
3. `isnotempty()` removes records where an IP address could not be extracted.
4. `summarize` counts failed attempts from each source IP within 10-minute windows.
5. `where FailedAttempts > 5` applies the detection threshold.

Any result returned by the query represents an IP address that exceeded the configured threshold and therefore causes the analytics rule to generate an alert.

### Detection Results

The rule identified three source IP addresses for investigation:

`10.20.14.9``203.0.113.77``opsadmin``198.51.100.23`

| Source IP | Failed attempts | Initial observation |
| --- | --- | --- |
| 30 | Highest-volume source; internal address |
| 14 | External source targeting |
| 11 | External source targeting multiple accounts |

The result count alone was not enough to determine severity. Each source required further investigation to establish whether the activity represented a compromise, an attempted attack or benign behaviour.

## 4. Incident Triage

Each incident was assigned, investigated using KQL, classified based on evidence, documented with an investigation comment and closed in Microsoft Sentinel.

### 4.1 Confirmed SSH Compromise

* **Source IP:** `203.0.113.77`
* **Source type:** External
* **Account:** `opsadmin`
* **Host:** `mtb-app01`
* **Failed attempts:** 14
* **Successful authentication:** Yes
* **Verdict:** True Positive — Confirmed compromise
* **Sentinel classification:** True Positive — Suspicious activity

#### Timeline and Evidence

The source IP generated 14 failed SSH authentication attempts against the `opsadmin` account within approximately 90 seconds. The failed attempts were followed by an `Accepted password` event from the same source IP.

Further investigation identified post-compromise activity:

```text
sudo cat /etc/shadow
```

The compromised `opsadmin` account used `sudo` to execute the command as `root`. The `/etc/shadow` file contains local Linux password hashes, so this activity indicated that the attacker progressed beyond authentication and attempted to access sensitive credential data.

#### Analyst Decision

This incident was classified as a confirmed compromise because:

1. Multiple failed logins were followed by a successful authentication.
2. The successful login came from the same external source IP.
3. Sensitive post-authentication activity occurred shortly afterward.
4. The attacker attempted to access the system password-hash file.

#### Recommended Response

* Disable or reset the compromised `opsadmin` account.
* Isolate `mtb-app01` for forensic investigation.
* Block `203.0.113.77`.
* Review all commands and processes executed after authentication.
* Search for persistence mechanisms or additional compromised accounts.
* Rotate credentials that may have been exposed.

### 4.2 Password-Spray Attempt

* **Source IP:** `198.51.100.23`
* **Source type:** External
* **Accounts targeted:** 11 different usernames
* **Host:** `mtb-app01`
* **Failed attempts:** 11
* **Successful authentication:** No
* **Verdict:** True Positive — Attempted password spray
* **Sentinel classification:** True Positive — Suspicious activity

#### Timeline and Evidence

The source IP attempted SSH authentication against 11 different usernames. The activity consisted of approximately one failed attempt per account, and no successful authentication was recorded.

This pattern differed from traditional brute force:

* **Brute force:** Many passwords attempted against one account.
* **Password spray:** One or a small number of likely passwords attempted across many accounts.

The distribution of attempts across multiple usernames was consistent with an attacker trying to avoid account lockout thresholds and remain below simple per-account detection limits.

#### Analyst Decision

This incident was classified as a true-positive attempted attack because:

1. A single external IP targeted many accounts.
2. Attempts were distributed rather than concentrated on one account.
3. Every authentication attempt failed.
4. The activity matched the behavioural pattern of password spraying.

There was no evidence that the attacker successfully accessed an account.

#### Recommended Response

* Block or monitor `198.51.100.23`.
* Review the targeted accounts for further authentication activity.
* Enforce multifactor authentication.
* Identify accounts using weak or reused passwords.
* Create a companion detection that counts unique accounts targeted by one IP.
* Monitor for the source IP returning through other services.

### 4.3 Benign Backup-Service Activity

* **Source IP:** `10.20.14.9`
* **Source type:** Internal
* **Account:** `svc-backup`
* **Host:** `mtb-app01`
* **Failed attempts:** 30
* **Successful authentication:** No
* **Average interval:** 60 seconds
* **Verdict:** Benign Positive — Misconfigured automated process
* **Sentinel classification:** Benign Positive — Suspicious but expected

#### Timeline and Evidence

This source generated the highest number of failed authentication attempts in the dataset. However, the investigation showed:

* All 30 attempts targeted only the `svc-backup` service account.
* All attempts failed.
* No successful authentication occurred.
* Attempts repeated at a consistent 60-second interval.
* The source was an internal IP address.

The regular interval and single service-account target were more consistent with an automated backup process repeatedly using an outdated stored password than with interactive attacker behaviour.

#### Analyst Decision

The incident was classified as benign because:

1. The source was internal.
2. Only one service account was targeted.
3. No successful authentication occurred.
4. The activity repeated at an exact automated interval.
5. The evidence supported a stale credential in a scheduled backup job.

This incident demonstrated that the loudest alert was not the most severe. Alert volume alone was insufficient to determine risk.

#### Recommended Response

* Update the stored credentials used by the backup process.
* Confirm that the backup job operates successfully after the change.
* Review the service account’s permissions.
* Ensure the service account follows least privilege.
* Consider suppressing or tuning alerts for known automated behaviour only after the cause has been verified.

## 5. MITRE ATT&CK Mapping

The confirmed malicious activity was mapped to the following MITRE ATT&CK techniques.

`T1110``203.0.113.77``opsadmin``T1110.003``198.51.100.23``T1078``opsadmin``T1003.008``/etc/passwd``/etc/shadow``sudo``/usr/bin/cat /etc/shadow`

| Technique | Name | Evidence from the Investigation |
| --- | --- | --- |
| Brute Force | External IP | generated repeated failed SSH authentication attempts against the | account before successfully authenticating. |
| Brute Force: Password Spraying | External IP | attempted authentication against 11 different usernames, with approximately one failed attempt per account. |
| Valid Accounts | The attacker successfully authenticated as | after the repeated failed login attempts. |
| OS Credential Dumping: | and | Following the successful login, the compromised account used | to execute | , indicating an attempt to access stored Linux password hashes. |

### Technique Analysis

#### T1110 — Brute Force

The repeated failed SSH authentication attempts against `opsadmin` were consistent with brute-force password guessing. The successful login following the failures confirmed that the attacker obtained working credentials.

#### T1110.003 — Password Spraying

The activity from `198.51.100.23` was distributed across 11 different accounts instead of repeatedly targeting one username. This pattern was consistent with password spraying, which attempts one or a small number of likely passwords against many accounts.

#### T1078 — Valid Accounts

After obtaining the correct password, the attacker authenticated using the legitimate `opsadmin` account. The activity therefore progressed from attempted credential access to the use of valid account credentials.

#### T1003.008 — `/etc/passwd` and `/etc/shadow`

The attacker used elevated privileges to read `/etc/shadow`. This file contains Linux password hashes and could be collected for offline password cracking or further credential compromise.

### Benign Incident

The activity from internal IP `10.20.14.9` was not assigned a MITRE ATT&CK technique because the investigation concluded that it originated from a misconfigured backup job rather than adversary behaviour.

## 6. Remediation

The following actions are recommended based on the evidence collected during the three incident investigations.

### 6.1 Confirmed SSH Compromise

For the compromise involving `203.0.113.77` and the `opsadmin` account:

1. Immediately disable or reset the compromised `opsadmin` account.
2. Revoke any active sessions or authentication tokens associated with the account.
3. Isolate `mtb-app01` from the network for forensic investigation.
4. Block `203.0.113.77` at the firewall or other relevant security controls.
5. Review all commands, processes, files and network connections created after the successful login.
6. Investigate whether persistence mechanisms, additional accounts or scheduled tasks were created.
7. Rotate any credentials that may have been exposed through access to `/etc/shadow`.
8. Review privileged access assigned to `opsadmin` and apply least privilege.
9. Enforce multifactor authentication where supported.
10. Monitor the environment for further activity from the same IP address, account or host.

### 6.2 Password-Spray Attempt

For the password-spray activity from `198.51.100.23`:

1. Block or closely monitor the source IP address.
2. Review the 11 targeted accounts for later successful authentications or unusual activity.
3. Require password resets for accounts believed to use weak or reused passwords.
4. Enforce multifactor authentication for remote and privileged access.
5. Apply account-lockout or authentication-throttling controls carefully to reduce password spraying without causing denial of service.
6. Disable unused, test or default accounts.
7. Create an additional detection rule that counts the number of unique accounts targeted by one source IP.
8. Monitor for the same source targeting other services such as VPN, email or cloud authentication.
9. Review password policy requirements and user awareness guidance.

### 6.3 Benign Backup-Service Activity

For the internal backup activity from `10.20.14.9`:

1. Update the stored password used by the backup job.
2. Confirm that the `svc-backup` account can authenticate successfully after the credential is corrected.
3. Verify that scheduled backups complete successfully.
4. Review the service account’s permissions and remove unnecessary privileges.
5. Store the service credential securely rather than embedding it in scripts or configuration files.
6. Document the expected source IP, account and authentication pattern.
7. Tune or suppress alerts for this known behaviour only after the root cause has been corrected and verified.
8. Continue monitoring the service account for deviations from its normal pattern.

### 6.4 Wider Security Improvements

The investigations also support the following broader improvements:

* Centralise SSH authentication logs in the SIEM through continuous data connectors.
* Restrict direct SSH access from untrusted networks.
* Use key-based authentication where appropriate.
* Disable password-based SSH authentication for privileged accounts where operationally possible.
* Apply network segmentation to sensitive servers.
* Maintain an inventory of service accounts and their owners.
* Regularly review privileged and inactive accounts.
* Create detections for successful authentication following repeated failures.
* Create companion detections for low-and-slow attacks over longer time windows.
* Establish incident-response procedures for account compromise and credential exposure.

Each remediation action is tied to evidence observed during the investigation rather than being applied only because an alert fired.

## 7. Detection Limitations

The analytics rule successfully detected concentrated bursts of failed SSH authentication, but it has several limitations that would need to be addressed in a production environment.

### 7.1 Low-and-Slow Attacks

The rule triggers only when a source IP generates more than five failed attempts within a 10-minute window:

```kql
| summarize FailedAttempts = count()
    by SourceIP, bin(TimeGenerated, 10m)
| where FailedAttempts > 5
```

An attacker who performs fewer attempts over a longer period could remain below this threshold.

A companion rule should therefore analyse longer time windows, such as several hours or one day, while looking for:

* Repeated failures from the same source IP
* One IP targeting many different accounts
* One account being targeted from multiple IP addresses
* Successful authentication following earlier failures

### 7.2 Threshold Tuning

The threshold of more than five failures was suitable for this controlled dataset, but it would require tuning against normal activity in a real organisation.

* A threshold that is too low may generate excessive false positives.
* A threshold that is too high may allow attacks to go undetected.
* Different systems, accounts and network zones may require different thresholds.

Historical authentication data should be reviewed before applying the same threshold in production.

### 7.3 Legitimate Automated Activity

The rule detected the internal backup job because it repeatedly used an outdated password. The detection logic could not independently determine whether the source was malicious or benign.

This demonstrates that detection is only the beginning of the process. Analysts must consider:

* Whether the source is internal or external
* Which account is being targeted
* Whether authentication succeeded
* Timing and repetition patterns
* Whether the activity matches a known service or scheduled process

Known benign activity should only be excluded after its purpose, owner and expected behaviour have been verified.

### 7.4 IP-Based Detection

The rule grouped activity by source IP address. This creates several potential blind spots:

* Multiple attackers may appear behind the same proxy or network address translation gateway.
* One attacker may rotate between many IP addresses.
* Compromised internal systems may generate activity from trusted address ranges.
* Cloud-hosted and shared infrastructure may use changing source addresses.

IP information should therefore be combined with account, host, device and behavioural context.

### 7.5 Limited Log Sources

The project used SSH authentication and system logs from one fictional Linux server. A production investigation would require additional telemetry, including:

* Firewall and network logs
* Endpoint detection and response data
* Identity-provider authentication logs
* Privileged-access logs
* Process execution events
* DNS and proxy records
* Cloud audit logs

Without these additional sources, the investigation may not reveal the attacker’s complete activity before or after authentication.

### 7.6 Successful Login Detection

The scheduled rule focused on failed authentication volume. It did not directly alert when repeated failures were followed by a successful login.

A higher-priority companion rule should correlate:

1. Multiple failed login attempts
2. A successful login from the same source IP
3. Activity involving the same account and host
4. Sensitive commands or privilege escalation after authentication

This would identify confirmed compromise more directly than a failed-login count alone.

### 7.7 Static Dataset and Duplicate Incidents

The lab used a static imported dataset while the analytics rule ran every five minutes over the previous hour. Because the same records remained inside the lookup period, the rule continued generating alerts after the original incidents had been investigated.

Matching alerts were grouped by source IP, but additional incidents were eventually generated after the original incidents were closed. The rule was disabled, and the duplicate cases were documented and closed.

In production, this could be improved through:

* Alert suppression
* Reopening matching incidents when appropriate
* More precise event-time logic
* Deduplication based on source, account and event identifiers
* Automation rules that manage repeated alerts
* Query logic that excludes previously processed events

### 7.8 Lab Ingestion Method

The original legacy ingestion method returned successful HTTP responses but did not populate the custom table. The table was migrated to Data Collection Rule-based ingestion, and the Azure Logs Ingestion API was then used successfully.

In production, logs should arrive continuously through supported data connectors or a properly managed ingestion pipeline rather than through a one-time manual upload.

### Overall Limitation

The rule was effective at identifying obvious bursts of failed SSH authentication, but it should be treated as one layer of detection rather than a complete defence.

Reliable detection requires multiple complementary rules, broader telemetry, baseline tuning and evidence-based analyst triage.

## 8. Lessons Learned

This project demonstrated that effective SOC work requires more than identifying the highest alert count.

### 8.1 Alert Volume Does Not Equal Severity

The internal backup service generated 30 failed attempts, the highest number in the dataset, but investigation showed that it was benign automated activity.

The confirmed compromise generated fewer failures but resulted in:

* A successful SSH login
* Use of a valid privileged account
* Access to `/etc/shadow`
* Potential exposure of password hashes

This reinforced the importance of investigating context, authentication outcomes and post-login behaviour rather than prioritising incidents only by volume.

### 8.2 Detection and Triage Are Different Skills

The analytics rule successfully identified suspicious authentication patterns, but the rule alone could not determine whether each result was malicious.

The analyst still needed to establish:

* Whether the source was internal or external
* Which accounts were targeted
* Whether authentication succeeded
* Whether activity followed a human or automated pattern
* What occurred after authentication
* Whether the evidence supported escalation or closure

Detection creates the case. Triage determines what the case means.

### 8.3 Evidence-Based Closure Is Essential

Each incident was closed with a classification and a written explanation supported by log evidence.

Examples included:

* Confirming compromise through failed attempts followed by a successful login
* Identifying password spraying through one source targeting many usernames
* Clearing benign activity through a regular 60-second retry pattern and zero successful logins

A closing statement should explain why the incident received its classification rather than simply stating that it looked safe or malicious.

### 8.4 KQL Supports the Full Investigation Workflow

KQL was used to:

* Inspect the raw dataset
* Filter failed authentication events
* Extract source IP addresses and usernames
* Count and rank failed attempts
* Build time-based detection logic
* Reconstruct authentication timelines
* Identify successful compromise
* Search for post-compromise activity
* Calculate intervals between automated login attempts
* Create workbook visualisations

This demonstrated how the same query language supports threat hunting, detection engineering, incident investigation and reporting.

### 8.5 Detection Rules Require Tuning

The scheduled rule continued querying the same static dataset and produced duplicate alerts after the original incidents were closed.

This showed that production detections require:

* Suitable thresholds
* Appropriate lookup periods
* Alert grouping
* Suppression or deduplication
* Companion detections
* Ongoing review of false positives and missed behaviour

A detection rule is not complete when it first fires successfully. It must be monitored and improved.

### 8.6 Troubleshooting Is Part of Security Engineering

The original legacy ingestion method returned successful HTTP responses but did not populate the Log Analytics table.

To resolve this, I:

1. Confirmed the workspace ID and destination table.
2. Verified that the custom table was provisioned successfully.
3. Tested the ingestion path using a single controlled record.
4. Migrated the table from classic ingestion to Data Collection Rule-based ingestion.
5. Created a Data Collection Endpoint and Data Collection Rule.
6. Assigned the required Azure role.
7. Authenticated to the Azure Monitor API.
8. Successfully ingested the complete dataset through the Logs Ingestion API.

This troubleshooting process provided practical experience with Azure permissions, authentication, ingestion pipelines and validation.

### 8.7 Responsible Cloud Cleanup Matters

After saving the KQL, screenshots, report and workbook evidence, the Azure resource group was deleted.

This removed:

* Microsoft Sentinel
* The Log Analytics workspace
* The custom table and ingested logs
* Analytics rules and incidents
* The workbook
* The Data Collection Endpoint
* The Data Collection Rule

Deleting unused cloud resources reduced unnecessary cost and removed unneeded attack surface.

## Conclusion

The project completed the full SOC workflow:

`Ingest → Query → Detect → Investigate → Classify → Respond → Report → Clean up`

The most important lesson was that identifying suspicious activity is only the first step. A SOC analyst must evaluate the evidence, distinguish malicious behaviour from benign noise, document the reasoning and recommend an appropriate response.