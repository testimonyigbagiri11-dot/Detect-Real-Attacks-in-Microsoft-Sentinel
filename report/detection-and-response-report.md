<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="description" content="Detection and Response Report: SSH Authentication Attacks in Microsoft Sentinel">
  <title>Detection and Response Report | Microsoft Sentinel</title>
  <style>
    :root {
      --bg: #f6f8fa;
      --card: #ffffff;
      --text: #24292f;
      --muted: #57606a;
      --border: #d0d7de;
      --accent: #0969da;
      --code-bg: #f6f8fa;
    }
    * { box-sizing: border-box; }
    html { scroll-behavior: smooth; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.65;
    }
    main {
      max-width: 1050px;
      margin: 40px auto;
      padding: 0 24px 60px;
    }
    article {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 42px;
      box-shadow: 0 2px 10px rgba(27,31,36,.06);
    }
    h1 { font-size: 2.25rem; line-height: 1.2; margin-top: 0; }
    h2 { margin-top: 2.4rem; padding-bottom: .35rem; border-bottom: 1px solid var(--border); }
    h3 { margin-top: 1.8rem; }
    h4 { margin-top: 1.4rem; }
    p { color: var(--text); }
    li { margin: .35rem 0; }
    code {
      padding: .15rem .35rem;
      border-radius: 5px;
      background: var(--code-bg);
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: .9em;
    }
    pre {
      overflow-x: auto;
      padding: 18px;
      border: 1px solid var(--border);
      border-radius: 8px;
      background: #0d1117;
      color: #e6edf3;
      line-height: 1.5;
    }
    pre code { padding: 0; background: transparent; color: inherit; }
    .table-wrap { overflow-x: auto; margin: 1rem 0; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border: 1px solid var(--border); padding: 10px 12px; text-align: left; vertical-align: top; }
    th { background: var(--code-bg); font-weight: 600; }
    @media (max-width: 700px) {
      main { margin: 0 auto; padding: 0 10px 30px; }
      article { padding: 22px 18px; border-radius: 0; }
      h1 { font-size: 1.8rem; }
    }
  </style>
</head>
<body>
  <main>
    <article>
<h1>Detection and Response Report: SSH Authentication Attacks in Microsoft Sentinel</h1>
<h2>1. Executive Summary</h2>
<p>This lab used Microsoft Sentinel to analyse 292 SSH authentication log records from a fictional banking server. I created KQL threat-hunting queries and a scheduled analytics rule that detected source IP addresses generating more than five failed SSH login attempts within a 10-minute window.</p>
<p>The detection generated three primary incidents:</p>
<ul><li>A confirmed SSH brute-force compromise from <code>203.0.113.77</code>, followed by access to <code>/etc/shadow</code>.</li><li>A password-spray attempt from <code>198.51.100.23</code> targeting 11 different accounts without a successful login.</li><li>Benign automated activity from internal IP <code>10.20.14.9</code>, caused by a backup service repeatedly using outdated credentials.</li></ul>
<p>The investigation demonstrated that alert volume alone does not determine severity. The source with the most failed attempts was benign, while a lower-volume source successfully compromised an account.</p>
<h2>2. Environment and Scope</h2>
<p>This project was completed in an authorised lab environment using a fictional banking scenario and a controlled SSH authentication dataset.</p>
<h3>Technologies Used</h3>
<ul><li>Microsoft Azure</li><li>Microsoft Sentinel</li><li>Azure Log Analytics</li><li>Kusto Query Language (KQL)</li><li>Sentinel scheduled analytics rules</li><li>Sentinel incident management</li><li>Sentinel Workbooks</li></ul>
<h3>Data Scope</h3>
<p>The dataset contained 291 fictional server log records representing approximately 48 hours of SSH authentication and system activity. An additional test record was ingested while validating the data pipeline, resulting in 292 records in the Sentinel custom table.</p>
<p>The logs were stored in the following custom Log Analytics table:</p>
<p><code>MeridianLogs_CL</code></p>
<p>The investigation focused on identifying:</p>
<ul><li>Concentrated SSH authentication failures</li><li>Successful authentication following repeated failures</li><li>Post-compromise activity</li><li>Password spraying across multiple accounts</li><li>Benign automated activity that resembled an attack</li></ul>
<h3>Lab Architecture</h3>
<p>The workflow used in this project was:</p>
<p><code>Log ingestion → KQL analysis → Scheduled detection → Sentinel incidents → Triage and classification → Dashboard visualisation</code></p>
<p>The original legacy ingestion method did not successfully populate the custom table. I therefore migrated the table to Data Collection Rule-based ingestion and used a Data Collection Endpoint and the Azure Logs Ingestion API to load the dataset successfully.</p>
<h2>3. Detection</h2>
<h3>Analytics Rule</h3>
<ul><li><strong>Rule name:</strong> Brute Force - Multiple Failed SSH Logins</li><li><strong>Rule type:</strong> Scheduled query rule</li><li><strong>Severity:</strong> Medium</li><li><strong>Query frequency:</strong> Every 5 minutes</li><li><strong>Lookup period:</strong> Previous 1 hour</li><li><strong>Alert threshold:</strong> Generate an alert when the query returns more than 0 results</li><li><strong>Entity mapping:</strong> <code>SourceIP</code> mapped as an IP address entity</li><li><strong>Incident creation:</strong> Enabled</li><li><strong>Alert grouping:</strong> Alerts with matching IP entities grouped into the same incident</li></ul>
<h3>Detection Logic</h3>
<p>The analytics rule identified source IP addresses generating more than five failed SSH authentication attempts within a 10-minute period.</p>
<pre><code class="language-kql">MeridianLogs_CL
| where RawData has &quot;Failed password&quot;
| extend SourceIP = extract(@&quot;from ([0-9.]+)&quot;, 1, RawData)
| where isnotempty(SourceIP)
| summarize FailedAttempts = count()
    by SourceIP, bin(TimeGenerated, 10m)
| where FailedAttempts &gt; 5</code></pre>
<h3>Query Explanation</h3>
<ol><li><code>where RawData has "Failed password"</code> filters the dataset to failed SSH authentication events.</li><li><code>extract()</code> retrieves the source IP address from each raw log entry.</li><li><code>isnotempty()</code> removes records where an IP address could not be extracted.</li><li><code>summarize</code> counts failed attempts from each source IP within 10-minute windows.</li><li><code>where FailedAttempts &gt; 5</code> applies the detection threshold.</li></ol>
<p>Any result returned by the query represents an IP address that exceeded the configured threshold and therefore causes the analytics rule to generate an alert.</p>
<h3>Detection Results</h3>
<p>The rule identified three source IP addresses for investigation:</p>
<div class="table-wrap"><table><thead><tr><th>Source IP</th><th>Failed attempts</th><th>Initial observation</th></tr></thead><tbody><tr><td><code>10.20.14.9</code></td><td>30</td><td>Highest-volume source; internal address</td></tr><tr><td><code>203.0.113.77</code></td><td>14</td><td>External source targeting <code>opsadmin</code></td></tr><tr><td><code>198.51.100.23</code></td><td>11</td><td>External source targeting multiple accounts</td></tr></tbody></table></div>
<p>The result count alone was not enough to determine severity. Each source required further investigation to establish whether the activity represented a compromise, an attempted attack or benign behaviour.</p>
<h2>4. Incident Triage</h2>
<p>Each incident was assigned, investigated using KQL, classified based on evidence, documented with an investigation comment and closed in Microsoft Sentinel.</p>
<h3>4.1 Confirmed SSH Compromise</h3>
<ul><li><strong>Source IP:</strong> <code>203.0.113.77</code></li><li><strong>Source type:</strong> External</li><li><strong>Account:</strong> <code>opsadmin</code></li><li><strong>Host:</strong> <code>mtb-app01</code></li><li><strong>Failed attempts:</strong> 14</li><li><strong>Successful authentication:</strong> Yes</li><li><strong>Verdict:</strong> True Positive — Confirmed compromise</li><li><strong>Sentinel classification:</strong> True Positive — Suspicious activity</li></ul>
<h4>Timeline and Evidence</h4>
<p>The source IP generated 14 failed SSH authentication attempts against the <code>opsadmin</code> account within approximately 90 seconds. The failed attempts were followed by an <code>Accepted password</code> event from the same source IP.</p>
<p>Further investigation identified post-compromise activity:</p>
<pre><code class="language-text">sudo cat /etc/shadow</code></pre>
<p>The compromised <code>opsadmin</code> account used <code>sudo</code> to execute the command as <code>root</code>. The <code>/etc/shadow</code> file contains local Linux password hashes, so this activity indicated that the attacker progressed beyond authentication and attempted to access sensitive credential data.</p>
<h4>Analyst Decision</h4>
<p>This incident was classified as a confirmed compromise because:</p>
<ol><li>Multiple failed logins were followed by a successful authentication.</li><li>The successful login came from the same external source IP.</li><li>Sensitive post-authentication activity occurred shortly afterward.</li><li>The attacker attempted to access the system password-hash file.</li></ol>
<h4>Recommended Response</h4>
<ul><li>Disable or reset the compromised <code>opsadmin</code> account.</li><li>Isolate <code>mtb-app01</code> for forensic investigation.</li><li>Block <code>203.0.113.77</code>.</li><li>Review all commands and processes executed after authentication.</li><li>Search for persistence mechanisms or additional compromised accounts.</li><li>Rotate credentials that may have been exposed.</li></ul>
<h3>4.2 Password-Spray Attempt</h3>
<ul><li><strong>Source IP:</strong> <code>198.51.100.23</code></li><li><strong>Source type:</strong> External</li><li><strong>Accounts targeted:</strong> 11 different usernames</li><li><strong>Host:</strong> <code>mtb-app01</code></li><li><strong>Failed attempts:</strong> 11</li><li><strong>Successful authentication:</strong> No</li><li><strong>Verdict:</strong> True Positive — Attempted password spray</li><li><strong>Sentinel classification:</strong> True Positive — Suspicious activity</li></ul>
<h4>Timeline and Evidence</h4>
<p>The source IP attempted SSH authentication against 11 different usernames. The activity consisted of approximately one failed attempt per account, and no successful authentication was recorded.</p>
<p>This pattern differed from traditional brute force:</p>
<ul><li><strong>Brute force:</strong> Many passwords attempted against one account.</li><li><strong>Password spray:</strong> One or a small number of likely passwords attempted across many accounts.</li></ul>
<p>The distribution of attempts across multiple usernames was consistent with an attacker trying to avoid account lockout thresholds and remain below simple per-account detection limits.</p>
<h4>Analyst Decision</h4>
<p>This incident was classified as a true-positive attempted attack because:</p>
<ol><li>A single external IP targeted many accounts.</li><li>Attempts were distributed rather than concentrated on one account.</li><li>Every authentication attempt failed.</li><li>The activity matched the behavioural pattern of password spraying.</li></ol>
<p>There was no evidence that the attacker successfully accessed an account.</p>
<h4>Recommended Response</h4>
<ul><li>Block or monitor <code>198.51.100.23</code>.</li><li>Review the targeted accounts for further authentication activity.</li><li>Enforce multifactor authentication.</li><li>Identify accounts using weak or reused passwords.</li><li>Create a companion detection that counts unique accounts targeted by one IP.</li><li>Monitor for the source IP returning through other services.</li></ul>
<h3>4.3 Benign Backup-Service Activity</h3>
<ul><li><strong>Source IP:</strong> <code>10.20.14.9</code></li><li><strong>Source type:</strong> Internal</li><li><strong>Account:</strong> <code>svc-backup</code></li><li><strong>Host:</strong> <code>mtb-app01</code></li><li><strong>Failed attempts:</strong> 30</li><li><strong>Successful authentication:</strong> No</li><li><strong>Average interval:</strong> 60 seconds</li><li><strong>Verdict:</strong> Benign Positive — Misconfigured automated process</li><li><strong>Sentinel classification:</strong> Benign Positive — Suspicious but expected</li></ul>
<h4>Timeline and Evidence</h4>
<p>This source generated the highest number of failed authentication attempts in the dataset. However, the investigation showed:</p>
<ul><li>All 30 attempts targeted only the <code>svc-backup</code> service account.</li><li>All attempts failed.</li><li>No successful authentication occurred.</li><li>Attempts repeated at a consistent 60-second interval.</li><li>The source was an internal IP address.</li></ul>
<p>The regular interval and single service-account target were more consistent with an automated backup process repeatedly using an outdated stored password than with interactive attacker behaviour.</p>
<h4>Analyst Decision</h4>
<p>The incident was classified as benign because:</p>
<ol><li>The source was internal.</li><li>Only one service account was targeted.</li><li>No successful authentication occurred.</li><li>The activity repeated at an exact automated interval.</li><li>The evidence supported a stale credential in a scheduled backup job.</li></ol>
<p>This incident demonstrated that the loudest alert was not the most severe. Alert volume alone was insufficient to determine risk.</p>
<h4>Recommended Response</h4>
<ul><li>Update the stored credentials used by the backup process.</li><li>Confirm that the backup job operates successfully after the change.</li><li>Review the service account’s permissions.</li><li>Ensure the service account follows least privilege.</li><li>Consider suppressing or tuning alerts for known automated behaviour only after the cause has been verified.</li></ul>
<h2>5. MITRE ATT&amp;CK Mapping</h2>
<p>The confirmed malicious activity was mapped to the following MITRE ATT&amp;CK techniques.</p>
<div class="table-wrap"><table><thead><tr><th>Technique</th><th>Name</th><th>Evidence from the Investigation</th></tr></thead><tbody><tr><td><code>T1110</code></td><td>Brute Force</td><td>External IP <code>203.0.113.77</code> generated repeated failed SSH authentication attempts against the <code>opsadmin</code> account before successfully authenticating.</td></tr><tr><td><code>T1110.003</code></td><td>Brute Force: Password Spraying</td><td>External IP <code>198.51.100.23</code> attempted authentication against 11 different usernames, with approximately one failed attempt per account.</td></tr><tr><td><code>T1078</code></td><td>Valid Accounts</td><td>The attacker successfully authenticated as <code>opsadmin</code> after the repeated failed login attempts.</td></tr><tr><td><code>T1003.008</code></td><td>OS Credential Dumping: <code>/etc/passwd</code> and <code>/etc/shadow</code></td><td>Following the successful login, the compromised account used <code>sudo</code> to execute <code>/usr/bin/cat /etc/shadow</code>, indicating an attempt to access stored Linux password hashes.</td></tr></tbody></table></div>
<h3>Technique Analysis</h3>
<h4>T1110 — Brute Force</h4>
<p>The repeated failed SSH authentication attempts against <code>opsadmin</code> were consistent with brute-force password guessing. The successful login following the failures confirmed that the attacker obtained working credentials.</p>
<h4>T1110.003 — Password Spraying</h4>
<p>The activity from <code>198.51.100.23</code> was distributed across 11 different accounts instead of repeatedly targeting one username. This pattern was consistent with password spraying, which attempts one or a small number of likely passwords against many accounts.</p>
<h4>T1078 — Valid Accounts</h4>
<p>After obtaining the correct password, the attacker authenticated using the legitimate <code>opsadmin</code> account. The activity therefore progressed from attempted credential access to the use of valid account credentials.</p>
<h4>T1003.008 — <code>/etc/passwd</code> and <code>/etc/shadow</code></h4>
<p>The attacker used elevated privileges to read <code>/etc/shadow</code>. This file contains Linux password hashes and could be collected for offline password cracking or further credential compromise.</p>
<h3>Benign Incident</h3>
<p>The activity from internal IP <code>10.20.14.9</code> was not assigned a MITRE ATT&amp;CK technique because the investigation concluded that it originated from a misconfigured backup job rather than adversary behaviour.</p>
<h2>6. Remediation</h2>
<p>The following actions are recommended based on the evidence collected during the three incident investigations.</p>
<h3>6.1 Confirmed SSH Compromise</h3>
<p>For the compromise involving <code>203.0.113.77</code> and the <code>opsadmin</code> account:</p>
<ol><li>Immediately disable or reset the compromised <code>opsadmin</code> account.</li><li>Revoke any active sessions or authentication tokens associated with the account.</li><li>Isolate <code>mtb-app01</code> from the network for forensic investigation.</li><li>Block <code>203.0.113.77</code> at the firewall or other relevant security controls.</li><li>Review all commands, processes, files and network connections created after the successful login.</li><li>Investigate whether persistence mechanisms, additional accounts or scheduled tasks were created.</li><li>Rotate any credentials that may have been exposed through access to <code>/etc/shadow</code>.</li><li>Review privileged access assigned to <code>opsadmin</code> and apply least privilege.</li><li>Enforce multifactor authentication where supported.</li><li>Monitor the environment for further activity from the same IP address, account or host.</li></ol>
<h3>6.2 Password-Spray Attempt</h3>
<p>For the password-spray activity from <code>198.51.100.23</code>:</p>
<ol><li>Block or closely monitor the source IP address.</li><li>Review the 11 targeted accounts for later successful authentications or unusual activity.</li><li>Require password resets for accounts believed to use weak or reused passwords.</li><li>Enforce multifactor authentication for remote and privileged access.</li><li>Apply account-lockout or authentication-throttling controls carefully to reduce password spraying without causing denial of service.</li><li>Disable unused, test or default accounts.</li><li>Create an additional detection rule that counts the number of unique accounts targeted by one source IP.</li><li>Monitor for the same source targeting other services such as VPN, email or cloud authentication.</li><li>Review password policy requirements and user awareness guidance.</li></ol>
<h3>6.3 Benign Backup-Service Activity</h3>
<p>For the internal backup activity from <code>10.20.14.9</code>:</p>
<ol><li>Update the stored password used by the backup job.</li><li>Confirm that the <code>svc-backup</code> account can authenticate successfully after the credential is corrected.</li><li>Verify that scheduled backups complete successfully.</li><li>Review the service account’s permissions and remove unnecessary privileges.</li><li>Store the service credential securely rather than embedding it in scripts or configuration files.</li><li>Document the expected source IP, account and authentication pattern.</li><li>Tune or suppress alerts for this known behaviour only after the root cause has been corrected and verified.</li><li>Continue monitoring the service account for deviations from its normal pattern.</li></ol>
<h3>6.4 Wider Security Improvements</h3>
<p>The investigations also support the following broader improvements:</p>
<ul><li>Centralise SSH authentication logs in the SIEM through continuous data connectors.</li><li>Restrict direct SSH access from untrusted networks.</li><li>Use key-based authentication where appropriate.</li><li>Disable password-based SSH authentication for privileged accounts where operationally possible.</li><li>Apply network segmentation to sensitive servers.</li><li>Maintain an inventory of service accounts and their owners.</li><li>Regularly review privileged and inactive accounts.</li><li>Create detections for successful authentication following repeated failures.</li><li>Create companion detections for low-and-slow attacks over longer time windows.</li><li>Establish incident-response procedures for account compromise and credential exposure.</li></ul>
<p>Each remediation action is tied to evidence observed during the investigation rather than being applied only because an alert fired.</p>
<h2>7. Detection Limitations</h2>
<p>The analytics rule successfully detected concentrated bursts of failed SSH authentication, but it has several limitations that would need to be addressed in a production environment.</p>
<h3>7.1 Low-and-Slow Attacks</h3>
<p>The rule triggers only when a source IP generates more than five failed attempts within a 10-minute window:</p>
<pre><code class="language-kql">| summarize FailedAttempts = count()
    by SourceIP, bin(TimeGenerated, 10m)
| where FailedAttempts &gt; 5</code></pre>
<p>An attacker who performs fewer attempts over a longer period could remain below this threshold.</p>
<p>A companion rule should therefore analyse longer time windows, such as several hours or one day, while looking for:</p>
<ul><li>Repeated failures from the same source IP</li><li>One IP targeting many different accounts</li><li>One account being targeted from multiple IP addresses</li><li>Successful authentication following earlier failures</li></ul>
<h3>7.2 Threshold Tuning</h3>
<p>The threshold of more than five failures was suitable for this controlled dataset, but it would require tuning against normal activity in a real organisation.</p>
<ul><li>A threshold that is too low may generate excessive false positives.</li><li>A threshold that is too high may allow attacks to go undetected.</li><li>Different systems, accounts and network zones may require different thresholds.</li></ul>
<p>Historical authentication data should be reviewed before applying the same threshold in production.</p>
<h3>7.3 Legitimate Automated Activity</h3>
<p>The rule detected the internal backup job because it repeatedly used an outdated password. The detection logic could not independently determine whether the source was malicious or benign.</p>
<p>This demonstrates that detection is only the beginning of the process. Analysts must consider:</p>
<ul><li>Whether the source is internal or external</li><li>Which account is being targeted</li><li>Whether authentication succeeded</li><li>Timing and repetition patterns</li><li>Whether the activity matches a known service or scheduled process</li></ul>
<p>Known benign activity should only be excluded after its purpose, owner and expected behaviour have been verified.</p>
<h3>7.4 IP-Based Detection</h3>
<p>The rule grouped activity by source IP address. This creates several potential blind spots:</p>
<ul><li>Multiple attackers may appear behind the same proxy or network address translation gateway.</li><li>One attacker may rotate between many IP addresses.</li><li>Compromised internal systems may generate activity from trusted address ranges.</li><li>Cloud-hosted and shared infrastructure may use changing source addresses.</li></ul>
<p>IP information should therefore be combined with account, host, device and behavioural context.</p>
<h3>7.5 Limited Log Sources</h3>
<p>The project used SSH authentication and system logs from one fictional Linux server. A production investigation would require additional telemetry, including:</p>
<ul><li>Firewall and network logs</li><li>Endpoint detection and response data</li><li>Identity-provider authentication logs</li><li>Privileged-access logs</li><li>Process execution events</li><li>DNS and proxy records</li><li>Cloud audit logs</li></ul>
<p>Without these additional sources, the investigation may not reveal the attacker’s complete activity before or after authentication.</p>
<h3>7.6 Successful Login Detection</h3>
<p>The scheduled rule focused on failed authentication volume. It did not directly alert when repeated failures were followed by a successful login.</p>
<p>A higher-priority companion rule should correlate:</p>
<ol><li>Multiple failed login attempts</li><li>A successful login from the same source IP</li><li>Activity involving the same account and host</li><li>Sensitive commands or privilege escalation after authentication</li></ol>
<p>This would identify confirmed compromise more directly than a failed-login count alone.</p>
<h3>7.7 Static Dataset and Duplicate Incidents</h3>
<p>The lab used a static imported dataset while the analytics rule ran every five minutes over the previous hour. Because the same records remained inside the lookup period, the rule continued generating alerts after the original incidents had been investigated.</p>
<p>Matching alerts were grouped by source IP, but additional incidents were eventually generated after the original incidents were closed. The rule was disabled, and the duplicate cases were documented and closed.</p>
<p>In production, this could be improved through:</p>
<ul><li>Alert suppression</li><li>Reopening matching incidents when appropriate</li><li>More precise event-time logic</li><li>Deduplication based on source, account and event identifiers</li><li>Automation rules that manage repeated alerts</li><li>Query logic that excludes previously processed events</li></ul>
<h3>7.8 Lab Ingestion Method</h3>
<p>The original legacy ingestion method returned successful HTTP responses but did not populate the custom table. The table was migrated to Data Collection Rule-based ingestion, and the Azure Logs Ingestion API was then used successfully.</p>
<p>In production, logs should arrive continuously through supported data connectors or a properly managed ingestion pipeline rather than through a one-time manual upload.</p>
<h3>Overall Limitation</h3>
<p>The rule was effective at identifying obvious bursts of failed SSH authentication, but it should be treated as one layer of detection rather than a complete defence.</p>
<p>Reliable detection requires multiple complementary rules, broader telemetry, baseline tuning and evidence-based analyst triage.</p>
<h2>8. Lessons Learned</h2>
<p>This project demonstrated that effective SOC work requires more than identifying the highest alert count.</p>
<h3>8.1 Alert Volume Does Not Equal Severity</h3>
<p>The internal backup service generated 30 failed attempts, the highest number in the dataset, but investigation showed that it was benign automated activity.</p>
<p>The confirmed compromise generated fewer failures but resulted in:</p>
<ul><li>A successful SSH login</li><li>Use of a valid privileged account</li><li>Access to <code>/etc/shadow</code></li><li>Potential exposure of password hashes</li></ul>
<p>This reinforced the importance of investigating context, authentication outcomes and post-login behaviour rather than prioritising incidents only by volume.</p>
<h3>8.2 Detection and Triage Are Different Skills</h3>
<p>The analytics rule successfully identified suspicious authentication patterns, but the rule alone could not determine whether each result was malicious.</p>
<p>The analyst still needed to establish:</p>
<ul><li>Whether the source was internal or external</li><li>Which accounts were targeted</li><li>Whether authentication succeeded</li><li>Whether activity followed a human or automated pattern</li><li>What occurred after authentication</li><li>Whether the evidence supported escalation or closure</li></ul>
<p>Detection creates the case. Triage determines what the case means.</p>
<h3>8.3 Evidence-Based Closure Is Essential</h3>
<p>Each incident was closed with a classification and a written explanation supported by log evidence.</p>
<p>Examples included:</p>
<ul><li>Confirming compromise through failed attempts followed by a successful login</li><li>Identifying password spraying through one source targeting many usernames</li><li>Clearing benign activity through a regular 60-second retry pattern and zero successful logins</li></ul>
<p>A closing statement should explain why the incident received its classification rather than simply stating that it looked safe or malicious.</p>
<h3>8.4 KQL Supports the Full Investigation Workflow</h3>
<p>KQL was used to:</p>
<ul><li>Inspect the raw dataset</li><li>Filter failed authentication events</li><li>Extract source IP addresses and usernames</li><li>Count and rank failed attempts</li><li>Build time-based detection logic</li><li>Reconstruct authentication timelines</li><li>Identify successful compromise</li><li>Search for post-compromise activity</li><li>Calculate intervals between automated login attempts</li><li>Create workbook visualisations</li></ul>
<p>This demonstrated how the same query language supports threat hunting, detection engineering, incident investigation and reporting.</p>
<h3>8.5 Detection Rules Require Tuning</h3>
<p>The scheduled rule continued querying the same static dataset and produced duplicate alerts after the original incidents were closed.</p>
<p>This showed that production detections require:</p>
<ul><li>Suitable thresholds</li><li>Appropriate lookup periods</li><li>Alert grouping</li><li>Suppression or deduplication</li><li>Companion detections</li><li>Ongoing review of false positives and missed behaviour</li></ul>
<p>A detection rule is not complete when it first fires successfully. It must be monitored and improved.</p>
<h3>8.6 Troubleshooting Is Part of Security Engineering</h3>
<p>The original legacy ingestion method returned successful HTTP responses but did not populate the Log Analytics table.</p>
<p>To resolve this, I:</p>
<ol><li>Confirmed the workspace ID and destination table.</li><li>Verified that the custom table was provisioned successfully.</li><li>Tested the ingestion path using a single controlled record.</li><li>Migrated the table from classic ingestion to Data Collection Rule-based ingestion.</li><li>Created a Data Collection Endpoint and Data Collection Rule.</li><li>Assigned the required Azure role.</li><li>Authenticated to the Azure Monitor API.</li><li>Successfully ingested the complete dataset through the Logs Ingestion API.</li></ol>
<p>This troubleshooting process provided practical experience with Azure permissions, authentication, ingestion pipelines and validation.</p>
<h3>8.7 Responsible Cloud Cleanup Matters</h3>
<p>After saving the KQL, screenshots, report and workbook evidence, the Azure resource group was deleted.</p>
<p>This removed:</p>
<ul><li>Microsoft Sentinel</li><li>The Log Analytics workspace</li><li>The custom table and ingested logs</li><li>Analytics rules and incidents</li><li>The workbook</li><li>The Data Collection Endpoint</li><li>The Data Collection Rule</li></ul>
<p>Deleting unused cloud resources reduced unnecessary cost and removed unneeded attack surface.</p>
<h2>Conclusion</h2>
<p>The project completed the full SOC workflow:</p>
<p><code>Ingest → Query → Detect → Investigate → Classify → Respond → Report → Clean up</code></p>
<p>The most important lesson was that identifying suspicious activity is only the first step. A SOC analyst must evaluate the evidence, distinguish malicious behaviour from benign noise, document the reasoning and recommend an appropriate response.</p>
    </article>
  </main>
</body>
</html>
