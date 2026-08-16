<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="description" content="Microsoft Sentinel SOC Detection and Triage Lab">
<title>Microsoft Sentinel SOC Detection and Triage Lab</title>
<style>
:root { color-scheme: dark; --bg:#0b1220; --panel:#111827; --text:#e5e7eb; --accent:#60a5fa; --border:#263244; --code:#0a0f18; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--text); font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif; line-height:1.7; }
main { width:min(100% - 32px,1000px); margin:40px auto; background:var(--panel); padding:40px; border:1px solid var(--border); border-radius:16px; box-shadow:0 12px 40px rgba(0,0,0,.25); }
h1,h2,h3 { line-height:1.25; color:#f8fafc; }
h1 { font-size:clamp(2rem,5vw,3rem); margin-top:0; }
h2 { margin-top:2.2em; padding-bottom:.35em; border-bottom:1px solid var(--border); }
a { color:var(--accent); }
code { background:var(--code); border:1px solid var(--border); border-radius:5px; padding:.12em .35em; }
pre { overflow-x:auto; background:var(--code); border:1px solid var(--border); border-radius:10px; padding:18px; }
pre code { border:0; padding:0; }
blockquote { margin:1.2em 0; padding:.8em 1em; border-left:4px solid var(--accent); background:rgba(96,165,250,.06); }
table { width:100%; border-collapse:collapse; margin:1.2em 0; display:block; overflow-x:auto; }
th,td { border:1px solid var(--border); padding:10px 12px; text-align:left; vertical-align:top; }
th { background:#182235; }
li { margin:.35em 0; }
@media (max-width:700px) { main { padding:24px; margin:16px auto; } }
</style>
</head>
<body><main>
<h1>Microsoft Sentinel SOC Detection and Triage Lab</h1>
<blockquote>End-to-end SOC investigation using Microsoft Sentinel, Azure Log Analytics and KQL, covering log ingestion, threat hunting, scheduled detection, incident triage, MITRE ATT&amp;CK mapping and reporting.</blockquote>
<h2>Project Summary</h2>
<p>I deployed Microsoft Sentinel, ingested 292 controlled SSH authentication events and developed nine KQL hunting and investigation queries.</p>
<p>I converted the detection logic into a scheduled analytics rule and investigated three resulting incidents:</p>
<ul>
<li>Confirmed SSH account compromise</li>
<li>Password-spray attempt</li>
<li>Benign automated backup failure</li>
</ul>
<p>The project demonstrates that alert volume alone does not determine severity: the highest-volume source was benign, while a lower-volume source successfully compromised an account.</p>
<h2>Quick Links</h2>
<ul>
<li>[View KQL Queries](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries)</li>
<li>[Read the Detection and Response Report](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/report/detection-and-response-report.md)</li>
<li>[View Investigation Evidence](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/screenshots)</li>
<li>[View the Sentinel Workbook](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab#sentinel-workbook)</li>
</ul>
<h2>Key Outcomes</h2>
<p>The detection identified three suspicious source IP addresses:</p>
<table><thead><tr><th>**Source IPActivityVerdict**</th><th></th><th></th></tr></thead><tbody>
<tr><td>`203.0.113.77`</td><td>Repeated failures followed by a successful SSH login and access to `/etc/shadow`</td><td>True Positive — Confirmed compromise</td></tr>
<tr><td>`198.51.100.23`</td><td>One external source targeting 11 different accounts</td><td>True Positive — Password-spray attempt</td></tr>
<tr><td>`10.20.14.9`</td><td>Internal backup service retrying an outdated password every 60 seconds</td><td>Benign Positive — Misconfigured backup job</td></tr>
<h2>Tools and Skills</h2>
<p><strong>SIEM and Cloud</strong></p>
<ul>
<li>Microsoft Sentinel</li>
<li>Azure Log Analytics</li>
<li>Azure Monitor Logs Ingestion API</li>
<li>Data Collection Endpoints and Data Collection Rules</li>
</ul>
<p><strong>Detection and Investigation</strong></p>
<ul>
<li>Kusto Query Language</li>
<li>Threat hunting</li>
<li>Scheduled analytics rules</li>
<li>Entity mapping and alert grouping</li>
<li>Incident triage and classification</li>
<li>Detection tuning</li>
<li>MITRE ATT&amp;CK mapping</li>
</ul>
<p><strong>Reporting and Visualisation</strong></p>
<ul>
<li>Microsoft Sentinel Workbooks</li>
<li>Evidence-based incident reporting</li>
<li>Remediation recommendations</li>
<li>Azure resource cleanup</li>
</ul>
<p><strong>Supporting Tools</strong></p>
<ul>
<li>PowerShell</li>
<li>Azure Cloud Shell</li>
<li>Git and GitHub</li>
</ul>
<h2>Architecture and Workflow</h2>
<p>The project followed the complete SOC lifecycle:</p>
<h3>Workflow</h3>
<ol>
<li>**Ingest** — Loaded the controlled SSH dataset into the custom `MeridianLogs_CL` table.</li>
<li>**Inspect** — Reviewed the raw fields and original authentication events.</li>
<li>**Hunt** — Used KQL to extract source IP addresses, usernames and authentication outcomes.</li>
<li>**Detect** — Created a scheduled rule for sources generating more than five failed SSH logins within a 10-minute window.</li>
<li>**Alert** — Mapped source IPs as entities and generated separate Sentinel incidents.</li>
<li>**Triage** — Investigated each incident to determine whether authentication succeeded and what occurred afterward.</li>
<li>**Classify** — Closed two incidents as true positives and one as a benign positive.</li>
<li>**Visualise** — Built a Sentinel workbook showing failed logins over time and the top source IPs.</li>
<li>**Report** — Documented the evidence, MITRE ATT&amp;CK mappings, remediation and detection limitations.</li>
<li>**Clean up** — Deleted the Azure resource group after preserving the project evidence.</li>
</ol>
<h2>What I Built</h2>
<ul>
<li>A Microsoft Sentinel deployment connected to an Azure Log Analytics workspace</li>
<li>A custom Log Analytics table containing SSH authentication activity</li>
<li>A Data Collection Endpoint and Data Collection Rule</li>
<li>Nine documented KQL threat-hunting and investigation queries</li>
<li>A scheduled brute-force analytics rule</li>
<li>IP entity mapping and alert grouping</li>
<li>Three fully investigated Sentinel incidents</li>
<li>A workbook dashboard for authentication monitoring</li>
<li>A detailed detection-and-response report</li>
<li>A redacted evidence set for portfolio publication</li>
</ul>
<h2>Data Ingestion Troubleshooting</h2>
<p>The original legacy ingestion script returned successful HTTP responses but did not populate the custom table.</p>
<p>To resolve the issue, I:</p>
<ol>
<li>Verified the workspace ID and destination table.</li>
<li>Confirmed that the custom table was provisioned successfully.</li>
<li>Tested ingestion with a single controlled record.</li>
<li>Migrated the table from classic ingestion to Data Collection Rule-based ingestion.</li>
<li>Created a Data Collection Endpoint and Data Collection Rule.</li>
<li>Assigned the required Azure role.</li>
<li>Authenticated to the Azure Monitor API.</li>
<li>Successfully ingested the dataset using the current Logs Ingestion API.</li>
</ol>
<p>This troubleshooting provided practical experience with Azure authentication, permissions, custom tables and modern log-ingestion pipelines.</p>
<h2>Detection Evidence</h2>
<h3>Suspicious Sources Identified</h3>
<p>The first hunting query grouped failed SSH authentication attempts by source IP. Three sources stood out significantly above the normal background activity.</p>
<h3>Scheduled Analytics Rule</h3>
<p>The hunting logic was converted into an enabled Microsoft Sentinel scheduled analytics rule with Medium severity.</p>
<h3>Incidents Generated</h3>
<p>The rule generated separate incidents for the three suspicious source IP addresses.</p>
<h3>Confirmed Account Compromise</h3>
<p>Investigation of <code>203.0.113.77</code> showed repeated failed authentication attempts followed by a successful SSH login to the <code>opsadmin</code> account.</p>
<p>The investigation also identified post-compromise access to the Linux password-hash file.</p>
<h3>Password-Spray Attempt</h3>
<p>The source <code>198.51.100.23</code> attempted authentication against 11 different usernames, with no successful login.</p>
<h3>Benign Backup-Service Activity</h3>
<p>The internal source <code>10.20.14.9</code> generated 30 failed attempts against <code>svc-backup</code>, with no successful authentication and an exact 60-second interval between attempts.</p>
<h3>Completed Incident Queue</h3>
<p>All primary incidents were investigated, classified, documented and closed.</p>
<h3>Sentinel Workbook</h3>
<p>A custom workbook was created to visualise failed SSH logins over time and rank the top source IP addresses.</p>
<h2>KQL Queries</h2>
<p>The complete KQL used during the project is available in the <a href="https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries"><code>queries</code></a> directory.</p>
<table><thead><tr><th>**FilePurpose**</th><th></th></tr></thead><tbody>
<tr><td>[`01-raw-log-inspection.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/01-raw-log-inspection.kql)</td><td>Inspect the custom table structure and sample raw events</td></tr>
<tr><td>[`02-failed-logins-by-ip.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/02-failed-logins-by-ip.kql)</td><td>Count and rank failed logins by source IP</td></tr>
<tr><td>[`03-brute-force-detection.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/03-brute-force-detection.kql)</td><td>Detect more than five failures within a 10-minute window</td></tr>
<table><thead><tr><th>[`04-confirmed-compromise-investigation.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/04-confirmed-compromise-investigation.kql)</th><th>Reconstruct failures followed by successful authentication</th></tr></thead><tbody>
<tr><td>[`05-post-compromise-shadow-access.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/05-post-compromise-shadow-access.kql)</td><td>Identify access to `/etc/shadow`</td></tr>
<tr><td>[`06-password-spray-investigation.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/06-password-spray-investigation.kql)</td><td>Extract usernames targeted by the password spray</td></tr>
<tr><td>[`07-benign-backup-investigation.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/07-benign-backup-investigation.kql)</td><td>Summarise the automated backup retry pattern</td></tr>
<table><thead><tr><th>[`08-failed-logins-over-time.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/08-failed-logins-over-time.kql)</th><th>Power the workbook authentication timeline</th></tr></thead><tbody>
<tr><td>[`09-top-source-ips.kql`](https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/queries/09-top-source-ips.kql)</td><td>Power the workbook source-IP ranking</td></tr>
<h2>Investigation Report</h2>
<p>The full detection-and-response report contains the incident evidence, analyst decisions, MITRE ATT&amp;CK mapping, remediation recommendations, detection limitations and lessons learned.</p>
<p><a href="https://github.com/Ahmad-Obeid7/Microsoft-sentinel-soc-lab/blob/main/report/detection-and-response-report.md">Read the full Detection and Response Report</a></p>
<h2>MITRE ATT&amp;CK Mapping</h2>
<table><thead><tr><th>**TechniqueNameProject Evidence**</th><th></th><th></th></tr></thead><tbody>
<tr><td>`T1110`</td><td>Brute Force</td><td>Repeated failed SSH logins against the `opsadmin` account</td></tr>
<tr><td>`T1110.003`</td><td>Password Spraying</td><td>One external IP attempted authentication against 11 different usernames</td></tr>
<tr><td>`T1078`</td><td>Valid Accounts</td><td>The attacker successfully authenticated using the `opsadmin` account</td></tr>
<table><thead><tr><th>`T1003.008`</th><th>OS Credential Dumping: `/etc/passwd` and `/etc/shadow`</th><th>The compromised account accessed `/etc/shadow` after authentication</th></tr></thead><tbody>
<h2>Detection Limitations</h2>
<p>The scheduled analytics rule was effective at identifying concentrated failed-login activity, but it has several limitations:</p>
<ul>
<li>Low-and-slow attacks may remain below the threshold of more than five failures within 10 minutes.</li>
<li>IP-based grouping may miss attackers who rotate source addresses.</li>
<li>Shared proxies or NAT gateways may cause multiple systems to appear under one source IP.</li>
<li>The rule does not independently determine whether activity is malicious or benign.</li>
<li>The rule does not directly correlate failed attempts with a later successful login.</li>
<li>The lab used a static imported dataset rather than a continuous production data connector.</li>
<li>Repeated evaluation of the same static records generated duplicate incidents.</li>
<li>The available telemetry was limited to one fictional Linux server.</li>
</ul>
<p>A production implementation should combine this rule with identity, endpoint, firewall, network and cloud audit logs.</p>
<h2>What I Would Improve in Production</h2>
<ul>
<li>Create a higher-severity rule for repeated failures followed by successful authentication.</li>
<li>Add a password-spray rule based on the number of unique accounts targeted by one source.</li>
<li>Add a low-and-slow detection using a longer analysis period.</li>
<li>Tune thresholds using historical authentication baselines.</li>
<li>Use continuous data connectors instead of manual log ingestion.</li>
<li>Add alert suppression and deduplication.</li>
<li>Correlate authentication events with process-execution and endpoint telemetry.</li>
<li>Enrich source IP entities with threat-intelligence information.</li>
<li>Automate containment actions only after appropriate validation.</li>
<li>Track detection performance using false-positive and false-negative reviews.</li>
</ul>
<h2>Repository Structure</h2>
<pre><code>microsoft-sentinel-soc-lab/
├── README.md
├── .gitignore
├── queries/
│   ├── 01-raw-log-inspection.kql
│   ├── 02-failed-logins-by-ip.kql
│   ├── 03-brute-force-detection.kql
│   ├── 04-confirmed-compromise-investigation.kql
│   ├── 05-post-compromise-shadow-access.kql
│   ├── 06-password-spray-investigation.kql
│   ├── 07-benign-backup-investigation.kql
│   ├── 08-failed-logins-over-time.kql
│   └── 09-top-source-ips.kql
├── report/
│   └── detection-and-response-report.md
└── screenshots/
    ├── 01-sentinel-enabled.png
    ├── 02-log-ingestion-confirmed.png
    ├── 03-raw-log-sample.png
    ├── 04-failed-logins-by-source-ip.png
    ├── 06-analytics-rule-enabled.png
    ├── 07-sentinel-incidents-generated.png
    ├── 08-incident-details-confirmed-compromise.png
    ├── 09-confirmed-compromise-success-login.png
    ├── 10-post-compromise-shadow-file-access.png
    ├── 11-confirmed-compromise-closed.png
    ├── 13-password-spray-evidence.png
    ├── 14-password-spray-closed.png
    ├── 15-incident-details-benign-backup.png
    ├── 16-benign-backup-job-evidence.png
    ├── 17-benign-backup-incident-closed.png
    ├── 18-incidents-triaged-and-closed.png
    ├── 19-sentinel-workbook-dashboard.png
    └── 20-resource-group-deleted.png
</code></pre>
<h2>Responsible Use and Attribution</h2>
<p>This project was completed in an authorised lab environment using a fictional banking scenario and controlled training data.</p>
<p>The original scenario and sample dataset were supplied through the MyFirstHack Mentorship Weekly Project 05 material. The Azure deployment, ingestion troubleshooting, KQL analysis, detection configuration, incident investigation, written report and redacted screenshots were completed as part of my own lab work.</p>
<p>The original dataset, training guide, ingestion scripts, credentials and unredacted evidence are not included in this repository.</p>
<h2>Cloud Cleanup</h2>
<p>After preserving the required project evidence, the Azure resource group was deleted.</p>
<p>This removed the Sentinel deployment, Log Analytics workspace, custom table, analytics rule, incidents, workbook, Data Collection Endpoint and Data Collection Rule.</p>
<h2>Key Takeaway</h2>
<p>The most important lesson from this project was that alert volume does not equal severity.</p>
<p>The highest-volume source was a benign backup process, while a lower-volume source successfully compromised an account and accessed sensitive credential data. Effective SOC analysis therefore requires evidence-based investigation, contextual reasoning and clear documentation rather than relying only on alert counts.</p>
</tbody></table>
</main></body>
</html>
