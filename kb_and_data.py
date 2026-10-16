
import random

CATEGORIES = ["account_access", "email_m365", "network_vpn", "hardware", "software",
              "security_incident", "cloud_azure", "backup_storage", "printing", "data_bi"]
PRIORITIES = ["P1", "P2", "P3", "P4"]

# ---------------------------------------------------------------- knowledge base
KB = [
 ("KB-001","account_access","Password reset and account lockout","1) Confirm the user's identity via the approved verification steps. 2) Unlock the account in Entra ID / Active Directory. 3) Issue a temporary password and force change at next sign-in. 4) Check for repeated lockouts from an old phone or mapped drive using stale credentials."),
 ("KB-002","account_access","MFA reset and new device enrolment","1) Verify identity. 2) In Entra ID > Authentication methods, require re-register MFA. 3) User signs in and registers Microsoft Authenticator on the new phone. 4) Remove the old device from the user's registered methods."),
 ("KB-003","email_m365","Outlook not syncing or profile corrupt","1) Check Microsoft 365 service health. 2) Run Outlook in safe mode and disable add-ins. 3) Remove and re-add the mail profile. 4) Rebuild the OST file. 5) If only one mailbox is affected, check mailbox size and licence."),
 ("KB-004","email_m365","Missing email, quarantine and mail flow","1) Run a message trace in Exchange admin centre. 2) Check Defender quarantine and release if legitimate. 3) Review inbox rules and forwarding. 4) Verify SPF, DKIM and DMARC if external senders are affected. 5) Check shared mailbox permissions."),
 ("KB-005","network_vpn","VPN will not connect","1) Confirm the user's internet connection and credentials. 2) Check the VPN gateway status and licence/user limit on the firewall. 3) Reinstall or update the VPN client. 4) Check MFA prompt delivery. 5) Review firewall logs for blocked or geo-blocked attempts."),
 ("KB-006","network_vpn","Network or Wi-Fi drops, slow or no connectivity","1) Identify scope: one user, one site, or all sites. 2) Check switch and access point status in the monitoring tool. 3) Test DNS and DHCP. 4) Check ISP circuit and failover link. 5) If a site is down, escalate to the network team immediately."),
 ("KB-007","hardware","Laptop slow, freezing or will not boot","1) Check disk space, CPU and memory in Task Manager. 2) Apply pending Windows updates and restart. 3) Run hardware diagnostics. 4) Check disk health (SMART). 5) If failing, arrange a loan device and re-image."),
 ("KB-008","hardware","Monitor, docking station or headset not working","1) Reseat cables and test another port. 2) Update dock and graphics drivers. 3) Test with a known-good peripheral. 4) Raise a hardware replacement through the supplier if faulty."),
 ("KB-009","software","Software installation or access request","1) Check the request has manager approval. 2) Confirm a licence is available. 3) Deploy via Intune / Software Centre. 4) Add the user to the correct application group. 5) Confirm with the user and close."),
 ("KB-010","software","Application crashing or licence not activating","1) Capture the error message and app version. 2) Repair or reinstall the application. 3) Clear the cached licence and sign in again. 4) Check the licence assignment in the admin portal. 5) Check compatibility after recent updates."),
 ("KB-011","security_incident","Reported phishing email","1) Do NOT click links or open attachments. 2) Have the user report it using the Report Message button. 3) Search the tenant for the same message and purge it. 4) Check whether anyone clicked or entered credentials; if so, reset the password and revoke sessions. 5) Notify the security team."),
 ("KB-012","security_incident","Suspected malware or ransomware","1) Isolate the device from the network immediately (do not power off if ransomware is suspected). 2) Escalate to the security operations team as a P1 incident. 3) Preserve logs and evidence. 4) Identify the scope using EDR. 5) Begin the incident response plan and notify the client's nominated contact."),
 ("KB-013","cloud_azure","Azure VM or web app unavailable","1) Check Azure Service Health for the region. 2) Check VM status, recent deployments and resource health. 3) Review the NSG and firewall rules for recent changes. 4) Restart the VM or app service if safe. 5) Escalate to the cloud team if production is affected."),
 ("KB-014","cloud_azure","Azure permissions, role access or cost alert","1) Identify the subscription and resource group. 2) Review role assignments (RBAC) and PIM eligibility. 3) For cost alerts, review Cost Analysis for the spike and look for idle or oversized resources. 4) Apply tags and budget alerts."),
 ("KB-015","backup_storage","Backup job failed","1) Check the backup console for the error code. 2) Verify agent status and free space on the target. 3) Check network connectivity to the repository. 4) Re-run the job manually. 5) If repeated failures, escalate as the client may have no valid recovery point."),
 ("KB-016","backup_storage","File restore or shared drive full","1) Confirm the file path and the date it was last good. 2) Restore from the backup or previous versions. 3) For a full drive, find the largest folders and archive or extend the volume. 4) Confirm the restore with the user."),
 ("KB-017","printing","Printer offline or print queue stuck","1) Check the printer is on the network and has a valid IP. 2) Clear the print queue and restart the Print Spooler service. 3) Reinstall the printer driver. 4) Check the print server status if multiple users are affected."),
 ("KB-018","printing","Scan to email or scan to folder failing","1) Check the SMTP relay settings and credentials on the device. 2) Verify the destination folder permissions. 3) Test with a different user. 4) Check the firewall is not blocking the SMTP relay."),
 ("KB-019","data_bi","Power BI dataset refresh failed","1) Open the refresh history and read the error. 2) Check data source credentials and gateway status. 3) Check source database availability. 4) Re-run the refresh. 5) If a schema changed, update the query in Power Query."),
 ("KB-020","data_bi","Power BI report access or gateway problem","1) Check the user's licence (Pro/PPU) and workspace role. 2) Share the report or app with the user's group. 3) Check the on-premises data gateway is online and updated. 4) Apply row-level security mapping if data is missing."),
]
KB_BY_ID = {k[0]: k for k in KB}

# symptom phrases: (kb_id, [phrasings]) -- the second item of each tuple is ticket text
SYMPTOMS = {
 "KB-001": ["I forgot my password and cannot log in", "my account is locked out again after the weekend", "password expired and the reset page gives an error", "keeps saying incorrect password but I know it is right"],
 "KB-002": ["got a new phone and the authenticator app no longer works", "not receiving the MFA code when signing in", "need my multi factor reset, old mobile was lost", "authenticator keeps asking for approval but nothing arrives"],
 "KB-003": ["outlook is stuck on updating inbox and wont sync", "outlook keeps crashing when I open it", "emails not coming through to outlook on my laptop but fine on phone", "outlook asking for password over and over"],
 "KB-004": ["an email from a customer never arrived, can you trace it", "emails going to junk or quarantine from a supplier", "cannot see the shared mailbox in outlook", "mail to external clients is bouncing back"],
 "KB-005": ["VPN wont connect from home", "vpn client says connection timed out", "cannot connect to the vpn since the update last night", "vpn connects then drops after a few minutes"],
 "KB-006": ["internet is very slow in the office", "wifi keeps dropping on the second floor", "no network connection on my desk port", "cannot reach any internal websites, dns issue maybe"],
 "KB-007": ["laptop is extremely slow and freezes", "laptop wont boot, stuck on the black screen", "pc keeps restarting by itself", "laptop battery drains in an hour and it gets hot"],
 "KB-008": ["second monitor not detected via the dock", "headset microphone not working in teams", "docking station not charging the laptop", "keyboard and mouse intermittently disconnecting"],
 "KB-009": ["please can you install Adobe Acrobat on my machine", "new starter needs access to the CRM and Visio", "request to install python for the data team", "need Project installed, manager has approved"],
 "KB-010": ["excel crashes every time I open a large file", "office says product not activated", "the accounting software throws an error on startup", "application will not launch after the latest windows update"],
 "KB-011": ["received a suspicious email asking me to confirm my bank details", "got an email that looks like phishing pretending to be the CEO", "clicked a link in an email and entered my password, now worried", "strange email with a zip attachment from unknown sender"],
 "KB-012": ["antivirus popup says malware detected on my laptop", "files have extensions changed and cant be opened, ransom note on desktop", "computer is showing lots of pop ups and running strangely, might be a virus", "EDR alert: unknown process encrypting files on server"],
 "KB-013": ["the azure web app is returning 503 errors", "our VM in azure is unreachable over RDP", "the customer portal hosted in azure is down", "azure app service keeps restarting"],
 "KB-014": ["I need contributor access to the azure subscription", "unexpected cost alert on our azure account this month", "cannot see the resource group in azure portal", "need to set up a budget alert in azure"],
 "KB-015": ["last night's backup failed with an error", "backup job has been failing for three days", "veeam reports a warning on the file server backup", "no successful backup recorded for the sql server"],
 "KB-016": ["I accidentally deleted a folder from the shared drive, can you restore it", "shared drive is full and no one can save files", "need to recover an old version of a spreadsheet", "restore request for the finance folder from last week"],
 "KB-017": ["printer shows offline", "print jobs stuck in the queue", "cannot print to the third floor printer", "printer prints blank pages"],
 "KB-018": ["scan to email stopped working on the copier", "scan to folder says access denied", "scanner sends nothing to my inbox", "multi function device cannot send scans"],
 "KB-019": ["power bi refresh failed this morning", "the sales dashboard has not updated since yesterday", "scheduled refresh error credentials invalid", "dataset refresh keeps timing out"],
 "KB-020": ["cannot open the power bi report, says no access", "gateway is offline in power bi", "numbers missing in the report for my region", "need access to the finance workspace in power bi"],
}

OPENERS = ["Hi,", "Hello team,", "Hi support,", "Good morning,", "Urgent:", "Hey,", "", "", "Hi there,", "Afternoon,", "Hello,"]
CLOSERS = ["Thanks", "Thanks in advance", "Please advise", "Cheers", "Regards", "", "", "Let me know", "Thank you"]
SCOPE = {
 "P1": ["Everyone in the office is affected.", "This is affecting all users.", "Production is down and customers cannot use the service.", "Whole site is impacted.", "Business critical, the entire team is stopped."],
 "P2": ["Several of us have the same problem.", "My whole team cannot work at the moment.", "Finance has a deadline today.", "Cannot do my job at all right now.", "Impacting a few colleagues."],
 "P3": ["It's just me.", "Happens intermittently.", "I have a workaround for now.", "Not blocking me but annoying.", "Only on my machine."],
 "P4": ["No rush.", "When you get a chance.", "Not urgent at all.", "Whenever convenient.", "Low priority."],
}
BASE_PRIO = {  # prior over priorities per category
 "security_incident": [0.35,0.35,0.2,0.1], "cloud_azure": [0.25,0.3,0.3,0.15], "backup_storage": [0.15,0.3,0.35,0.2],
 "network_vpn": [0.2,0.3,0.35,0.15], "email_m365": [0.08,0.27,0.45,0.2], "account_access": [0.03,0.27,0.5,0.2],
 "hardware": [0.03,0.17,0.5,0.3], "software": [0.02,0.13,0.4,0.45], "printing": [0.03,0.17,0.5,0.3], "data_bi": [0.05,0.25,0.4,0.3],
}
KB_CAT = {k[0]: k[1] for k in KB}

def _typo(s, rng, p=0.04):
    out = []
    for i, ch in enumerate(s):
        r = rng.random()
        if ch.isalpha() and r < p / 2 and i > 0:
            continue                      # drop char
        if ch.isalpha() and r > 1 - p / 2:
            out.append(ch + ch); continue  # double char
        out.append(ch)
    return "".join(out)

SYN = {"cannot": ["can't", "unable to", "not able to", "cant"], "laptop": ["notebook", "machine", "pc", "work laptop"],
       "email": ["e-mail", "mail", "message"], "emails": ["mails", "messages"], "printer": ["printer", "copier", "mfd", "office printer"],
       "wont": ["will not", "refuses to", "doesn't"], "not working": ["has stopped", "is broken", "is down", "fails"],
       "slow": ["sluggish", "crawling", "laggy"], "access": ["permission", "rights"], "install": ["set up", "deploy", "add"],
       "azure": ["azure", "our cloud tenant", "azure"], "files": ["documents", "data"], "stopped working": ["died", "packed up"]}

def augment(text, rng):
    for k, vs in SYN.items():
        if k in text and rng.random() < 0.5:
            text = text.replace(k, rng.choice(vs), 1)
    return text

def make_ticket(rng):
    kb = rng.choice(list(SYMPTOMS))
    cat = KB_CAT[kb]
    pr = rng.choices(PRIORITIES, weights=BASE_PRIO[cat])[0]
    sym = rng.choice(SYMPTOMS[kb])
    # 15% vague tickets: symptom stated minimally
    if rng.random() < 0.15:
        sym = rng.choice(["it's not working", "having issues again", "something is wrong", "problem with " + cat.split("_")[0]]) + ", " + sym.split(",")[0][:25]
    parts = [rng.choice(OPENERS), sym[0].upper() + sym[1:] + ".", rng.choice(SCOPE[pr]) if rng.random() < 0.85 else "", rng.choice(CLOSERS)]
    text = " ".join(p for p in parts if p).strip()
    if rng.random() < 0.6:
        text = augment(text, rng)
    if rng.random() < 0.5:
        text = _typo(text, rng)
    if rng.random() < 0.25:
        text = text.lower()
    # label noise: ~2% category swapped, ~8% priority shifted by one (human inconsistency)
    label_cat = cat
    if rng.random() < 0.02:
        label_cat = rng.choice(CATEGORIES)
    if rng.random() < 0.08:
        i = PRIORITIES.index(pr) + rng.choice([-1, 1]); pr = PRIORITIES[min(3, max(0, i))]
    return {"text": text, "category": label_cat, "priority": pr, "kb_id": kb}

def generate(n=3000, seed=42):
    rng = random.Random(seed)
    return [make_ticket(rng) for _ in range(n)]

# Hand-written tickets in different wording than the generator templates, used as an
# out-of-template robustness check. (text, category, priority, kb_id)
HAND_TESTSET = [
 ("Can't get into my account after returning from holiday, says it's disabled", "account_access", "P3", "KB-001"),
 ("Our new starter Priya begins Monday, she needs a laptop login and email created", "account_access", "P4", "KB-001"),
 ("Got a new iPhone, how do I move my Microsoft sign-in codes across?", "account_access", "P3", "KB-002"),
 ("MD has lost his phone and is travelling, he cannot approve any sign in prompts", "account_access", "P2", "KB-002"),
 ("Outlook says disconnected since this morning for the whole sales team", "email_m365", "P2", "KB-003"),
 ("my calendar is not showing meetings that were accepted yesterday", "email_m365", "P3", "KB-003"),
 ("A client says they emailed our accounts mailbox on Tuesday but we never received it", "email_m365", "P3", "KB-004"),
 ("Newsletter emails keep landing in quarantine, please whitelist the sender", "email_m365", "P4", "KB-004"),
 ("Remote staff cannot reach the file server over the VPN, started 10 minutes ago, about 40 people", "network_vpn", "P1", "KB-005"),
 ("GlobalProtect keeps giving me gateway not found error at home", "network_vpn", "P3", "KB-005"),
 ("Our Belfast branch has completely lost internet", "network_vpn", "P1", "KB-006"),
 ("Wi-Fi in meeting room 2 is awful and video calls keep freezing", "network_vpn", "P3", "KB-006"),
 ("My laptop screen has gone black but the power light is on", "hardware", "P3", "KB-007"),
 ("Laptop takes 15 minutes to start and fan is loud, getting worse each week", "hardware", "P3", "KB-007"),
 ("My HDMI output through the USB-C hub only shows one display now", "hardware", "P4", "KB-008"),
 ("Webcam is not detected by Teams anymore", "hardware", "P3", "KB-008"),
 ("Would it be possible to get Visual Studio Code installed? Approved by Sam.", "software", "P4", "KB-009"),
 ("Could I get a Zoom licence for the marketing team please", "software", "P4", "KB-009"),
 ("Word closes without warning every time I try to save to SharePoint", "software", "P3", "KB-010"),
 ("Adobe says my subscription has expired but we renewed last month", "software", "P3", "KB-010"),
 ("I think I just gave my Microsoft password to a fake login page", "security_incident", "P1", "KB-011"),
 ("Delivery company email asking to pay a customs fee, looks dodgy, I did not click", "security_incident", "P3", "KB-011"),
 ("Our file server shows all documents renamed .locked and there is a text file demanding bitcoin", "security_incident", "P1", "KB-012"),
 ("Sophos quarantined a trojan on the reception PC", "security_incident", "P2", "KB-012"),
 ("Customer-facing website hosted on Azure gives gateway timeout for all visitors", "cloud_azure", "P1", "KB-013"),
 ("Dev VM in Azure won't start, deployment blocked", "cloud_azure", "P2", "KB-013"),
 ("Our Azure bill doubled this month, can someone find out why?", "cloud_azure", "P3", "KB-014"),
 ("Need reader access to the prod subscription for an auditor", "cloud_azure", "P4", "KB-014"),
 ("Nightly Azure Backup alerts show failures on the ERP server for 4 days", "backup_storage", "P2", "KB-015"),
 ("Backup report is red for the Thatcham site", "backup_storage", "P3", "KB-015"),
 ("Deleted the wrong version of the budget file on the S drive, need it back from Monday", "backup_storage", "P3", "KB-016"),
 ("The Q drive is at 100%, nobody can save anything", "backup_storage", "P2", "KB-016"),
 ("The HP in accounts keeps saying error and won't print anything", "printing", "P3", "KB-017"),
 ("Whole floor cannot print since lunchtime", "printing", "P2", "KB-017"),
 ("Photocopier scan to my email gives authentication failed", "printing", "P4", "KB-018"),
 ("Scans no longer arrive in the shared HR folder", "printing", "P3", "KB-018"),
 ("The board pack dashboard still shows last month's figures", "data_bi", "P2", "KB-019"),
 ("Report refresh failing with 'could not connect to data source'", "data_bi", "P3", "KB-019"),
 ("New analyst cannot see the operations workspace in Power BI", "data_bi", "P4", "KB-020"),
 ("Power BI says gateway is not reachable, all scheduled reports stalled", "data_bi", "P2", "KB-020"),
]
