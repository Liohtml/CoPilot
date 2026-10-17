//! The monitoring-alert catalog — `AvailableMonitoringAlerts` and the
//! provisioning functions of `app/integrations/monitoring_alert/` as one
//! table.
//!
//! Every catalog alert but the two SOCFortress WAF ones is a Graylog event
//! definition built the same way (`provision_alert_definition` of a
//! `GraylogAlertProvisionModel`): an `aggregation-v1` search with no streams,
//! groups, series or condition, the window and interval from the request,
//! `event_limit` 1000, four template fields (`ALERT_ID` = `${source._id}`,
//! `CUSTOMER_CODE`, `ALERT_SOURCE`, `COPILOT_ALERT_ID` = `NONE`), no key spec,
//! grace period 0, no notifications, `alert` true. What the 49 Python
//! functions differ in is the data of a [`Definition`]; the WAF alerts are
//! `copilot-waf`'s ([`Kind::WafBlocked`], [`Kind::WafBruteForce`]).
//!
//! The rows are in the enum's declaration order, which is the order
//! `GET /available` lists them in and the order the `Invalid alert name`
//! message names them in. `monitoring_alert_vectors.json`
//! (`scripts/gen-monitoring-alert-vectors.py`) pins every row, and every body
//! built from it, to the Python module.

/// One catalog alert.
#[derive(Debug)]
pub struct Alert {
    /// The `AvailableMonitoringAlerts` member name (`WAZUH_SYSLOG_LEVEL_ALERT`).
    pub name: &'static str,
    /// The member's value: what `GET /available` shows.
    pub summary: &'static str,
    /// What provisioning it creates.
    pub kind: Kind,
}

/// What provisioning an alert creates.
#[derive(Debug)]
pub enum Kind {
    /// One Graylog event definition (`provision_alert_definition`).
    Definition(Definition),
    /// `SOCFORTRESS WAF BLOCKED` (`copilot_waf::alerts::provision_blocked_alert`).
    WafBlocked,
    /// `SOCFORTRESS WAF BRUTE FORCE`
    /// (`copilot_waf::alerts::provision_brute_force_alert`).
    WafBruteForce,
}

/// The data of one provisioning function's `GraylogAlertProvisionModel`.
#[derive(Debug)]
pub struct Definition {
    /// `title` (not always `name` with spaces: the existence check uses that).
    pub title: &'static str,
    /// `description`.
    pub description: &'static str,
    /// `config.query`.
    pub query: &'static str,
    /// `priority` (2 or 3).
    pub priority: i64,
    /// The `CUSTOMER_CODE` field's template.
    pub customer_code: &'static str,
    /// The `ALERT_SOURCE` field's template.
    pub source: &'static str,
}

impl Alert {
    /// `PINNED_TO_DEFAULT_GRAYLOG`: the WAF alerts ignore the requested
    /// Graylog instance.
    pub fn pinned_to_default_graylog(&self) -> bool {
        matches!(self.kind, Kind::WafBlocked | Kind::WafBruteForce)
    }
}

/// The catalog alert named `name` (a member name).
pub fn find(name: &str) -> Option<&'static Alert> {
    ALERTS.iter().find(|a| a.name == name)
}

/// The member names, in declaration order.
pub fn names() -> impl Iterator<Item = &'static str> {
    ALERTS.iter().map(|a| a.name)
}

/// `AvailableMonitoringAlerts`, in declaration order.
pub static ALERTS: &[Alert] = &[
    Alert {
        name: "WAZUH_SYSLOG_LEVEL_ALERT",
        summary: "This alert monitors the SYSLOG_LEVEL field in the Wazuh logs. When the level is ALERT, \
         it triggers an alert that is created within CoPilot. Ensure that you have a pipeline \
         rule that sets the SYSLOG_LEVEL field to ALERT when the Wazuh rule level is greater \
         than 11.",
        kind: Kind::Definition(Definition {
            title: "WAZUH SYSLOG LEVEL ALERT",
            description: "Alert on Wazuh syslog level equal to ALERT",
            query: "syslog_level:ALERT AND syslog_type:wazuh AND NOT (rule_group1:office365 OR \
             rule_group1:vulnerability-detector)",
            priority: 2,
            customer_code: "${source.agent_labels_customer}",
            source: "WAZUH",
        }),
    },
    Alert {
        name: "SURICATA_ALERT_SEVERITY_1",
        summary: "This alert monitors the Suricata logs. When an the alert_severity field is 1, it \
         triggers an alert that is created within CoPilot. Ensure that you have a pipeline rule \
         that sets ",
        kind: Kind::Definition(Definition {
            title: "SURICATA ALERT SEVERITY 1",
            description: "Alert on Suricata alerts",
            query: "alert_severity:1 AND syslog_type:suricata",
            priority: 2,
            customer_code: "${source.agent_labels_customer}",
            source: "SURICATA",
        }),
    },
    Alert {
        name: "OFFICE365_EXCHANGE_ONLINE",
        summary: "This alert monitors the Office365 Exchange events. When an alert is detected, it \
         triggers an alert that is created within CoPilot. Ensure that you have a pipeline rule \
         that sets the alert_severity field to 1 when the Office365 alert is detected.",
        kind: Kind::Definition(Definition {
            title: "OFFICE365 EXCHANGE ONLINE",
            description: "Alert on Office365 Exchange Online alerts",
            query: "syslog_level:ALERT AND data_office365_Subscription:Audit.Exchange",
            priority: 2,
            customer_code: "${source.data_office365_OrganizationId}",
            source: "OFFICE365_EXCHANGE_ONLINE",
        }),
    },
    Alert {
        name: "OFFICE365_THREAT_INTEL",
        summary: "This alert monitors the Office365 Threat Intelligence events. When an alert is \
         detected, it triggers an alert that is created within CoPilot. Ensure that you have a \
         pipeline rule that sets the alert_severity field to 1 when the Office365 alert is \
         detected.",
        kind: Kind::Definition(Definition {
            title: "OFFICE365 THREAT INTEL",
            description: "Alert on Office365 Threat Intel alerts",
            query: "syslog_level:ALERT AND data_office365_UserId:ThreatIntel AND NOT \
             data_office365_DeliveryAction:Blocked",
            priority: 2,
            customer_code: "${source.data_office365_OrganizationId}",
            source: "OFFICE365_THREAT_INTEL",
        }),
    },
    Alert {
        name: "SOCFORTRESS_WAF_BLOCKED",
        summary: "This alert monitors SOCFortress WAF events forwarded into the SIEM (Customers → WAF → \
         Set up event forwarding). Every request the WAF blocks creates a CoPilot alert titled \
         by the matched rule; repeated blocks for the same rule and customer are added to the \
         open alert, with each attacking IP as an IoC. Always provisioned on the default \
         Graylog, where WAF events are ingested.",
        kind: Kind::WafBlocked,
    },
    Alert {
        name: "SOCFORTRESS_WAF_BRUTE_FORCE",
        summary: "This alert fires when one IP has 30 or more requests blocked by a customer's \
         SOCFortress WAF within 5 minutes. Graylog delivers it to CoPilot's threshold route, so \
         ALERT_FORWARDING_IP and GRAYLOG_API_HEADER_VALUE must be set in CoPilot's environment. \
         Always provisioned on the default Graylog.",
        kind: Kind::WafBruteForce,
    },
    Alert {
        name: "CROWDSTRIKE_ALERT",
        summary: "This alert monitors the CrowdStrike events. When an alert is detected, it triggers an \
         alert that is created within CoPilot. Ensure that you have a pipeline rule that sets \
         the alert_severity field to 1 when the CrowdStrike alert is detected.",
        kind: Kind::Definition(Definition {
            title: "CROWDSTRIKE ALERT",
            description: "Alert on Crowdstrike alerts",
            query: "syslog_type:crowdstrike AND (syslog_level:Alert OR syslog_level:Warning)",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "CROWDSTRIKE",
        }),
    },
    Alert {
        name: "FORTINET_SYSTEM",
        summary: "This alert monitors the Fortinet System events. When an alert is detected, it triggers \
         an alert that is created within CoPilot. Ensure that you have a pipeline rule that sets \
         the alert_severity field to 1 when the Fortinet alert is detected.",
        kind: Kind::Definition(Definition {
            title: "FORTINET SYSTEM - CRITICAL EVENTS",
            description: "FORTINET SYSTEM - CRITICAL EVENTS",
            query: "syslog_type:fortinet AND subtype:system AND level:critical",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_UTM",
        summary: "This alert monitors the Fortinet UTM events. When an alert is detected, it triggers an \
         alert that is created within CoPilot. Ensure that you have a pipeline rule that sets \
         the alert_severity field to 1 when the Fortinet alert is detected.",
        kind: Kind::Definition(Definition {
            title: "FORTINET UTM - HIGH SEVERITY EVENTS",
            description: "FORTINET UTM - HIGH SEVERITY EVENTS",
            query: "syslog_type:fortinet AND type:utm AND (severity:high OR severity:critical) AND \
             !action:dropped AND !action:clear_session",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_FORTIWEB_PATH_TRAVERSAL_VULNERABILITY_EXPLOITATION_ATTEMPT",
        summary: "Detects potential exploitation attempts targeting CVE-2025-64446, a critical path \
         traversal vulnerability affecting Fortinet FortiWeb Web Application Firewalls (WAF). An \
         adversary can abuse this flaw, which requires no authentication, to create new, \
         unauthorized administrative user accounts on the exposed device. This provides the \
         threat actor with full administrative control over the security appliance, allowing \
         them to bypass security policies, neutralize the WAF, and establish a persistent \
         backdoor for further network intrusions.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - FORTIWEB PATH TRAVERSAL VULNERABILITY EXPLOITATION ATTEMPT",
            description: "FORTINET - FORTIWEB PATH TRAVERSAL VULNERABILITY EXPLOITATION ATTEMPT",
            query: "syslog_type:fortinet AND httpmethod:POST AND !action:blocked AND !action:block AND \
             !action:reset AND !action:drop AND !action:dropped AND (url:/\\/system\\/admin%3F/ \
             OR url:/\\/cgi\\-bin\\/fwbcgi/)",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_VALID_CLIENT_MISASSOCIATION_DETECTED",
        summary: "Detects when FortiGate Wireless IDS identifies an incident where a legitimate wireless \
         client associates with a rogue or unauthorized access point (AP), a behavior known as \
         valid client misassociation. Attackers may set up malicious APs to impersonate trusted \
         networks, tricking legitimate clients into connecting. This tactic is commonly used in \
         evil twin attacks to intercept traffic, harvest credentials, or inject malicious \
         payloads. Identifying such associations is essential to safeguarding wireless network \
         integrity and preventing data leakage.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS VALID CLIENT MISASSOCIATION DETECTED",
            description: "FORTINET - WIDS WIRELESS VALID CLIENT MISASSOCIATION DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless valid_client_misassoc detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_MANAGEMENT_FLOODING_DETECTED",
        summary: "Detects when FortiGate Wireless IDS identifies abnormal surges of wireless management \
         frames, such as authentication, association, or probe requests, which may indicate a \
         management frame flooding attack. Adversaries use this technique to disrupt wireless \
         network operations, exhaust access point resources, or perform denial-of-service (DoS) \
         attacks. Continuous monitoring of management frame activity helps with the early \
         identification and mitigation of wireless network disruptions.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS MANAGEMENT FLOODING DETECTED",
            description: "FORTINET - WIDS WIRELESS MANAGEMENT FLOODING DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless management flooding detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_EAPOL_PACKET_FLOODING_DETECTED",
        summary: "Detects a flood of EAPOL (Extensible Authentication Protocol over LAN) packets on the \
         wireless network identified by FortiGate Wireless IDS. Such flooding can exhaust \
         network resources, disrupt normal authentication processes, or exploit weaknesses in \
         WPA/WPA2 handshakes. Monitoring for this behavior is crucial to maintaining secure and \
         stable wireless authentication services in enterprise environments.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS EAPOL PACKET FLOODING DETECTED",
            description: "FORTINET - WIDS WIRELESS EAPOL PACKET FLOODING DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless EAPOL packet flooding detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_ROGUE_ACCESS_POINT_DETECTED",
        summary: "Detects the rogue access point (AP) in the network as reported by FortiGate Wireless \
         IDS. Rogue APs are unauthorized wireless access points connected to a network, often \
         used by attackers to bypass security controls, capture sensitive data, or conduct \
         man-in-the-middle attacks. Detection of rogue APs is critical to maintaining wireless \
         network integrity and preventing unauthorized access.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS ROGUE ACCESS POINT DETECTED",
            description: "FORTINET - WIDS ROGUE ACCESS POINT DETECTED",
            query: "syslog_type:fortinet AND (logdesc:\"Rogue AP detected\" OR logdesc:\"Rogue AP \
             activity\" OR logdesc:\"Rogue AP on air\" OR logdesc:\"Fake AP on air\" OR \
             logdesc:\"Fake AP detected\" OR logdesc:\"Offending AP on air\" OR \
             logdesc:\"Offending AP detected\")",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_LONG_DURATION_ATTACK_DETECTED",
        summary: "Detects a long duration attack on the wireless network identified by FortiGate Wireless \
         IDS. These attacks often involve persistent connections to rogue access points or the \
         use of compromised clients to maintain unauthorized access over an extended period. \
         Such activity may be used by adversaries for sustained data exfiltration, network \
         reconnaissance, or to establish footholds in the environment. Monitoring these patterns \
         is crucial to detecting stealthy and persistent wireless threats.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS LONG DURATION ATTACK DETECTED",
            description: "FORTINET - WIDS WIRELESS LONG DURATION ATTACK DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless long duration attack detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_FIREWALL_VIRUS_DETECTED",
        summary: "Detects the virus in the network identified by FortiGate Firewall. This may indicate \
         the presence of malware or a malicious file attempting to execute or transfer within \
         the network. Threat actors may use malware to gain access, maintain persistence, or \
         exfiltrate data. Monitoring such events can help identify compromised systems or \
         prevent further infection spread.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - FIREWALL VIRUS DETECTED",
            description: "FORTINET - FIREWALL VIRUS DETECTED",
            query: "syslog_type:fortinet AND subtype:\"virus\" AND !action:\"blocked\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_THREAT_DETECTED",
        summary: "Detects potential wireless-based security threats as identified by FortiGate Wireless \
         IDS. These threats may include spoofed access points, EAPOL flooding, deauthentication \
         attacks, or other suspicious wireless behaviors. Monitoring such events is critical to \
         protecting against wireless intrusion attempts, maintaining the integrity of the Wi-Fi \
         network, and preventing unauthorized access or denial-of-service conditions caused by \
         malicious actors.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS THREAT DETECTED",
            description: "FORTINET - WIDS WIRELESS THREAT DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless threat detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_INVALID_MAC_OUI_DETECTED",
        summary: "Detects instances where a FortiGate Wireless IDS identifies a client with an invalid or \
         unrecognized MAC Organizationally Unique Identifier (OUI). This may indicate the \
         presence of unauthorized, rogue, or potentially malicious devices attempting to connect \
         to the wireless network. Monitoring for invalid MAC OUIs helps strengthen network \
         access controls and prevent unauthorized access.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS INVALID MAC OUI DETECTED",
            description: "FORTINET - WIDS WIRELESS INVALID MAC OUI DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless invalid MAC OUI detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_ASLEAP_ATTACK_DETECTED",
        summary: "Detects the presence of an Asleap attack in a wireless network identified by FortiGate \
         Wireless IDS. Asleap is a tool used to exploit weak authentication in LEAP (Lightweight \
         Extensible Authentication Protocol), potentially allowing attackers to capture and \
         crack wireless credentials. Monitoring for this activity helps identify unauthorized \
         attempts to compromise wireless network security and protect sensitive credentials.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS ASLEAP ATTACK DETECTED",
            description: "FORTINET - WIDS WIRELESS ASLEAP ATTACK DETECTED",
            query: "syslog_type:fortinet AND logdesc:\"Wireless Asleap attack detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_IPS_MALICIOUS_URL_DETECTED",
        summary: "Detects when FortiGate Intrusion Prevention System (IPS) identifies access to a known \
         malicious URL. This activity may indicate attempts to connect to command and control \
         infrastructure, deliver malware, or exfiltrate data. Monitoring these detections helps \
         identify potential threats, prevent compromise, and maintain network security.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - IPS MALICIOUS URL DETECTED",
            description: "FORTINET - IPS MALICIOUS URL DETECTED",
            query: "syslog_type:fortinet AND subtype:\"ips\" AND attack:\"malicious-url\" AND \
             action:\"detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_IPS_BOTNET_ACTIVITY_DETECTED",
        summary: "Detects botnet-related activity identified by FortiGate Intrusion Prevention System \
         (IPS). This may indicate that a host within the network is communicating with known \
         botnet command and control servers or exhibiting behavior consistent with botnet \
         infections. Monitoring these events helps identify compromised systems, prevent data \
         exfiltration, and mitigate the spread of malicious activity within the environment.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - IPS BOTNET ACTIVITY DETECTED",
            description: "FORTINET - IPS BOTNET ACTIVITY DETECTED",
            query: "syslog_type:fortinet AND subtype:\"ips\" AND attack:\"botnet\" AND action:\"detected\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_ADMIN_USER_CREATED_FROM_PUBLIC_IP",
        summary: "Detects the creation of a new administrator user account on a Fortinet FortiGate device \
         originating from a public IP address. An adversary who gains access to the management \
         interface may create unauthorized admin accounts to establish persistent, privileged \
         control over the firewall. By creating these accounts from external or atypical network \
         locations, attackers can maintain long-term access, modify security policies, \
         exfiltrate sensitive data, or prepare the environment for additional malicious activity.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - ADMIN USER CREATED FROM PUBLIC IP",
            description: "FORTINET - ADMIN USER CREATED FROM PUBLIC IP",
            query: "syslog_type:fortinet AND subtype:\"system\" AND logdesc:\"Object attribute \
             configured\" AND action:\"Add\" AND cfgpath:\"system.admin\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_SUSPICIOUS_CONFIG_FILE_ACCESS_FROM_EXTERNAL_NETWORK",
        summary: "Detects attempts to download a FortiGate configuration file from an external or \
         publicly accessible network source. Adversaries may abuse this behavior to obtain \
         sensitive configuration data, including administrative credentials, network topology \
         details, VPN settings, or firewall policies. Access to this information can enable \
         further compromise through targeted lateral movement, privilege escalation, or tailored \
         exploitation of exposed services.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - SUSPICIOUS CONFIG FILE ACCESS FROM EXTERNAL NETWORK",
            description: "FORTINET - SUSPICIOUS CONFIG FILE ACCESS FROM EXTERNAL NETWORK",
            query: "syslog_type:fortinet AND msg:\"System config file has been downloaded\" AND \
             status:\"success\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_WIDS_WIRELESS_WEAK_ENCRYPTION_DETECTED",
        summary: "Detects wireless access points using weak or deprecated encryption protocols, as \
         reported by FortiGate Wireless IDS. Risky encryption methods, such as WEP or \
         misconfigured WPA settings, may allow adversaries to eavesdrop on network traffic or \
         perform cryptographic attacks to gain unauthorized access. Identifying and remediating \
         such vulnerabilities is essential to ensure wireless network confidentiality and \
         compliance with security best practices.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - WIDS WIRELESS WEAK ENCRYPTION DETECTED",
            description: "FORTINET - WIDS WIRELESS WEAK ENCRYPTION DETECTED",
            query: "syslog_type:fortinet AND (logdesc:\"Wireless risky_encryption detected\" OR \
             logdesc:\"Wireless Weak WEP IV detected\")",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "FORTINET_SUSPICIOUS_SUPER_ADMIN_LOGIN_DETECTED",
        summary: "Detects a super admin login attempt to a FortiGate firewall originating from a \
         suspicious or public IP address. This may indicate an attempt to exploit CVE-2025-24472 \
         which allows unauthenticated attackers to gain super admin privileges on vulnerable \
         FortiOS devices (<7.0.16) with exposed management interfaces.",
        kind: Kind::Definition(Definition {
            title: "FORTINET - SUSPICIOUS SUPER ADMIN LOGIN DETECTED",
            description: "FORTINET - SUSPICIOUS SUPER ADMIN LOGIN DETECTED",
            query: "syslog_type:fortinet AND subtype:\"system\" AND logdesc:\"Admin login successful\" \
             AND profile:\"super_admin\" AND method:\"jsconsole\" AND status:\"success\" AND \
             srcip_reserved_ip:false",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "FORTINET",
        }),
    },
    Alert {
        name: "PALOALTO_ALERT",
        summary: "This alert monitors the PaloAlto events. When an alert is detected, it triggers an \
         alert that is created within CoPilot. Ensure that you have a pipeline rule that sets \
         the alert_severity field to 1 when the PaloAlto alert is detected.",
        kind: Kind::Definition(Definition {
            title: "PALO ALTO - HIGH SEVERITY EVENTS",
            description: "PALO ALTO - HIGH SEVERITY EVENTS",
            query: "syslog_type:palo_alto AND event_log_name:THREAT AND (vendor_alert_severity:high OR \
             vendor_alert_severity:critical) AND !vendor_event_action:drop",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "PALOALTO",
        }),
    },
    Alert {
        name: "PALOALTO_FIREWALL_TRAFFIC_TO_PHISHING_URL_ALLOWED",
        summary: "Detects when the Palo Alto Networks firewall does not block traffic to a URL known to \
         be used in phishing attacks. An adversary can abuse this by directing victims to the \
         phishing site, potentially stealing credentials, deploying malware, or conducting other \
         malicious activities.",
        kind: Kind::Definition(Definition {
            title: "PALOALTO - FIREWALL TRAFFIC TO PHISHING URL ALLOWED",
            description: "Detects when the Palo Alto Networks firewall does not block traffic to a URL known \
             to be used in phishing attacks. An adversary can abuse this by directing victims to \
             the phishing site, potentially stealing credentials, deploying malware, or \
             conducting other malicious activities.",
            query: "syslog_type:palo_alto_fw AND event_log_name:THREAT AND pan_log_subtype:url AND \
             alert_category:phishing AND (event_severity:critical OR event_severity:high OR \
             event_severity:medium) AND !vendor_event_action:deny AND !vendor_event_action:drop \
             AND !vendor_event_action:reset AND !vendor_event_action:block",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "PALOALTO",
        }),
    },
    Alert {
        name: "PALOALTO_FIREWALL_TRAFFIC_TO_MALICIOUS_URL_ALLOWED",
        summary: "Detects when the Palo Alto Networks firewall does not block traffic to a URL associated \
         with malware distribution or operation. This typically indicates a lapse in the \
         firewall's threat intelligence or a misconfiguration. An adversary can abuse this by \
         using the unblocked URL to download malware onto a target system, establish a command \
         and control channel, or exfiltrate data.",
        kind: Kind::Definition(Definition {
            title: "PALOALTO - FIREWALL TRAFFIC TO MALICIOUS URL ALLOWED",
            description: "Detects when the Palo Alto Networks firewall does not block traffic to a URL \
             associated with malware distribution or operation. This typically indicates a lapse \
             in the firewall's threat intelligence or a misconfiguration. An adversary can abuse \
             this by using the unblocked URL to download malware onto a target system, establish \
             a command and control channel, or exfiltrate data.",
            query: "syslog_type:palo_alto_fw AND event_log_name:THREAT AND pan_log_subtype:url AND \
             alert_category:malware AND (event_severity:critical OR event_severity:high OR \
             event_severity:medium) AND !vendor_event_action:deny AND !vendor_event_action:drop \
             AND !vendor_event_action:reset AND !vendor_event_action:block",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "PALOALTO",
        }),
    },
    Alert {
        name: "PALOALTO_FIREWALL_VIRUS_ALLOWED",
        summary: "Detects active network communication associated with known malware that is being \
         allowed by the Palo Alto Networks firewall. This may indicate an ongoing security \
         threat, where malicious traffic is bypassing firewall protections, potentially leading \
         to system compromise, data exfiltration, or further infiltration within the network.",
        kind: Kind::Definition(Definition {
            title: "PALOALTO - FIREWALL VIRUS ALLOWED",
            description: "Detects active network communication associated with known malware that is being \
             allowed by the Palo Alto Networks firewall. This may indicate an ongoing security \
             threat, where malicious traffic is bypassing firewall protections, potentially \
             leading to system compromise, data exfiltration, or further infiltration within the \
             network.",
            query: "syslog_type:palo_alto_fw AND event_log_name:THREAT AND pan_log_subtype:virus AND \
             !vendor_event_action:deny AND !vendor_event_action:drop AND \
             !vendor_event_action:reset AND !vendor_event_action:block",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "PALOALTO",
        }),
    },
    Alert {
        name: "PALOALTO_FIREWALL_TOR_TRAFFIC_ALLOWED",
        summary: "Detects allowed network traffic to the TOR network. Adversaries can use TOR to \
         anonymize their network activity, bypass security controls, and evade detection while \
         conducting malicious operations. This could lead to unauthorized access, data \
         exfiltration, and compliance violations if deemed malicious.",
        kind: Kind::Definition(Definition {
            title: "PALOALTO - FIREWALL TOR TRAFFIC ALLOWED",
            description: "Detects allowed network traffic to the TOR network. Adversaries can use TOR to \
             anonymize their network activity, bypass security controls, and evade detection \
             while conducting malicious operations. This could lead to unauthorized access, data \
             exfiltration, and compliance violations if deemed malicious.",
            query: "syslog_type:palo_alto_fw AND event_log_name:TRAFFIC AND application_name:tor AND \
             vendor_event_action:allow",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "PALOALTO",
        }),
    },
    Alert {
        name: "PALOALTO_FIREWALL_MEDIUM_SEVERITY_CORRELATION_EVENT_DETECTED",
        summary: "Detects medium severity correlation events generated by Palo Alto Networks firewall's \
         automated correlation engine. The correlation engine connects isolated network events \
         and looks for patterns that indicate a more significant event. This helps identify \
         suspicious traffic patterns and network anomalies which, when correlated, indicate with \
         a high probability that a host on the network has been compromised.",
        kind: Kind::Definition(Definition {
            title: "PALOALTO - FIREWALL MEDIUM SEVERITY CORRELATION EVENT DETECTED",
            description: "Detects medium severity correlation events generated by Palo Alto Networks \
             firewall's automated correlation engine. The correlation engine connects isolated \
             network events and looks for patterns that indicate a more significant event. This \
             helps identify suspicious traffic patterns and network anomalies which, when \
             correlated, indicate with a high probability that a host on the network has been \
             compromised.",
            query: "syslog_type:palo_alto_fw AND event_log_name:CORRELATION AND \
             vendor_alert_severity:medium",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "PALOALTO",
        }),
    },
    Alert {
        name: "SENTINELONE_NEW_ACTIVE_THREAT_MALICIOUS_DETECTED",
        summary: "Threat with confidence level malicious detected",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - NEW ACTIVE THREAT MALICIOUS DETECTED",
            description: "Threat with confidence level malicious detected",
            query: "syslog_type:sentinelone AND cat:MALWARE AND threatConfidenceLevel:malicious",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_NEW_ACTIVE_THREAT_SUSPICIOUS_DETECTED",
        summary: "Threat with confidence level suspicious detected",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - NEW ACTIVE THREAT SUSPICIOUS DETECTED",
            description: "Threat with confidence level suspicious detected",
            query: "syslog_type:sentinelone AND cat:MALWARE AND threatConfidenceLevel:suspicious",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_NEW_MITIGATION_KILL_PERFORMED_SUCCESSFULLY",
        summary: "Kill performed successfully",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - NEW MITIGATION KILL PERFORMED SUCCESSFULLY",
            description: "Kill performed successfully",
            query: "syslog_type:sentinelone AND cat:MITIGATION AND eventDesc:\"Kill performed \
             successfully\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_NEW_MITIGATION_QUARANTINE_PERFORMED_SUCCESSFULLY",
        summary: "Quarantine performed successfully",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - NEW MITIGATION QUARANTINE PERFORMED SUCCESSFULLY",
            description: "Quarantine performed successfully",
            query: "syslog_type:sentinelone AND cat:MITIGATION AND eventDesc:\"Quarantine performed \
             successfully\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_NEW_EXCLUSION_WAS_ADDED_OR_MODIFIED_BY_USER",
        summary: "Exclusion was added/modified by user",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - NEW EXCLUSION WAS ADDED OR MODIFIED BY USER",
            description: "Exclusion was added/modified by user",
            query: "syslog_type:sentinelone AND cat:WHITELISTBLACKLIST AND eventDesc:\"Exclusion was \
             added/modified by user\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_NEW_PATH_EXCLUSION_ADDED",
        summary: "Path Exclusion added",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - NEW PATH EXCLUSION ADDED",
            description: "Path Exclusion added",
            query: "syslog_type:sentinelone AND cat:WHITELISTBLACKLIST AND eventDesc:\"Path Exclusion \
             added\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_ANALYST_VERDICT_CHANGED_TO_TRUE_POSITIVE",
        summary: "A management user changed the analyst verdict to \"True Positive\".",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - ANALYST VERDICT CHANGED TO \"TRUE POSITIVE\"",
            description: "A management user changed the analyst verdict to True positive.",
            query: "syslog_type:sentinelone AND cat:THREATMANAGEMENT AND \
             data_newAnalystVerdict:true_positive",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "SENTINELONE_ANALYST_VERDICT_CHANGED_TO_FALSE_POSITIVE",
        summary: "A management user changed the analyst verdict to \"False Positive\".",
        kind: Kind::Definition(Definition {
            title: "SENTINELONE - ANALYST VERDICT CHANGED TO \"FALSE POSITIVE\"",
            description: "A management user changed the analyst verdict to False Positive.",
            query: "syslog_type:sentinelone AND cat:THREATMANAGEMENT AND \
             data_newAnalystVerdict:false_positive",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "SENTINELONE",
        }),
    },
    Alert {
        name: "MIMECAST_COMPROMISED_SITE_URL_ACCESSED",
        summary: "Detects user clicks on compromised websites classified by Mimecast, which were \
         delivered via email. Adversaries can exploit these links to direct users to malicious \
         sites hosting malware, phishing pages, or spam content.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - COMPROMISED SITE URL ACCESSED",
            description: "MIMECAST - COMPROMISED SITE URL ACCESSED",
            query: "integration:mimecast AND (category:\"Compromised\" OR category:\"Botnets\" OR \
             category:\"Attacker Controlled Infrastructure\") AND !action:\"hold\" AND \
             !action:\"block\" AND !action:\"bounce\" AND !actions:\"Hold\" AND \
             !actions:\"Block\" AND !adminOverride:\"Hold\" AND !adminOverride:\"Block\" AND \
             !adminOverride:\"Bounce\"",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_EXECUTABLE_FILE_ATTACHMENT_DELIVERED",
        summary: "Detects emails containing executable file attachments that have been delivered to a \
         user's mailbox, as identified by Mimecast. An adversary can abuse this delivery method \
         to distribute malicious payloads, including malware, ransomware, or other executables \
         designed to compromise the recipient's system.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - EXECUTABLE FILE ATTACHMENT DELIVERED",
            description: "MIMECAST - EXECUTABLE FILE ATTACHMENT DELIVERED",
            query: "integration:mimecast AND (Route:\"Inbound\" OR Dir:\"Inbound\" OR \
             route:\"inbound\") AND (file_type:\"application/x-dosexec\" OR \
             file_type:\"application/x-msdownload\" OR file_type:\"application/x-executable\" OR \
             file_type:\"application/vnd.microsoft.portable-executable\") AND \
             !actionTriggered:\"Hold\" AND !actionTriggered:\"Block\" AND \
             !actionTriggered:\"Bounce\"",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_MALICIOUS_EMAIL_ATTACHMENT_DELIVERED",
        summary: "Detects emails containing malicious attachments identified by Mimecast that have been \
         delivered to a user's mailbox. Attackers commonly use spearphishing emails with \
         malicious attachments to compromise systems by tricking recipients into opening them.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - MALICIOUS EMAIL ATTACHMENT DELIVERED",
            description: "MIMECAST - MALICIOUS EMAIL ATTACHMENT DELIVERED",
            query: "integration:mimecast AND scanResult:\"malicious\" AND (Route:\"Inbound\" OR \
             Dir:\"Inbound\" OR route:\"inbound\") AND !actionTriggered:\"Hold\" AND \
             !actionTriggered:\"Block\" AND !actionTriggered:\"Bounce\"",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_MALICIOUS_EMAIL_LINK_ACCESSED",
        summary: "Detects instances where users click on malicious URLs embedded in emails. These URLs \
         may redirect to phishing sites, initiate malware downloads, or enable advanced threats, \
         posing risks to user and organizational security.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - MALICIOUS EMAIL LINK ACCESSED",
            description: "MIMECAST - MALICIOUS EMAIL LINK ACCESSED",
            query: "integration:mimecast AND scanResult:\"malicious\" AND !action:\"block\"",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_P2P_FILE_SHARING_URL_ACCESSED",
        summary: "Detects a user clicking on a peer-to-peer file sharing URL, as classified by Mimecast, \
         that was delivered via email. Adversaries can abuse P2P file-sharing platforms to \
         distribute malicious files, such as malware, ransomware, or unauthorized software, by \
         embedding these links in phishing emails.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - P2P FILE SHARING URL ACCESSED",
            description: "MIMECAST - P2P FILE SHARING URL ACCESSED",
            query: "integration:mimecast AND category:\"Peer-to-Peer\" AND !action:\"hold\" AND \
             !action:\"block\" AND !action:\"bounce\" AND !actions:\"Hold\" AND \
             !actions:\"Block\" AND !adminOverride:\"Hold\" AND !adminOverride:\"Block\" AND \
             !adminOverride:\"Bounce\"",
            priority: 3,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_ANONYMIZER_URL_ACCESSED",
        summary: "Detects user clicks on anonymizer URLs classified by Mimecast that arrived in an email. \
         An adversary can abuse anonymizer services to mask their identity and hide the origin \
         of malicious traffic, making it harder to trace their activities.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - ANONYMIZER URL ACCESSED",
            description: "MIMECAST - ANONYMIZER URL ACCESSED",
            query: "integration:mimecast AND category:\"Anonymizers\" AND !action:\"hold\" AND \
             !action:\"block\" AND !action:\"bounce\" AND !actions:\"Hold\" AND \
             !actions:\"Block\" AND !adminOverride:\"Hold\" AND !adminOverride:\"Block\" AND \
             !adminOverride:\"Bounce\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_IMPERSONATION_EMAIL_DELIVERED",
        summary: "Detects unblocked email messages flagged by Mimecast as potential impersonation \
         attempts. These emails are strong indicators of Business Email Compromise (BEC), a \
         sophisticated phishing tactic in which attackers impersonate trusted entities to \
         deceive recipients.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - IMPERSONATION EMAIL DELIVERED",
            description: "MIMECAST - IMPERSONATION EMAIL DELIVERED",
            query: "integration:mimecast AND taggedMalicious:true AND !action:\"hold\" AND \
             !action:\"block\" AND !action:\"bounce\" AND !actions:\"Hold\" AND \
             !actions:\"Block\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_MALICIOUS_OUTBOUND_EMAIL",
        summary: "Detects outbound emails identified by Mimecast as malicious, including those containing \
         phishing links, malware-laden attachments, or other suspicious content. Monitoring \
         these events is crucial in identifying potential account compromises or unauthorized \
         activities aimed at distributing threats to external recipients.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - MALICIOUS OUTBOUND EMAIL",
            description: "MIMECAST - MALICIOUS OUTBOUND EMAIL",
            query: "integration:mimecast AND Dir:\"Outbound\" AND category:\"Malware\" AND \
             scanResult:\"malicious\" AND !action:\"hold\" AND !action:\"block\" AND \
             !action:\"bounce\" AND !actions:\"Hold\" AND !actions:\"Block\" AND \
             !adminOverride:\"Hold\" AND !adminOverride:\"Block\" AND !adminOverride:\"Bounce\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_MALICIOUS_RTF_ATTACHMENT_DELIVERED",
        summary: "Detects emails containing malicious rtf file attachments identified by Mimecast that \
         have been delivered to a user's mailbox. Adversaries can abuse malicious RTF files to \
         exploit vulnerabilities in applications that process these files, potentially executing \
         arbitrary code or delivering malware.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - MALICIOUS RTF ATTACHMENT DELIVERED",
            description: "MIMECAST - MALICIOUS RTF ATTACHMENT DELIVERED",
            query: "integration:mimecast AND scanResult:\"malicious\" AND fileName:/\\.rtf$/ AND \
             !actionTriggered:\"Hold\" AND !actionTriggered:\"Block\" AND \
             !actionTriggered:\"Bounce\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_PHISHING_EMAIL_DELIVERED",
        summary: "Detects unblocked email messages flagged as phishing by Mimecast, indicating their \
         successful delivery to recipients' mailboxes. Such emails may contain malicious \
         attachments, URLs, or deceptive content.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - PHISHING EMAIL DELIVERED",
            description: "MIMECAST - PHISHING EMAIL DELIVERED",
            query: "integration:mimecast AND category:\"Phishing & Fraud\" AND (Route:\"Inbound\" OR \
             Dir:\"Inbound\" OR route:\"inbound\") AND !action:\"hold\" AND !action:\"block\" \
             AND !action:\"bounce\" AND !actions:\"Hold\" AND !actions:\"Block\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_SOURCE_CODE_FILE_IN_EMAIL_ATTACHMENT",
        summary: "Detects the presence of source code files in email attachments by analyzing Mimecast \
         email logs. This activity may indicate potential insider threats, as internal users \
         could be attempting to exfiltrate sensitive or proprietary information.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - SOURCE CODE FILE IN EMAIL ATTACHMENT",
            description: "MIMECAST - SOURCE CODE FILE IN EMAIL ATTACHMENT",
            query: "integration:mimecast AND (AttNames:/\\.py$/ OR AttNames:/\\.java$/ OR \
             AttNames:/\\.c$/ OR AttNames:/\\.cs$/ OR AttNames:/\\.cpp$/ OR AttNames:/\\.jsp$/ \
             OR AttNames:/\\.vba$/ OR AttNames:/\\.class$/)",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
    Alert {
        name: "MIMECAST_URL_WITH_DANGEROUS_FILE_TYPE_ACCESSED",
        summary: "Detects user clicks on URLs containing dangerous file types, as classified by Mimecast, \
         that were delivered via email. Adversaries often use emails with embedded URLs linking \
         to files with extensions commonly associated with malware, such as .exe, .bat, .js, or \
         .msi.",
        kind: Kind::Definition(Definition {
            title: "MIMECAST - URL WITH DANGEROUS FILE TYPE ACCESSED",
            description: "MIMECAST - URL WITH DANGEROUS FILE TYPE ACCESSED",
            query: "integration:mimecast AND category:\"Dangerous file extension\" AND !action:\"hold\" \
             AND !action:\"block\" AND !action:\"bounce\" AND !actions:\"Hold\" AND \
             !actions:\"Block\" AND !adminOverride:\"Hold\" AND !adminOverride:\"Block\" AND \
             !adminOverride:\"Bounce\"",
            priority: 2,
            customer_code: "${source.syslog_customer}",
            source: "MIMECAST",
        }),
    },
];
