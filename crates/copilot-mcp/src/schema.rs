//! `schema/copilot_mcp.py` and the tables of `services/example_questions.py`
//! (`ExampleQuestionsService._SERVER_INFO`, `_EXAMPLE_QUESTIONS`), with the
//! routing of `services/copilot_mcp.py` (`MCPService._SERVER_CONFIGS`).

use copilot_auth::pyvalue::PyValue;
use copilot_upstream::model::{EnumTy, Field, Model, Ty};

/// `MCPServerType`, in declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    /// `wazuh-indexer`.
    WazuhIndexer,
    /// `wazuh-manager`.
    WazuhManager,
    /// `copilot`.
    Copilot,
    /// `velociraptor`.
    Velociraptor,
    /// `threat-intel`.
    ThreatIntel,
    /// `cyber-news`.
    CyberNews,
    /// `knowledgebase`.
    Knowledgebase,
    /// `attack-surface`.
    AttackSurface,
}

/// Every server, in `MCPServerType`'s order.
pub const ALL: [Server; 8] = [
    Server::WazuhIndexer,
    Server::WazuhManager,
    Server::Copilot,
    Server::Velociraptor,
    Server::ThreatIntel,
    Server::CyberNews,
    Server::Knowledgebase,
    Server::AttackSurface,
];

/// `MCPServerType` for Pydantic (`Input should be 'wazuh-indexer', …`).
pub static SERVER_ENUM: EnumTy = EnumTy {
    name: "MCPServerType",
    values: &[
        "wazuh-indexer",
        "wazuh-manager",
        "copilot",
        "velociraptor",
        "threat-intel",
        "cyber-news",
        "knowledgebase",
        "attack-surface",
    ],
};

impl Server {
    /// The enum value.
    pub fn value(self) -> &'static str {
        match self {
            Server::WazuhIndexer => "wazuh-indexer",
            Server::WazuhManager => "wazuh-manager",
            Server::Copilot => "copilot",
            Server::Velociraptor => "velociraptor",
            Server::ThreatIntel => "threat-intel",
            Server::CyberNews => "cyber-news",
            Server::Knowledgebase => "knowledgebase",
            Server::AttackSurface => "attack-surface",
        }
    }

    /// `MCPServerType(value)`.
    pub fn from_value(value: &str) -> Option<Self> {
        ALL.iter().copied().find(|s| s.value() == value)
    }

    /// `MCPService._SERVER_CONFIGS[server]`: whether it is a cloud service,
    /// and its endpoint under the deployment's base.
    pub fn config(self) -> (bool, &'static str) {
        match self {
            Server::WazuhIndexer => (false, "opensearch-query"),
            Server::WazuhManager => (false, "wazuh-query"),
            Server::Copilot => (false, "mysql-query"),
            Server::Velociraptor => (false, "velociraptor-query"),
            Server::ThreatIntel => (true, "threat_intel"),
            Server::CyberNews => (true, "cyber_news"),
            Server::Knowledgebase => (true, "knowledgebase"),
            Server::AttackSurface => (true, "attack_surface"),
        }
    }
}

/// `MCPQueryRequest` (its `mcp_server` validator is the caller's: an
/// unknown string is an `HTTPException`).
pub static MCP_QUERY_REQUEST: Model = Model::new(
    "MCPQueryRequest",
    &[
        Field::req("input", Ty::Str),
        Field::req("mcp_server", Ty::Enum(&SERVER_ENUM)),
        Field::def("verbose", Ty::Nullable(&Ty::Bool), || PyValue::Bool(true)),
    ],
);

/// One `MCPServerInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerInfo {
    /// `name`.
    pub name: &'static str,
    /// `value`.
    pub value: &'static str,
    /// `description`.
    pub description: &'static str,
    /// `capabilities`.
    pub capabilities: &'static [&'static str],
}

impl ServerInfo {
    /// `model_dump()`.
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("name".into(), PyValue::Str(self.name.into())),
            ("value".into(), PyValue::Str(self.value.into())),
            ("description".into(), PyValue::Str(self.description.into())),
            (
                "capabilities".into(),
                PyValue::List(
                    self.capabilities
                        .iter()
                        .map(|c| PyValue::Str((*c).into()))
                        .collect(),
                ),
            ),
        ])
    }
}

/// One `ExampleQuestion` (every one of the tables has a description and a
/// category).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Question {
    /// `question`.
    pub question: &'static str,
    /// `description`.
    pub description: &'static str,
    /// `category`.
    pub category: &'static str,
}

impl Question {
    /// `model_dump()`.
    pub fn dump(&self) -> PyValue {
        PyValue::Dict(vec![
            ("question".into(), PyValue::Str(self.question.into())),
            ("description".into(), PyValue::Str(self.description.into())),
            ("category".into(), PyValue::Str(self.category.into())),
        ])
    }
}

/// `get_server_info(server)`.
pub fn server_info(server: Server) -> Option<&'static ServerInfo> {
    SERVERS.iter().find(|s| s.value == server.value())
}

/// `get_available_categories(server)`: the distinct categories, sorted.
pub fn categories(server: Server) -> Vec<&'static str> {
    let set: std::collections::BTreeSet<&str> = questions(server)
        .iter()
        .map(|q| q.category)
        .filter(|c| !c.is_empty())
        .collect();
    set.into_iter().collect()
}

/// `ExampleQuestionsService._SERVER_INFO`, in its order.
pub const SERVERS: &[ServerInfo] = &[
    ServerInfo {
        name: "CoPilot",
        value: "copilot",
        description: "Query customer data, alerts, incidents, and analytics from the CoPilot platform",
        capabilities: &[
            "Customer management queries",
            "Alert analysis and filtering",
            "Incident tracking and trends",
            "Security analytics and reporting",
            "Dashboard data retrieval",
        ],
    },
    ServerInfo {
        name: "Wazuh Manager",
        value: "wazuh-manager",
        description: "Interact with Wazuh Manager for agent management, security monitoring, and endpoint analysis",
        capabilities: &[
            "Agent status monitoring",
            "Endpoint security scanning",
            "Software inventory management",
            "Network port analysis",
        ],
    },
    ServerInfo {
        name: "Wazuh Indexer",
        value: "wazuh-indexer",
        description: "Query the Wazuh Indexer for log analysis, search operations, and cluster health monitoring",
        capabilities: &[
            "Log data search and analysis",
            "Index management and statistics",
            "Cluster health monitoring",
            "Vulnerability assessment",
        ],
    },
    ServerInfo {
        name: "Velociraptor",
        value: "velociraptor",
        description: "Digital forensics and incident response platform for endpoint monitoring and threat hunting",
        capabilities: &[
            "Live endpoint forensics",
            "Artifact collection and analysis",
            "Process and network monitoring",
            "Persistence mechanism detection",
            "Lateral movement hunting",
            "Browser artifact collection",
            "Hardware device tracking",
        ],
    },
    ServerInfo {
        name: "Threat Intel",
        value: "threat-intel",
        description: "Access threat intelligence data, such as IP reputation scores and malware indicators",
        capabilities: &[
            "Threat intelligence lookups",
            "IP and domain reputation scoring",
            "File hash and URL analysis",
        ],
    },
    ServerInfo {
        name: "Cyber News",
        value: "cyber-news",
        description: "Access the latest news and updates related to cyber threats and vulnerabilities",
        capabilities: &["Vulnerability disclosure tracking"],
    },
    ServerInfo {
        name: "Knowledgebase",
        value: "knowledgebase",
        description: "Access documentation and guides for using CoPilot and its integrations",
        capabilities: &[
            "Configuration guides",
            "Best practices",
            "Troubleshooting tips",
        ],
    },
    ServerInfo {
        name: "Attack Surface",
        value: "attack-surface",
        description: "Analyze and manage the attack surface of your organization",
        capabilities: &[
            "Attack surface mapping",
            "Exposure management",
            "Risk assessment",
        ],
    },
];

/// `ExampleQuestionsService._EXAMPLE_QUESTIONS`: each server's questions.
pub fn questions(server: Server) -> &'static [Question] {
    match server {
        Server::WazuhIndexer => &[
            Question {
                question: "What is the cluster health status?",
                description: "Check the overall health and status of the Wazuh indexer cluster",
                category: "health",
            },
            Question {
                question: "What are the most critical vulnerabilities for `agent_name`: endpoint123 from the index pattern `wazuh-states-vulnerabilities-*`??",
                description: "Get critical vulnerabilities for a specific agent from the Wazuh index",
                category: "vulnerabilities",
            },
            Question {
                question: "Has the agent named `agent_name` made any dns requests to `evil.com` within the index pattern `wazuh-customerA*`?",
                description: "Search for DNS requests made by a specific agent to a known malicious domain",
                category: "search",
            },
            Question {
                question: "Has the agent named `agent_name` had any rule_group3 `authentication_failed` within the index name: `wazuh-customerA*`?",
                description: "Check for authentication failures in a specific index for a given agent",
                category: "search",
            },
            Question {
                question: "How much diskspace is the `wazuh-customerA*` indices consuming?",
                description: "Get the disk space usage for all indices related to customerA",
                category: "indexing",
            },
        ],
        Server::WazuhManager => &[
            Question {
                question: "What is the status of agent endpoint123?",
                description: "Check the current operational status of a specific Wazuh agent",
                category: "agents",
            },
            Question {
                question: "What are the SCA findings for endpoint123?",
                description: "Retrieve the Software Composition Analysis (SCA) findings for a specific endpoint",
                category: "agents",
            },
            Question {
                question: "What are the open ports on endpoint123?",
                description: "List all open network ports detected on a specific endpoint",
                category: "network",
            },
            Question {
                question: "What software is installed on endpoint123?",
                description: "Get inventory of installed software packages on an endpoint",
                category: "inventory",
            },
            Question {
                question: "Show me all disconnected agents",
                description: "List agents that are currently offline or disconnected",
                category: "agents",
            },
            Question {
                question: "Do I have any sysmon event 1 detection rules?",
                description: "Check for specific security rules related to Sysmon event 1",
                category: "rules",
            },
        ],
        Server::Copilot => &[
            Question {
                question: "How many alerts do I have for customerA?",
                description: "Get the total count of alerts for a specific customer",
                category: "alerts",
            },
            Question {
                question: "What customer has the highest number of alerts?",
                description: "Find the customer with the most alerts in the system",
                category: "alerts",
            },
            Question {
                question: "Show me spotted iocs for customerA",
                description: "Retrieve recent high-priority security alerts",
                category: "alerts",
            },
            Question {
                question: "What are the top 5 most common alert sources?",
                description: "Analyze alert patterns to identify frequent security events",
                category: "analytics",
            },
            Question {
                question: "How many active customers do we have?",
                description: "Get the count of currently active customers in the system",
                category: "customers",
            },
            Question {
                question: "Show me agents status for customerA",
                description: "Display agents status.",
                category: "agents",
            },
        ],
        Server::Velociraptor => &[
            Question {
                question: "What users have logged onto endpoint123 in the last 30 days?",
                description: "List all users who have logged onto a specific endpoint within the last 30 days",
                category: "users",
            },
            Question {
                question: "List all network connections on endpoint123",
                description: "Display active and recent network connections from an endpoint",
                category: "network",
            },
            Question {
                question: "What artifacts are available for checking browser activity?",
                description: "Show available artifacts for browser activity analysis",
                category: "artifacts",
            },
            Question {
                question: "What scheduled tasks exist on endpoint123?",
                description: "List all scheduled tasks for persistence analysis",
                category: "persistence",
            },
            Question {
                question: "Find all executables in the Downloads folder across all endpoints",
                description: "Hunt for potentially suspicious executable files in user download directories",
                category: "hunting",
            },
            Question {
                question: "Show me the startup programs on endpoint DESKTOP-ABC123",
                description: "List programs that start automatically with the system",
                category: "persistence",
            },
            Question {
                question: "What browser artifacts can I collect from endpoint DESKTOP-ABC123?",
                description: "Gather web browser history, downloads, and other forensic artifacts",
                category: "artifacts",
            },
        ],
        Server::ThreatIntel => &[
            Question {
                question: "What is the IP reputation for 8.8.8.8?",
                description: "Retrieve the IP reputation for a specific IP address",
                category: "threat_intel",
            },
            Question {
                question: "What is the domain analysis for example.com?",
                description: "Get threat intelligence data for a specific domain",
                category: "threat_intel",
            },
            Question {
                question: "What is the file hash analysis for 1234567890abcdef1234567890abcdef?",
                description: "Analyze a file hash for malware or other threats",
                category: "threat_intel",
            },
        ],
        Server::CyberNews => &[
            Question {
                question: "What are the latest cyber threat headlines?",
                description: "Retrieve the most recent headlines related to cyber threats",
                category: "cyber_news",
            },
            Question {
                question: "What vulnerabilities were disclosed this week?",
                description: "Get a list of vulnerabilities that were made public in the last week",
                category: "cyber_news",
            },
            Question {
                question: "Who are the top threat actors currently?",
                description: "Identify the most active threat actors based on recent intelligence",
                category: "cyber_news",
            },
        ],
        Server::Knowledgebase => &[
            Question {
                question: "How would I configure the Office365 API Integration?",
                description: "Configure the Office365 API Integration for optimal performance",
                category: "knowledgebase",
            },
            Question {
                question: "How can I create a new index set in Graylog?",
                description: "Get best practices for creating index sets in Graylog",
                category: "knowledgebase",
            },
            Question {
                question: "How do I upgrade CoPilot?",
                description: "Follow these steps to upgrade your CoPilot installation",
                category: "knowledgebase",
            },
        ],
        Server::AttackSurface => &[
            Question {
                question: "Search for breaches related to email example@company.com",
                description: "Explore data breaches involving the specified email address",
                category: "attack_surface",
            },
            Question {
                question: "Search for exposures regarding service.example.com",
                description: "Explore data exposures involving the specified service",
                category: "attack_surface",
            },
            Question {
                question: "Has the password `password123` been exposed?",
                description: "Check if a specific password has been involved in any data breaches",
                category: "attack_surface",
            },
        ],
    }
}
