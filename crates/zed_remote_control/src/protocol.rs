use serde::{Deserialize, Serialize};

/// Events sent from Zed to the relay server (tap output).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum TapEvent {
    /// A new project/thread became active.
    #[serde(rename = "thread.opened")]
    ThreadOpened {
        project: String,
        thread_id: String,
    },

    /// A thread was closed/deactivated.
    #[serde(rename = "thread.closed")]
    ThreadClosed {
        project: String,
        thread_id: String,
    },

    /// List of all active projects.
    #[serde(rename = "projects.list")]
    ProjectsList { projects: Vec<String> },

    /// A new entry was added to a thread.
    #[serde(rename = "entry.new")]
    EntryNew {
        project: String,
        thread_id: String,
        index: usize,
        entry: EntryData,
    },

    /// An existing entry was updated (e.g., streaming text append).
    #[serde(rename = "entry.updated")]
    EntryUpdated {
        project: String,
        thread_id: String,
        index: usize,
        entry: EntryData,
    },

    /// The agent turn completed.
    #[serde(rename = "thread.stopped")]
    ThreadStopped {
        project: String,
        thread_id: String,
    },

    /// Thread title changed.
    #[serde(rename = "thread.title_changed")]
    TitleChanged {
        project: String,
        thread_id: String,
        title: String,
    },

    /// Token usage update.
    #[serde(rename = "thread.token_usage")]
    TokenUsage {
        project: String,
        thread_id: String,
        input_tokens: Option<u64>,
        output_tokens: Option<u64>,
    },
}

/// Serializable representation of a thread entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum EntryData {
    #[serde(rename = "user_message")]
    UserMessage { text: String },

    #[serde(rename = "assistant_message")]
    AssistantMessage { text: String, has_thinking: bool },

    #[serde(rename = "tool_call")]
    ToolCall {
        tool_name: Option<String>,
        status: String,
        input: Option<serde_json::Value>,
        output: Option<serde_json::Value>,
    },
}

/// Messages sent from the relay server to Zed (inbound commands).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RelayCommand {
    /// Send a prompt to a specific project's active thread.
    #[serde(rename = "prompt")]
    Prompt { project: String, text: String },
}
