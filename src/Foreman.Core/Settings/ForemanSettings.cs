namespace Foreman.Core.Settings;

public sealed class ForemanSettings
{
    public int McpPort { get; set; } = 54321;
    public int HangThresholdMinutes { get; set; } = 10;
    public int HookJamThresholdMinutes { get; set; } = 5;

    /// <summary>
    /// After a hang alert for a process, suppress further hang alerts for that same PID for this many
    /// minutes — even if its I/O briefly resumes and it idles again. Stops a bursty-I/O child (language
    /// server, file watcher, MCP helper) from re-firing a "no I/O" alert on every idle stretch. 0 = no
    /// cooldown (re-arm immediately on each new silent episode).
    /// </summary>
    public int HangRealertCooldownMinutes { get; set; } = 60;
    public int IoPollerIntervalSeconds { get; set; } = 30;
    public int AlertSuppressWindowMinutes { get; set; } = 5;
    public bool NotifyOnHang { get; set; } = true;
    public bool NotifyOnOrphan { get; set; } = true;
    public bool NotifyOnCriticalCommand { get; set; } = true;
    public bool MonitorAllProcesses { get; set; } = false; // false = harness children only

    /// <summary>
    /// Opt-in: launch an elevated, capture-only ETW sidecar so the Process Monitor can show
    /// per-process Network throughput. Off by default — only the sidecar runs elevated; the main
    /// app (UI, MCP server, kill action) stays at medium integrity. Toggling it on prompts UAC.
    /// </summary>
    public bool RunElevated { get; set; } = false;

    /// <summary>
    /// Opt-in (Tier 1): periodically connect to the HTTP/SSE MCP servers your harnesses use,
    /// enumerate their tools, and scan the tool names + descriptions for prompt-injection / data-
    /// exfil text. Off by default — this is the only feature that makes outbound network connections
    /// to third-party servers. stdio servers are never launched (we don't spawn what we're auditing).
    /// </summary>
    public bool ScanMcpTools { get; set; } = false;

    public string ProfilesDirectory { get; set; } =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Foreman", "profiles");

    /// <summary>
    /// Harness IDs (matching KnownHarnesses.All[].Id, or "custom:exename.exe") that
    /// should not be monitored.  Foreman still detects them for status display purposes
    /// but will not emit hang/orphan/permission alerts for disabled harnesses.
    /// </summary>
    public HashSet<string> DisabledHarnesses { get; set; } = [];

    /// <summary>
    /// User-added process exe names to treat as harnesses (e.g. "myagent.exe").
    /// Stored lower-case; the classifier matches them case-insensitively.
    /// </summary>
    public List<string> CustomHarnessExes { get; set; } = [];

    // ── Escalation thresholds ────────────────────────────────────────────────

    /// <summary>Medium-severity alerts before escalating to Alert level (per harness session).</summary>
    public int AlertLevelMediumCount { get; set; } = 3;

    /// <summary>High-severity alerts before escalating to Alarm level.</summary>
    public int AlarmLevelHighCount { get; set; } = 2;

    /// <summary>Unique rule IDs fired before escalating to Alarm level.</summary>
    public int AlarmLevelUniqueRules { get; set; } = 5;

    /// <summary>Distinct threat categories touched before escalating to Alarm level.</summary>
    public int AlarmLevelCategories { get; set; } = 3;

    /// <summary>Total alerts from one harness before escalating to Emergency level.</summary>
    public int EmergencyLevelTotalAlerts { get; set; } = 10;

    /// <summary>
    /// Rule IDs that unconditionally trigger Emergency escalation (no count threshold).
    /// Covers the most dangerous single-action patterns: credential dumping, ransomware
    /// indicators, remote code execution, UAC bypass, and administrator escalation.
    /// </summary>
    public string[] EmergencyRuleIds { get; set; } =
    [
        // Credential theft
        "cred-004",   // mimikatz
        "cred-005",   // LSASS dump
        "cred-018",   // DCSync / AD attack
        "cred-019",   // lateral movement (CrackMapExec / Impacket)

        // Ransomware indicators
        "win-009",    // VSS shadow copy deletion (windows-specific)
        "priv-003",   // VSS deletion (privilege-escalation duplicate pattern)

        // Remote code execution
        "net-001",    // curl|bash
        "net-002",    // PowerShell IEX from web
        "net-005",    // Python reverse shell
        "net-008",    // mshta remote HTA
        "net-009",    // regsvr32 Squiblydoo

        // Privilege escalation
        "priv-002",   // add user to Administrators group
        "priv-004",   // disable Windows Defender
        "priv-008",   // UAC bypass via fodhelper/eventvwr
        "priv-010",   // modify sudoers (NOPASSWD)
    ];

    public LlmTriageSettings LlmTriage { get; set; } = new();
}

public sealed class LlmTriageSettings
{
    public bool Enabled { get; set; } = true;
    public bool PreventSelfAudit { get; set; } = true;
    public int MaxEventsPerReview { get; set; } = 20;
    public List<AuditorPreference> AuditorPreferences { get; set; } =
    [
        new()
        {
            AuditorId = "codex",
            AuditorType = "harness",
            DisplayName = "Codex CLI",
            TargetHarnessIds = ["claude-code", "opencode", "t3-code"],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        },
        new()
        {
            AuditorId = "claude-code",
            AuditorType = "harness",
            DisplayName = "Claude Code",
            TargetHarnessIds = ["codex", "opencode", "t3-code"],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        },
        new()
        {
            AuditorId = "opencode",
            AuditorType = "harness",
            DisplayName = "OpenCode",
            TargetHarnessIds = ["claude-code", "codex", "t3-code"],
            MinimumSeverities = ["High", "Critical"],
            Priority = 100,
        },
    ];
}

public sealed class AuditorPreference
{
    public bool Enabled { get; set; } = true;
    public string AuditorId { get; set; } = string.Empty;
    /// <summary>harness | api</summary>
    public string AuditorType { get; set; } = "harness";
    public string DisplayName { get; set; } = string.Empty;
    public string[] TargetHarnessIds { get; set; } = [];
    public string[] MinimumSeverities { get; set; } = ["High", "Critical"];
    public int Priority { get; set; } = 100;
    public string? ApiEndpoint { get; set; }
    public string? Model { get; set; }
}
