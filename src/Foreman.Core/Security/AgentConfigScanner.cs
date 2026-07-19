using System.Text.RegularExpressions;
using Foreman.Core.Models;

namespace Foreman.Core.Security;

/// <summary>
/// What a finding flagged. Kept coarse so the UI can group; Detail carries the specifics.
/// </summary>
public enum AgentConfigSignal
{
    AutoRunHook,            // .claude/.gemini settings.json hook that fetches/executes external code
    FolderOpenTask,         // .vscode/tasks.json task with runOn: folderOpen
    AlwaysApplyRuleExec,    // .cursor rule (alwaysApply) that instructs running a script
    ObfuscatedDropper,      // huge single-line / dropper-shaped script (e.g. .github/setup.js)
    SuspiciousPackageScript,// package.json (pre/post)install or test running a dropper
    PromptInjection,        // instruction-override text in an agent-readable file
    HiddenUnicode,          // zero-width / bidi-override characters hiding directives
    IocString,              // a Miasma / Shai-Hulud IOC marker or C2 string
    FetchAndExec,           // download-and-run cradle in an agent-readable file
    LinkedPath,             // symlink/junction inside the repo; reported but never followed by the scanner
    ScanIncomplete,         // traversal hit its safety budget; a clean result must not imply a complete scan
}

public sealed record AgentConfigFinding(string FilePath, ForemanSeverity Severity, AgentConfigSignal Signal, string Detail);

/// <summary>
/// Scans a repository's AGENT-CONFIG supply chain — the files that make an AI coding agent autonomous and so
/// turn "open a repo in Claude Code / Cursor / Gemini / VS Code" into code execution. This is the June-2026
/// Miasma "rules file backdoor" class: a planted .claude/settings.json (SessionStart -> node .github/setup.js),
/// .cursor/rules/setup.mdc (alwaysApply), .vscode/tasks.json (runOn: folderOpen), or a multi-megabyte
/// obfuscated .github/setup.js dropper, plus prompt-injection / hidden-unicode in CLAUDE.md / AGENTS.md.
///
/// The point is "scan BEFORE you open." <see cref="ScanFile"/> is pure (path + content -> findings) and is the
/// testable heart; <see cref="ScanDirectory"/> is the thin disk walk. Tuned to flag the Miasma shapes (remote
/// fetch / .github/setup / bun-run / folderOpen / always-apply-run) while staying silent on a benign local
/// hook (e.g. a Stop hook running a local python logger) or an ordinary CLAUDE.md.
/// </summary>
public static class AgentConfigScanner
{
    // ── candidate files (relative-path tails, '/'-normalised, lower-case) ─────────────────────────────
    private static readonly string[] _settingsHooks = [".claude/settings.json", ".gemini/settings.json"];
    private static readonly string[] _instructionDocs =
        ["claude.md", "agents.md", "gemini.md", ".cursorrules", "copilot-instructions.md"];

    public static bool IsAgentConfigFile(string relativePath)
    {
        var p = Norm(relativePath);
        var name = FileName(p);
        return _settingsHooks.Any(s => p.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            || _instructionDocs.Contains(name)
            || (p.Contains(".cursor/rules/") && name.EndsWith(".mdc"))
            || p.EndsWith(".vscode/tasks.json", StringComparison.OrdinalIgnoreCase)
            || p.EndsWith(".github/setup.js") || name is "setup.mjs" or "setup.js"
            || name == "package.json";
    }

    // ── compiled signatures ──────────────────────────────────────────────────────────────────────────
    private static readonly RegexOptions O =
        RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;
    private static readonly TimeSpan TO = TimeSpan.FromMilliseconds(500);

    // A hook/command that fetches or executes EXTERNAL code (the Miasma trigger) — NOT a benign local script.
    private static readonly Regex _hookFetchExec = new(
        @"\.github[/\\]setup\.(?:js|mjs|cjs)|setup\.mjs|\bbun\s+run\b|\b(?:curl|wget|iwr|Invoke-WebRequest|Invoke-RestMethod)\b|\|\s*(?:bash|sh|pwsh|powershell)\b",
        O, TO);
    private static readonly Regex _folderOpen = new(@"""runOn""\s*:\s*""folderOpen""", O, TO);
    private static readonly Regex _alwaysApply = new(@"alwaysApply\s*:\s*true", O, TO);
    private static readonly Regex _ruleRunsScript = new(
        @"\b(?:run|execute|exec)\b[^\n]{0,40}`?\s*(?:node|bun|npm|pnpm|yarn|python|sh|bash)\b|\.github[/\\]setup\.",
        O, TO);
    private static readonly Regex _pkgScriptDropper = new(
        @"""(?:preinstall|postinstall|install|prepare|test)""\s*:\s*""[^""]*(?:\.github[/\\]setup|setup\.(?:js|mjs|cjs)|\bbun\s+run\b|curl|wget)",
        O, TO);
    private static readonly Regex _promptInjection = new(
        @"ignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions|disregard\s+(?:all\s+)?(?:previous|prior)|new\s+system\s+prompt|you\s+are\s+now\s+|developer\s+mode|begin\s+system\s+prompt|override\s+(?:previous|prior)\s+(?:context|instructions)|message\s+from\s+anthropic",
        O, TO);
    private static readonly Regex _b64Injection = new(
        // base64 of "Ignore all previous instructions" + generic very-long base64 blobs in instruction text
        @"SWdub3JlIGFsbCBwcmV2aW91cyBpbnN0cnVjdGlvbnM|[A-Za-z0-9+/]{180,}={0,2}", O, TO);
    private static readonly Regex _ioc = new(
        @"(?:check\.)?git-service\.com|\bm-kosche\.com|api\.anthropic\.com/v1/api|Miasma[:\- ]+The Spreading Blight|DontRevokeOrItGoesBoom|thebeautifulmarchoftime|firedalazer|oven-sh/bun/releases/download/bun-v1\.3\.13",
        O, TO);
    private static readonly Regex _fetchExec = new(
        @"\bnode\s+[^\n]*\.github[/\\]setup\.|\b(?:curl|wget)\b[^\n]*\|\s*(?:bash|sh)\b|(?:iex|Invoke-Expression)\s*\(\s*(?:iwr|Invoke-WebRequest|New-Object)",
        O, TO);
    // zero-width (200B-200D, FEFF) + bidi overrides (202A-202E, 2066-2069)
    private static readonly Regex _hiddenUnicode = new("[​-‍﻿‪-‮⁦-⁩]", RegexOptions.Compiled, TO);

    /// <summary>Scan one file's content. Pure: same input always yields the same findings.</summary>
    public static IReadOnlyList<AgentConfigFinding> ScanFile(string relativePath, string content)
    {
        var findings = new List<AgentConfigFinding>();
        if (string.IsNullOrEmpty(content)) return findings;
        var p = Norm(relativePath);
        var name = FileName(p);

        void Add(ForemanSeverity sev, AgentConfigSignal sig, string detail) =>
            findings.Add(new AgentConfigFinding(relativePath, sev, sig, detail));

        // .claude / .gemini settings.json — auto-run hook that fetches or executes external code.
        if (_settingsHooks.Any(s => p.EndsWith(s, StringComparison.OrdinalIgnoreCase))
            && content.Contains("\"hooks\"", StringComparison.OrdinalIgnoreCase)
            && Matches(_hookFetchExec, content))
        {
            Add(ForemanSeverity.Critical, AgentConfigSignal.AutoRunHook,
                "Agent session hook fetches or executes external code (the Miasma 'open a repo = run code' trigger).");
        }

        // .vscode/tasks.json — runs on folder open with no prompt.
        if (p.EndsWith(".vscode/tasks.json", StringComparison.OrdinalIgnoreCase) && Matches(_folderOpen, content))
            Add(ForemanSeverity.Critical, AgentConfigSignal.FolderOpenTask,
                "VS Code task is configured to run automatically on folder open (runOn: folderOpen).");

        // .cursor rule that is always applied AND tells the agent to run a script.
        if ((name.EndsWith(".mdc") && p.Contains(".cursor/rules/")) || name == ".cursorrules")
            if (Matches(_alwaysApply, content) && Matches(_ruleRunsScript, content))
                Add(ForemanSeverity.High, AgentConfigSignal.AlwaysApplyRuleExec,
                    "Always-applied Cursor rule instructs the agent to run a script — a prompt-injection auto-run.");

        // package.json lifecycle/test script that runs a dropper.
        if (name == "package.json" && Matches(_pkgScriptDropper, content))
            Add(ForemanSeverity.High, AgentConfigSignal.SuspiciousPackageScript,
                "package.json lifecycle/test script runs a setup/dropper script or fetches remote code.");

        // Dropper-shaped JS: the exact .github/setup.js name/location, or any huge single-line obfuscated blob.
        if (name is "setup.js" or "setup.mjs" && p.Contains(".github/"))
            Add(ForemanSeverity.Critical, AgentConfigSignal.ObfuscatedDropper,
                ".github/setup.js present — the exact Miasma dropper filename/location.");
        else if (name.EndsWith(".js") || name.EndsWith(".mjs") || name.EndsWith(".cjs"))
            if (MaxLineLength(content) > 5000)
                Add(ForemanSeverity.High, AgentConfigSignal.ObfuscatedDropper,
                    $"Single line of {MaxLineLength(content)} chars — obfuscated/minified script shaped like the Miasma dropper.");

        // Prompt-injection text in any agent-readable file.
        if (Matches(_promptInjection, content))
            Add(ForemanSeverity.High, AgentConfigSignal.PromptInjection,
                "Instruction-override / prompt-injection text in an agent-readable file.");

        // Shared signatures on every agent-config file.
        if (Matches(_ioc, content))
            Add(ForemanSeverity.Critical, AgentConfigSignal.IocString, "Contains a Miasma / Shai-Hulud IOC or C2 string.");
        if (Matches(_fetchExec, content))
            Add(ForemanSeverity.High, AgentConfigSignal.FetchAndExec, "Contains a download-and-execute cradle.");
        if (Matches(_b64Injection, content) && (name.EndsWith(".md") || name == ".cursorrules" || name.EndsWith(".mdc")))
            Add(ForemanSeverity.Medium, AgentConfigSignal.PromptInjection, "Long base64 blob embedded in an instruction file (possible encoded directive).");
        if (Matches(_hiddenUnicode, content))
            Add(ForemanSeverity.Medium, AgentConfigSignal.HiddenUnicode, "Hidden zero-width / bidirectional-override characters that can conceal instructions.");

        return findings;
    }

    private static bool Matches(Regex regex, string content)
    {
        try { return regex.IsMatch(content); }
        catch (RegexMatchTimeoutException) { return false; }
    }

    /// <summary>
    /// Walk a directory, scanning the agent-config files in it. Bounded (skips node_modules/.git/bin/obj,
    /// caps filesystem entries + per-file size) so it is safe to run on a large or adversarial tree.
    /// </summary>
    public static IReadOnlyList<AgentConfigFinding> ScanDirectory(string root, int maxFiles = 4000, long maxFileBytes = 8L * 1024 * 1024)
    {
        var findings = new List<AgentConfigFinding>();
        if (!Directory.Exists(root)) return findings;

        var budget = new ScanBudget(Math.Max(0, maxFiles));
        foreach (var path in EnumerateSafe(root, findings, budget))
        {
            var rel = Path.GetRelativePath(root, path);
            if (!IsAgentConfigFile(rel)) continue;
            try
            {
                var info = new FileInfo(path);
                if (info.Length > maxFileBytes)
                {
                    findings.Add(new AgentConfigFinding(rel, ForemanSeverity.High, AgentConfigSignal.ObfuscatedDropper,
                        $"Agent-config file is unusually large ({info.Length / 1024} KB) — possible obfuscated dropper."));
                    continue;
                }
                findings.AddRange(ScanFile(rel, File.ReadAllText(path)));
            }
            catch { /* unreadable file — skip, never let the scan throw */ }
        }
        if (budget.Exhausted)
        {
            findings.Add(new AgentConfigFinding(".", ForemanSeverity.Medium, AgentConfigSignal.ScanIncomplete,
                $"Scan stopped after {budget.Visited} filesystem entries; increase the scan budget or inspect the remaining tree manually."));
        }
        return findings;
    }

    private static IEnumerable<string> EnumerateSafe(
        string root, List<AgentConfigFinding> findings, ScanBudget budget)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            string[] subdirs, files;
            try { subdirs = Directory.GetDirectories(dir); files = Directory.GetFiles(dir); }
            catch { continue; }
            // Reparse-point files can resolve outside the requested repository. Scanning their target would let a
            // repository author pull unrelated local files into the result set, so treat them as an untrusted
            // boundary just like directory links/junctions.
            foreach (var f in files)
            {
                if (!budget.TryVisit()) yield break;
                if (IsReparsePoint(f))
                {
                    findings.Add(new AgentConfigFinding(Path.GetRelativePath(root, f), ForemanSeverity.Medium,
                        AgentConfigSignal.LinkedPath,
                        "Linked file was not scanned because its target may be outside the requested repository."));
                    continue;
                }
                yield return f;
            }
            foreach (var d in subdirs)
            {
                if (!budget.TryVisit()) yield break;
                var n = Path.GetFileName(d).ToLowerInvariant();
                if (n is "node_modules" or ".git" or "bin" or "obj" or "dist" or ".next" or "target") continue;
                // Never follow directory symlinks/junctions: they can escape the scan root or create traversal
                // cycles. The linked directory can be scanned explicitly by the operator if it is in scope.
                if (IsReparsePoint(d))
                {
                    findings.Add(new AgentConfigFinding(Path.GetRelativePath(root, d), ForemanSeverity.Medium,
                        AgentConfigSignal.LinkedPath,
                        "Linked directory was not traversed because its target may escape the requested repository or form a cycle."));
                    continue;
                }
                stack.Push(d);
            }
        }
    }

    private sealed class ScanBudget(int limit)
    {
        public int Visited { get; private set; }
        public bool Exhausted { get; private set; }

        public bool TryVisit()
        {
            if (Visited >= limit)
            {
                Exhausted = true;
                return false;
            }
            Visited++;
            return true;
        }
    }

    private static bool IsReparsePoint(string path)
    {
        try { return (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0; }
        catch { return true; } // unreadable/unstable entry: fail closed at the filesystem boundary
    }

    private static string Norm(string p) => p.Replace('\\', '/');
    private static string FileName(string normPath)
    {
        var i = normPath.LastIndexOf('/');
        return (i >= 0 ? normPath[(i + 1)..] : normPath).ToLowerInvariant();
    }
    private static int MaxLineLength(string content)
    {
        var max = 0; var cur = 0;
        foreach (var ch in content)
        {
            if (ch == '\n') { if (cur > max) max = cur; cur = 0; }
            else if (ch != '\r') cur++;
        }
        return cur > max ? cur : max;
    }
}
