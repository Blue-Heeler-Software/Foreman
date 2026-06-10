using System.Text.Json;

namespace Foreman.Core.Settings;

public sealed class SettingsStore
{
    private static readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Foreman", "settings.json");

    private static readonly JsonSerializerOptions _opts = new() { WriteIndented = true };

    /// <summary>
    /// Set by <see cref="Load()"/> when settings.json existed but could not be parsed: the unreadable
    /// file is quarantined (renamed to <c>settings.json.&lt;timestamp&gt;.bad</c>) and defaults are loaded.
    /// The app reads this AFTER the event bus is wired and surfaces a notice — so a corrupt settings file
    /// no longer silently resets security-relevant posture (mutes, emergency rule IDs) without warning.
    /// </summary>
    public static string? LastLoadFault { get; private set; }

    public static ForemanSettings Load() => Load(_path);

    public static void Save(ForemanSettings settings) => Save(settings, _path);

    /// <summary>Loads from an explicit path. Quarantines an unreadable file and records <see cref="LastLoadFault"/>.</summary>
    public static ForemanSettings Load(string path)
    {
        LastLoadFault = null;
        if (!File.Exists(path)) return new ForemanSettings();
        try
        {
            var json = File.ReadAllText(path);
            return JsonSerializer.Deserialize<ForemanSettings>(json, _opts) ?? new ForemanSettings();
        }
        catch (Exception ex)
        {
            var quarantine = Quarantine(path);
            LastLoadFault = quarantine is not null
                ? $"settings.json could not be read ({ex.Message}). It was moved to {Path.GetFileName(quarantine)} " +
                  "and defaults were loaded — re-apply your settings, or restore from the .bad file."
                : $"settings.json could not be read ({ex.Message}); defaults were loaded.";
            return new ForemanSettings();
        }
    }

    /// <summary>Saves to an explicit path atomically (temp file + swap), so a crash mid-write can't corrupt it.</summary>
    public static void Save(ForemanSettings settings, string path)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(settings, _opts);

        // Write to a sibling temp file, then swap it in. A crash or full disk mid-write leaves the temp
        // file (ignored on next launch) rather than a half-written settings.json that would be quarantined.
        var tmp = path + ".tmp";
        File.WriteAllText(tmp, json);
        try
        {
            if (File.Exists(path))
                File.Replace(tmp, path, destinationBackupFileName: null);  // atomic same-volume swap, preserves ACLs
            else
                File.Move(tmp, path);
        }
        catch
        {
            // File.Replace/Move can transiently fail if an AV/indexer holds a handle — fall back to a
            // direct overwrite so the save still lands, then best-effort clean up the temp.
            File.Copy(tmp, path, overwrite: true);
            try { File.Delete(tmp); } catch { /* leftover temp is harmless */ }
        }
    }

    private static string? Quarantine(string path)
    {
        try
        {
            var dest = $"{path}.{DateTime.Now:yyyyMMdd-HHmmss}.bad";
            File.Move(path, dest, overwrite: true);
            return dest;
        }
        catch { return null; }
    }
}
