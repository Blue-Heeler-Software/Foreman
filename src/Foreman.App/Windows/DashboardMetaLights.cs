using System.Windows;
using System.Windows.Media;

namespace Foreman.App.Windows;

public enum MetaLightState { Off, Ok, Warn, Alert }

/// <summary>One system-level indicator on the dashboard meta strip.</summary>
public sealed class DashboardMetaLightVm
{
    public string Label { get; }
    public MetaLightState State { get; }
    public string ToolTip { get; }
    public Brush DotBrush { get; }

    /// <summary>Optional one-letter badge ("C"/"B") shown INSTEAD of the status dot, so this key entry uses the
    /// SAME glyph as the per-harness card badge it explains. Null = plain status dot. Dimmed when State is Off.</summary>
    public string? Glyph { get; }
    public Visibility GlyphVisibility => Glyph is null ? Visibility.Collapsed : Visibility.Visible;
    public Visibility DotVisibility   => Glyph is null ? Visibility.Visible   : Visibility.Collapsed;
    public double GlyphOpacity        => State == MetaLightState.Off ? 0.4 : 1.0;

    public DashboardMetaLightVm(string label, MetaLightState state, string toolTip, string? glyph = null)
    {
        Label = label;
        State = state;
        ToolTip = toolTip;
        Glyph = glyph;
        DotBrush = state switch
        {
            MetaLightState.Ok    => new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50)),
            MetaLightState.Warn  => new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C)),
            MetaLightState.Alert => new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x51)),
            _                    => new SolidColorBrush(Color.FromRgb(0x48, 0x4F, 0x58)),
        };
    }
}

/// <summary>One colored dot on a harness overview card (running, MCP, usage, etc.).</summary>
public sealed class HarnessLightVm
{
    public Brush DotBrush { get; }
    public string ToolTip { get; }

    public HarnessLightVm(MetaLightState state, string toolTip)
    {
        ToolTip = toolTip;
        DotBrush = state switch
        {
            MetaLightState.Ok    => new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50)),
            MetaLightState.Warn  => new SolidColorBrush(Color.FromRgb(0xE8, 0xB2, 0x3C)),
            MetaLightState.Alert => new SolidColorBrush(Color.FromRgb(0xF8, 0x51, 0x51)),
            _                    => new SolidColorBrush(Color.FromRgb(0x48, 0x4F, 0x58)),
        };
    }
}
