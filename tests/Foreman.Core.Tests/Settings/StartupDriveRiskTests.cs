using System.IO;
using Foreman.Core.Settings;
using static Foreman.Core.Settings.StartupRegistration;

namespace Foreman.Core.Tests.Settings;

public sealed class StartupDriveRiskTests
{
    private const string SystemRoot = @"C:\";

    [Fact]   // the happy path: exe on the system drive → safe, no warning
    public void SystemDrive_NoWarning()
    {
        var risk = ClassifyDriveRisk(@"C:\Users\me\AppData\Local\Foreman\app\Foreman.exe", SystemRoot, DriveType.Fixed);
        Assert.Equal(StartupDriveRisk.SystemDrive, risk);
        Assert.Null(DescribeDriveRisk(risk, @"C:\...\Foreman.exe"));
    }

    [Fact]   // THE bug: a secondary FIXED disk (W:) — reports Fixed, but isn't the system drive → warn
    public void SecondaryFixedDrive_Warns()
    {
        var exe = @"W:\TOOLS\Foreman\src\Foreman.App\bin\Debug\net10.0-windows10.0.19041.0\Foreman.exe";
        var risk = ClassifyDriveRisk(exe, SystemRoot, DriveType.Fixed);
        Assert.Equal(StartupDriveRisk.NonSystemFixed, risk);
        var msg = DescribeDriveRisk(risk, exe);
        Assert.NotNull(msg);
        Assert.Contains("W:", msg);
        Assert.Contains("system drive", msg);
    }

    [Fact]   // a drive that's absent right now (DriveType.Unknown) still warns because root != system drive
    public void AbsentDrive_StillWarns()
    {
        var risk = ClassifyDriveRisk(@"W:\app\Foreman.exe", SystemRoot, DriveType.Unknown);
        Assert.Equal(StartupDriveRisk.NonSystemFixed, risk);
        Assert.NotNull(DescribeDriveRisk(risk, @"W:\app\Foreman.exe"));
    }

    [Theory]   // removable + network are flagged regardless of which letter they're on
    [InlineData(DriveType.Removable, StartupDriveRisk.Removable)]
    [InlineData(DriveType.Network, StartupDriveRisk.Network)]
    public void RemovableAndNetwork_Warn(DriveType type, StartupDriveRisk expected)
    {
        var risk = ClassifyDriveRisk(@"E:\Foreman\Foreman.exe", SystemRoot, type);
        Assert.Equal(expected, risk);
        Assert.NotNull(DescribeDriveRisk(risk, @"E:\Foreman\Foreman.exe"));
    }

    [Fact]   // even a removable drive that happens to be the system letter is flagged (type wins)
    public void RemovableOnSystemLetter_StillRemovable()
    {
        Assert.Equal(StartupDriveRisk.Removable, ClassifyDriveRisk(@"C:\x\Foreman.exe", SystemRoot, DriveType.Removable));
    }

    [Theory]   // missing/blank inputs → Unknown, no warning (never crash, never false-warn)
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void BlankPath_Unknown(string? exe)
    {
        var risk = ClassifyDriveRisk(exe, SystemRoot, DriveType.Fixed);
        Assert.Equal(StartupDriveRisk.Unknown, risk);
        Assert.Null(DescribeDriveRisk(risk, exe));
    }

    [Fact]   // unknown system root → can't compare → Unknown (no false warning)
    public void NoSystemRoot_Unknown()
    {
        Assert.Equal(StartupDriveRisk.Unknown, ClassifyDriveRisk(@"W:\app\Foreman.exe", null, DriveType.Fixed));
    }
}
