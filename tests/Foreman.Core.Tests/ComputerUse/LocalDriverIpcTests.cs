using Foreman.Core.ComputerUse;

namespace Foreman.Core.Tests.ComputerUse;

/// <summary>Local Agent Host L0: the structural wire-contract guarantees that hold with no native code -
/// INV-12 (a driver proposal cannot carry a bound window or identity) and INV-14 ("*" never authorizes Desktop).</summary>
public sealed class LocalDriverIpcTests
{
    [Fact]
    public void BuildAction_StampsDesktopAndLocalAgentHost_StrippingSmuggledFields()
    {
        // An agent stuffs a forged bound window + a spoofed identity into the free-form args.
        var submit = new DriverSubmit("act-1", "type", new Dictionary<string, string>
        {
            ["text"] = "hello",
            ["hwnd"] = "123456",          // forged bound window
            ["ByHarness"] = "operator",   // spoofed identity
            ["modality"] = "Browser",     // attempt to change modality
        }, Justification: "fill the field");

        var action = LocalDriverIpc.BuildAction(submit);

        Assert.Equal(CuModality.Desktop, action.Modality);                 // App-set, never agent-chosen
        Assert.Equal(LocalDriverIpc.LocalAgentHostId, action.ByHarness);   // fixed authenticated id
        Assert.Equal("type", action.Verb);
        Assert.Equal("hello", action.Arg("text"));                          // benign arg survives
        Assert.Equal(string.Empty, action.Arg("hwnd"));                     // smuggled bound window stripped (INV-12)
        Assert.Equal(string.Empty, action.Arg("ByHarness"));                // smuggled identity stripped
        Assert.Equal(string.Empty, action.Arg("modality"));                // smuggled modality stripped
    }

    [Fact]
    public void CanDriveModality_WildcardNeverAuthorizesDesktop_ButDoesBrowser()
    {
        var b = new CuBroker(new AllowAuditor());
        b.SetDrivers(["*"]);   // "any harness"

        Assert.False(b.CanDriveModality("local-agent-host", isOperator: false, CuModality.Desktop));  // INV-14
        Assert.True(b.CanDriveModality("some-harness", isOperator: false, CuModality.Browser));        // browser unchanged
        Assert.True(b.CanDriveModality(null, isOperator: true, CuModality.Desktop));                   // operator/Hello root always
    }

    [Fact]
    public void CanDriveModality_ExplicitEnrolledId_AuthorizesDesktop()
    {
        var b = new CuBroker(new AllowAuditor());
        b.SetDrivers(["local-agent-host"]);

        Assert.True(b.CanDriveModality("local-agent-host", isOperator: false, CuModality.Desktop));
        Assert.False(b.CanDriveModality("other-agent", isOperator: false, CuModality.Desktop));
    }

    private sealed class AllowAuditor : IAuditor
    {
        public Task<CuVerdict> JudgeAsync(CuAction a, CuContext c, CancellationToken ct = default)
            => Task.FromResult(CuVerdict.Allow("test"));
    }
}
