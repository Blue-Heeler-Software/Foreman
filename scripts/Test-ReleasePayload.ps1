[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $PayloadPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^\d+\.\d+\.\d+(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?(?:\+[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?$')]
    [string] $ExpectedVersion,

    [switch] $RequireValidSignatures
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path -LiteralPath $PayloadPath).Path
$required = @(
    'Foreman.exe',
    'sidecar\Foreman.EtwSidecar.exe',
    'guardian\Foreman.Guardian.exe',
    'cu-sidecar\Foreman.CuSidecar.exe',
    'cu-pilot\Foreman.CuPilot.exe'
)

$missing = @($required | Where-Object { -not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf) })
if ($missing.Count -gt 0) {
    throw "Release payload is missing required executable(s): $($missing -join ', ')"
}

$wrongVersion = @()
$badSignature = @()
foreach ($relative in $required) {
    $full = Join-Path $root $relative
    $productVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($full).ProductVersion
    $versionMatches = -not [string]::IsNullOrWhiteSpace($productVersion) -and (
        $productVersion.Equals($ExpectedVersion, [StringComparison]::OrdinalIgnoreCase) -or
        $productVersion.StartsWith("$ExpectedVersion+", [StringComparison]::OrdinalIgnoreCase) -or
        ($ExpectedVersion.Contains('+') -and
         $productVersion.StartsWith("$ExpectedVersion.", [StringComparison]::OrdinalIgnoreCase))
    )
    if (-not $versionMatches) {
        $wrongVersion += "$relative=$productVersion"
    }

    if ($RequireValidSignatures -and (Get-AuthenticodeSignature -LiteralPath $full).Status -ne 'Valid') {
        $badSignature += $relative
    }
}

if ($wrongVersion.Count -gt 0) {
    throw "Release payload version mismatch; expected '$ExpectedVersion': $($wrongVersion -join ', ')"
}
if ($badSignature.Count -gt 0) {
    throw "Release payload contains unsigned or invalid executable(s): $($badSignature -join ', ')"
}

$sidecarPrefixes = @('Foreman.EtwSidecar.', 'Foreman.Guardian.', 'Foreman.CuSidecar.', 'Foreman.CuPilot.')
$stray = @(Get-ChildItem -LiteralPath $root -File | Where-Object {
    $name = $_.Name
    $sidecarPrefixes | Where-Object { $name.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }
})
if ($stray.Count -gt 0) {
    throw "Release payload contains stray root-level sidecar artifact(s): $($stray.Name -join ', ')"
}

$signatureNote = if ($RequireValidSignatures) { ', valid Authenticode signatures' } else { '' }
Write-Host "Release payload verified: $($required.Count) executables, version $ExpectedVersion$signatureNote."
