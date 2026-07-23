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

function Get-RelativeChildPath([string] $BasePath, [string] $ChildPath) {
    $base = [IO.Path]::GetFullPath($BasePath).TrimEnd('\', '/')
    $child = [IO.Path]::GetFullPath($ChildPath)
    $prefix = $base + [IO.Path]::DirectorySeparatorChar
    if (-not $child.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$child' is not under release payload '$base'."
    }
    return $child.Substring($prefix.Length)
}
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
$stray = @(Get-ChildItem -LiteralPath $root -File -Force | Where-Object {
    $name = $_.Name
    $sidecarPrefixes | Where-Object { $name.StartsWith($_, [StringComparison]::OrdinalIgnoreCase) }
})
if ($stray.Count -gt 0) {
    throw "Release payload contains stray root-level sidecar artifact(s): $($stray.Name -join ', ')"
}

# Every helper must remain a self-contained single-file publish. A neighbouring managed/native payload would
# sit outside the verified EXE and can recreate DLL-search or load-context hijack paths. Use -Force so a hidden
# sibling cannot evade release validation.
$singleFileDirectories = @{
    'sidecar'    = 'Foreman.EtwSidecar.exe'
    'guardian'   = 'Foreman.Guardian.exe'
    'cu-sidecar' = 'Foreman.CuSidecar.exe'
    'cu-pilot'   = 'Foreman.CuPilot.exe'
}
foreach ($entry in $singleFileDirectories.GetEnumerator()) {
    $directory = Join-Path $root $entry.Key
    $expected = Join-Path $directory $entry.Value
    $unexpected = @(Get-ChildItem -LiteralPath $directory -File -Recurse -Force | Where-Object {
        $_.FullName -ne $expected
    })
    if ($unexpected.Count -gt 0) {
        $relative = @($unexpected | ForEach-Object { Get-RelativeChildPath $root $_.FullName })
        throw "Helper '$($entry.Key)' is not a single-file payload: $($relative -join ', ')"
    }
}

$extensionRequirements = @(
    'extensions\foreman\manifest.json',
    'extensions\foreman\background.js',
    'extensions\liveweave\manifest.json',
    'extensions\liveweave\background.js'
)
$missingExtensions = @($extensionRequirements | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $root $_) -PathType Leaf)
})
if ($missingExtensions.Count -gt 0) {
    throw "Release payload is missing browser-extension file(s): $($missingExtensions -join ', ')"
}

foreach ($manifestRelative in @('extensions\foreman\manifest.json', 'extensions\liveweave\manifest.json')) {
    $manifest = Get-Content -LiteralPath (Join-Path $root $manifestRelative) -Raw | ConvertFrom-Json
    if ($manifest.manifest_version -ne 3 -or [string]::IsNullOrWhiteSpace($manifest.version)) {
        throw "Packaged browser extension has an invalid MV3 manifest: $manifestRelative"
    }
}

$packagedTests = @(Get-ChildItem -LiteralPath (Join-Path $root 'extensions') -Directory -Recurse -Force |
    Where-Object { $_.Name -eq 'tests' })
if ($packagedTests.Count -gt 0) {
    throw "Release payload contains browser-extension test directories: $($packagedTests.FullName -join ', ')"
}

$signatureNote = if ($RequireValidSignatures) { ', valid Authenticode signatures' } else { '' }
Write-Host "Release payload verified: $($required.Count) executables, two MV3 extensions, version $ExpectedVersion$signatureNote."
