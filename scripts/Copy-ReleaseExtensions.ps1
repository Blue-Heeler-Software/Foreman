[CmdletBinding()]
param(
    [string] $RepositoryRoot,

    [Parameter(Mandatory = $true)]
    [string] $PayloadPath
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Split-Path -Parent $PSScriptRoot
}
$repo = (Resolve-Path -LiteralPath $RepositoryRoot).Path
$payload = if (Test-Path -LiteralPath $PayloadPath) {
    (Resolve-Path -LiteralPath $PayloadPath).Path
} else {
    New-Item -ItemType Directory -Path $PayloadPath -Force | Select-Object -ExpandProperty FullName
}
$destinationRoot = Join-Path $payload 'extensions'

if (Test-Path -LiteralPath $destinationRoot) {
    Remove-Item -LiteralPath $destinationRoot -Recurse -Force
}

$packages = @(
    @{ Source = 'extension'; Destination = 'foreman' },
    @{ Source = 'extension-liveweave'; Destination = 'liveweave' }
)

foreach ($package in $packages) {
    $source = Join-Path $repo $package.Source
    if (-not (Test-Path -LiteralPath (Join-Path $source 'manifest.json') -PathType Leaf)) {
        throw "Browser extension source is missing manifest.json: $source"
    }

    $destination = Join-Path $destinationRoot $package.Destination
    foreach ($file in Get-ChildItem -LiteralPath $source -Recurse -File -Force) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Refusing to package browser-extension reparse point: $($file.FullName)"
        }

        $relative = $file.FullName.Substring($source.TrimEnd('\', '/').Length).TrimStart('\', '/')
        $segments = $relative -split '[\\/]'
        if ($segments[0] -eq 'tests') {
            continue
        }

        $target = Join-Path $destination $relative
        $targetDirectory = Split-Path -Parent $target
        New-Item -ItemType Directory -Path $targetDirectory -Force | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $target -Force
    }
}

Write-Host "Packaged Foreman and LiveWeave browser extensions under $destinationRoot."
