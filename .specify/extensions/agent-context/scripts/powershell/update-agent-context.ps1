#!/usr/bin/env pwsh
# update-agent-context.ps1
#
# Refresh the managed Spec Kit section in the coding agent's context file
# (e.g. CLAUDE.md, .github/copilot-instructions.md, AGENTS.md).
#
# Reads `context_file` and `context_markers.{start,end}` from the
# agent-context extension config:
#   .specify/extensions/agent-context/agent-context-config.yml
#
# Usage: update-agent-context.ps1 [plan_path]

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$PlanPath
)

function Get-ConfigValue {
    param(
        [AllowNull()][object]$Object,
        [Parameter(Mandatory = $true)][string]$Key
    )

    if ($null -eq $Object) {
        return $null
    }
    if ($Object -is [System.Collections.IDictionary]) {
        return $Object[$Key]
    }
    $prop = $Object.PSObject.Properties[$Key]
    if ($prop) {
        return $prop.Value
    }
    return $null
}

function Test-ConfigObject {
    param(
        [AllowNull()][object]$Object
    )

    if ($null -eq $Object) {
        return $false
    }
    if ($Object -is [System.Collections.IDictionary]) {
        return $true
    }
    if ($Object -is [System.Management.Automation.PSCustomObject]) {
        return $true
    }
    return $false
}

function ConvertFrom-MinimalYaml {
    # Handles the `key: value` subset (one nesting level) that this extension's config
    # uses -- deliberately not a general YAML parser. It exists so the PowerShell path
    # depends on neither the powershell-yaml module nor an external Python 3 + PyYAML,
    # both of which are routinely absent on Windows.
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Text
    )

    $root = [ordered]@{}
    $parentKey = $null

    foreach ($rawLine in ($Text -split "`r?`n")) {
        if ($rawLine -match '^\s*(#|$)') {
            continue
        }
        if ($rawLine -notmatch '^(\s*)([^:]+?)\s*:\s*(.*)$') {
            continue
        }

        $indent = $Matches[1].Length
        $key    = $Matches[2].Trim()
        $value  = $Matches[3].Trim()

        if (($value -match "^'(.*)'$") -or ($value -match '^"(.*)"$')) {
            $value = $Matches[1]
        }

        if ($indent -eq 0) {
            if ($value -eq '') {
                $parentKey = $key
                $root[$key] = [ordered]@{}
            } else {
                $parentKey = $null
                $root[$key] = $value
            }
        } elseif ($parentKey -and ($root[$parentKey] -is [System.Collections.IDictionary])) {
            $root[$parentKey][$key] = $value
        }
    }

    return $root
}

$ErrorActionPreference = 'Stop'
$DefaultStart = '<!-- SPECKIT START -->'
$DefaultEnd   = '<!-- SPECKIT END -->'
$ProjectRoot  = (Get-Location).Path
$ExtConfig    = Join-Path $ProjectRoot '.specify/extensions/agent-context/agent-context-config.yml'

if (-not (Test-Path -LiteralPath $ExtConfig)) {
    Write-Warning "agent-context: $ExtConfig not found; nothing to do."
    exit 0
}

$ConfigText = $null
try {
    $ConfigText = Get-Content -LiteralPath $ExtConfig -Raw -ErrorAction Stop
} catch {
    Write-Warning "agent-context: unable to read $ExtConfig ($($_.Exception.Message)); skipping update."
    exit 0
}

$Options = $null
if (Get-Command ConvertFrom-Yaml -ErrorAction SilentlyContinue) {
    try {
        $Options = $ConfigText | ConvertFrom-Yaml -ErrorAction Stop
    } catch {
        # fall through to the built-in reader
    }
}

if ($null -eq $Options) {
    # No powershell-yaml module. Parse in-process rather than shelling out to Python:
    # Windows PowerShell 5.1 mangles a multi-line `-c` argument on its way to a native
    # executable, and `python3` on Windows is usually a 0-byte Store alias that only
    # prints an advert -- so the former Python fallback could not work here at all.
    try {
        $Options = ConvertFrom-MinimalYaml -Text $ConfigText
    } catch {
        $Options = $null
    }
}

if (-not $Options) {
    Write-Warning "agent-context: unable to parse $ExtConfig; skipping update."
    exit 0
}

if (-not (Test-ConfigObject -Object $Options)) {
    Write-Warning "agent-context: $ExtConfig must contain a YAML mapping; skipping update."
    exit 0
}

$ContextFile = Get-ConfigValue -Object $Options -Key 'context_file'
if (-not $ContextFile) {
    Write-Warning 'agent-context: context_file not set in extension config; nothing to do.'
    exit 0
}

# Reject absolute paths and '..' path segments in context_file
if ([System.IO.Path]::IsPathRooted($ContextFile)) {
    Write-Warning "agent-context: context_file must be a project-relative path; got '$ContextFile'."
    exit 1
}
$cfSegments = $ContextFile -split '[/\\]'
if ($cfSegments -contains '..') {
    Write-Warning "agent-context: context_file must not contain '..' path segments; got '$ContextFile'."
    exit 1
}

$MarkerStart = $DefaultStart
$MarkerEnd   = $DefaultEnd
$cm = Get-ConfigValue -Object $Options -Key 'context_markers'
if ($cm) {
    $cmStart = Get-ConfigValue -Object $cm -Key 'start'
    if ($cmStart -is [string] -and $cmStart) {
        $MarkerStart = $cmStart
    }
    $cmEnd = Get-ConfigValue -Object $cm -Key 'end'
    if ($cmEnd -is [string] -and $cmEnd) {
        $MarkerEnd = $cmEnd
    }
}

# Resolve which plan the managed section should point at. `.specify/feature.json` names
# the feature this checkout is on, so it wins outright: when it names a feature that has
# no plan yet, the honest answer is "no plan", not some other feature's plan. Scanning for
# the most recently modified plan is only for when the current feature is genuinely unknown.
$FeatureKnown = $false
if (-not $PlanPath) {
    $FeatureJson = Join-Path $ProjectRoot '.specify/feature.json'
    if (Test-Path -LiteralPath $FeatureJson) {
        try {
            $Feature = Get-Content -LiteralPath $FeatureJson -Raw | ConvertFrom-Json -ErrorAction Stop
            $FeatureDir = Get-ConfigValue -Object $Feature -Key 'feature_directory'
            if ($FeatureDir -is [string] -and $FeatureDir.Trim()) {
                $FeatureDir = $FeatureDir.Trim().Replace('\', '/').TrimEnd('/')
                $FeatureKnown = $true
                if (Test-Path -LiteralPath (Join-Path $ProjectRoot "$FeatureDir/plan.md")) {
                    $PlanPath = "$FeatureDir/plan.md"
                }
            }
        } catch {
            # Unreadable pointer: treat the current feature as unknown and scan instead.
        }
    }
}

if (-not $PlanPath -and -not $FeatureKnown) {
    # Discover plan.md exactly one level deep (specs/<feature>/plan.md),
    # matching the bash glob specs/*/plan.md. Wrap in try/catch so access errors under
    # $ErrorActionPreference = 'Stop' don't abort the script.
    try {
        $specsDir = Join-Path $ProjectRoot 'specs'
        $candidate = Get-ChildItem -Path $specsDir -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { Get-Item -LiteralPath (Join-Path $_.FullName 'plan.md') -ErrorAction SilentlyContinue } |
            Where-Object { $_ } |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($candidate) {
            # Not [System.IO.Path]::GetRelativePath -- absent from the .NET Framework behind
            # Windows PowerShell 5.1, where it threw into the catch below and silently
            # dropped the plan path. The candidate is always under $ProjectRoot by construction.
            $Prefix = $ProjectRoot.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
            if ($candidate.FullName.StartsWith($Prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $PlanPath = $candidate.FullName.Substring($Prefix.Length).Replace('\', '/')
            } else {
                $PlanPath = $candidate.FullName.Replace('\', '/')
            }
        }
    } catch {
        # Non-fatal: continue without a plan path.
    }
}

$CtxPath = Join-Path $ProjectRoot $ContextFile
$CtxDir  = Split-Path -Parent $CtxPath
if ($CtxDir -and -not (Test-Path -LiteralPath $CtxDir)) {
    New-Item -ItemType Directory -Path $CtxDir -Force | Out-Null
}

$lines = @($MarkerStart,
           'For additional context about technologies to be used, project structure,',
           'shell commands, and other important information, read the current plan')
if ($PlanPath) {
    $lines += "at $PlanPath"
}
$lines += $MarkerEnd
$Section = ($lines -join "`n") + "`n"

if (Test-Path -LiteralPath $CtxPath) {
    $rawBytes = [System.IO.File]::ReadAllBytes($CtxPath)
    # Strip UTF-8 BOM if present
    if ($rawBytes.Length -ge 3 -and $rawBytes[0] -eq 0xEF -and $rawBytes[1] -eq 0xBB -and $rawBytes[2] -eq 0xBF) {
        $content = [System.Text.Encoding]::UTF8.GetString($rawBytes, 3, $rawBytes.Length - 3)
    } else {
        $content = [System.Text.Encoding]::UTF8.GetString($rawBytes)
    }

    $s = $content.IndexOf($MarkerStart)
    $e = if ($s -ge 0) { $content.IndexOf($MarkerEnd, $s) } else { $content.IndexOf($MarkerEnd) }

    if ($s -ge 0 -and $e -ge 0 -and $e -gt $s) {
        $endOfMarker = $e + $MarkerEnd.Length
        if ($endOfMarker -lt $content.Length -and $content[$endOfMarker] -eq "`r") { $endOfMarker++ }
        if ($endOfMarker -lt $content.Length -and $content[$endOfMarker] -eq "`n") { $endOfMarker++ }
        $newContent = $content.Substring(0, $s) + $Section + $content.Substring($endOfMarker)
    } elseif ($s -ge 0) {
        $newContent = $content.Substring(0, $s) + $Section
    } elseif ($e -ge 0) {
        $endOfMarker = $e + $MarkerEnd.Length
        if ($endOfMarker -lt $content.Length -and $content[$endOfMarker] -eq "`r") { $endOfMarker++ }
        if ($endOfMarker -lt $content.Length -and $content[$endOfMarker] -eq "`n") { $endOfMarker++ }
        $newContent = $Section + $content.Substring($endOfMarker)
    } else {
        if ($content -and -not $content.EndsWith("`n")) { $content += "`n" }
        if ($content) { $newContent = $content + "`n" + $Section } else { $newContent = $Section }
    }
} else {
    $newContent = $Section
}

$newContent = $newContent.Replace("`r`n", "`n").Replace("`r", "`n")
[System.IO.File]::WriteAllText($CtxPath, $newContent, (New-Object System.Text.UTF8Encoding($false)))

Write-Host "agent-context: updated $ContextFile"
