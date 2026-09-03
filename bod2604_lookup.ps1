<#
.SYNOPSIS
    BOD 26-04 CVE Timeline Calculator

.DESCRIPTION
    Fetches vulnerability data from the CVE Program's public GitHub (cvelistV5) 
    and evaluates it against CISA BOD 26-04 criteria. Calculates accelerated 
    remediation timelines by extracting SSVC Vulnrichment data and checking KEV status.

    Both "If Exposed" and "If Not Exposed" timelines are calculated automatically.

.PARAMETER CveIds
    List of CVE IDs to look up (omit with -Recent to pull latest).

.PARAMETER Recent
    Fetch CVEs published/updated in the last N hours.

.PARAMETER Hours
    Hours window for -Recent (default: 24).

.PARAMETER KevOnly
    With -Recent: only show KEV entries (much smaller set).

.PARAMETER Limit
    With -Recent: cap results at N (sorted: KEV-first, then severity).

.PARAMETER JsonOut
    Output raw JSON.

.PARAMETER Full
    Print the full detailed output for each CVE.

.PARAMETER NoColor
    Disable ANSI color output.

.PARAMETER AssumeKev
    Treat all processed CVEs as if they are actively listed in the KEV catalog.

.EXAMPLE
    .\bod2604_lookup.ps1 CVE-2023-45727
.EXAMPLE
    .\bod2604_lookup.ps1 CVE-2021-44228 CVE-2023-34362 -AssumeKev
.EXAMPLE
    .\bod2604_lookup.ps1 -Recent -Hours 48 -KevOnly -Full

.NOTES
https://github.com/AKapaldo/BOD_26-04

Date                Ver     Author          Details                         
-------------------------------------------------------------------------------------------     
19  Mar 2024        1.0.0   Andrew Kapaldo  Initial Release

#>
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline=$true, Position=0)]
    [string[]]$CveIds,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$ExtraArgs,

    [switch]$Recent,
    [int]$Hours = 24,
    [switch]$KevOnly,
    [int]$Limit = 0,
    [Alias("json")]
    [switch]$JsonOut,
    [switch]$Full,
    [switch]$NoColor,
    [switch]$AssumeKev
)

# ---------------------------------------------------------------------------
# Constants & Colors
# ---------------------------------------------------------------------------
$RAW_CVE_BASE  = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves"
$DELTA_LOG_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"

$ESC = [char]27
$BOLD = "$ESC[1m"
$RED  = "$ESC[91m"
$YEL  = "$ESC[93m"
$GRN  = "$ESC[92m"
$CYN  = "$ESC[96m"
$DIM  = "$ESC[2m"
$RST  = "$ESC[0m"

$SEV_RANK = @{ "CRITICAL" = 4; "HIGH" = 3; "MEDIUM" = 2; "LOW" = 1; "N/A" = 0 }

if ($NoColor) {
    $BOLD = ""; $RED = ""; $YEL = ""; $GRN = ""; $CYN = ""; $DIM = ""; $RST = ""
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-CveUrl([string]$CveId) {
    if ($CveId -match '(?i)CVE-(\d{4})-(\d{4,})') {
        $year = $Matches[1]
        $seq = $Matches[2]
        $bucket = if ($seq.Length -gt 3) { $seq.Substring(0, $seq.Length - 3) + "xxx" } else { "0xxx" }
        return "$RAW_CVE_BASE/$year/$bucket/$($CveId.ToUpper()).json"
    }
    throw "Invalid CVE ID format: $CveId"
}

function Get-BodTimeline([string]$Kev, [bool]$Exposed, [string]$Automatable, [string]$TechImpact) {
    $k = $Kev.ToUpper() -eq "YES"
    $e = $Exposed
    $a = $Automatable.ToLower() -eq "yes"
    $t = $TechImpact.ToLower() -eq "total"

    if ($e -and $k -and $a -and $t) { return "3 DAYS & FORENSIC TRIAGE", "KEV + Exposed + Automatable + Total Impact" }
    if ($e -and $k -and $a)         { return "3 DAYS",                   "KEV + Exposed + Automatable" }
    if ($e -and $k -and $t)         { return "3 DAYS & FORENSIC TRIAGE", "KEV + Exposed + Total Impact" }
    if ($e -and $k)                 { return "14 DAYS",                  "KEV + Exposed" }
    if ($e -and $a -and $t)         { return "3 DAYS",                   "Exposed + Automatable + Total Impact (not KEV)" }
    if ($e -and ($a -or $t))        { return "14 DAYS",                  "Exposed + Automatable OR Total Impact (not KEV)" }
    if ($e)                         { return "60 DAYS",                  "Exposed" }
    if ($k -and $a -and $t)         { return "3 DAYS & FORENSIC TRIAGE", "KEV + Automatable + Total Impact" }
    if ($k -and ($a -or $t))        { return "14 DAYS",                  "KEV + Automatable OR Total Impact" }
    if ($k)                         { return "14 DAYS",                  "KEV - asset not publicly exposed" }
    if ($a -and $t)                 { return "60 DAYS",                  "Automatable + Total Impact" }
    if ($a)                         { return "60 DAYS",                  "Automatable" }
    return "FIX ON SYSTEM UPGRADE", "Does not meet accelerated criteria"
}

# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------
function Format-Sev([string]$s) {
    $su = $s.ToUpper()
    if ($su -eq 'CRITICAL') { return "${RED}${BOLD}${s}${RST}" }
    if ($su -eq 'HIGH')     { return "${RED}${s}${RST}" }
    if ($su -eq 'MEDIUM')   { return "${YEL}${s}${RST}" }
    if ($su -eq 'LOW')      { return "${GRN}${s}${RST}" }
    return $s
}

function Format-Yn([string]$v) {
    if ($v.ToUpper() -eq "YES") { return "${RED}YES${RST}" }
    if ($v.ToUpper() -eq "NO")  { return "${GRN}NO${RST}" }
    return $v
}

function Format-Timeline([string]$t) {
    if ($t -match "3 DAYS")  { return "${RED}${BOLD}${t}${RST}" }
    if ($t -match "14 DAYS") { return "${YEL}${t}${RST}" }
    if ($t -match "30 DAYS") { return "${YEL}${t}${RST}" }
    if ($t -match "60 DAYS") { return "${GRN}${t}${RST}" }
    return "${GRN}${t}${RST}"
}

function Format-Tech([string]$v) {
    if ($v.ToLower() -eq "total") { return "${RED}${v}${RST}" }
    return $v
}

function Format-Expl([string]$v) {
    if ($v.ToLower() -eq "active") { return "${RED}${BOLD}${v}${RST}" }
    if ($v.ToLower() -eq "poc")    { return "${YEL}${v}${RST}" }
    return $v
}

function Write-Field([string]$label, [string]$value) {
    if (-not $NoColor) { Write-Host "  ${DIM}${label,-26}${RST} $value" }
    else               { Write-Host "  ${label,-26} $value" }
}

function Write-Section([string]$title) {
    $padLength = [math]::Max(0, [math]::Floor((72 - $title.Length - 2) / 2))
    $line = ("-" * $padLength) + " $title " + ("-" * $padLength)
    if (-not $NoColor) { Write-Host "  ${DIM}${line}${RST}" }
    else               { Write-Host "  $line" }
}

# ---------------------------------------------------------------------------
# Main Logic
# ---------------------------------------------------------------------------
$RawInput = [System.Collections.Generic.List[string]]::new()
if ($CveIds) { $CveIds | ForEach-Object { $RawInput.Add($_.Trim()) } }
if ($ExtraArgs) { $ExtraArgs | ForEach-Object { $RawInput.Add($_.Trim()) } }

# Input Validation
$CveList = [System.Collections.Generic.List[string]]::new()
foreach ($item in $RawInput) {
    if ($item -match '(?i)^CVE-\d{4}-\d{4,}$') {
        $CveList.Add($item.ToUpper())
    } else {
        if ($item -match '^\d+$') {
            Write-Host "WARNING: Ignored invalid CVE ID '$item'. If you meant to specify hours for -Recent, use '-Hours $item'." -ForegroundColor Yellow
        } else {
            Write-Host "WARNING: Ignored invalid CVE ID '$item'." -ForegroundColor Yellow
        }
    }
}

$RecentMeta = @{} # cve_id -> hashtable

if ($Recent -or $CveList.Count -eq 0) {
    Write-Host "  Fetching CVEs from the last ${Hours}h via deltaLog.json..." -ForegroundColor DarkGray
    $cutoff = (Get-Date).ToUniversalTime().AddHours(-$Hours)
    
    try {
        $log = Invoke-RestMethod -Uri $DELTA_LOG_URL -ErrorAction Stop
        
        $seen = @{}
        foreach ($snapshot in $log) {
            foreach ($changeType in @("new", "updated")) {
                if ($null -ne $snapshot.$changeType) {
                    foreach ($entry in $snapshot.$changeType) {
                        $dtStr = $entry.dateUpdated
                        try {
                            $dt = [datetime]::ParseExact($dtStr, "yyyy-MM-ddTHH:mm:ss.fffZ", $null, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
                        } catch {
                            continue
                        }

                        if ($dt -lt $cutoff) { continue }

                        $cId = $entry.cveId
                        if (-not $seen.ContainsKey($cId) -or $dt -gt $seen[$cId]._dt) {
                            $seen[$cId] = @{
                                cve_id       = $cId
                                github_url   = $entry.githubLink
                                date_updated = $dt.ToString("yyyy-MM-dd HH:mm:ss UTC")
                                change_type  = $changeType
                                _dt          = $dt
                            }
                        }
                    }
                }
            }
        }

        $RecentEntries = $seen.Values | Sort-Object -Property _dt -Descending
        if ($RecentEntries.Count -gt 0) {
            Write-Host "  Found $($RecentEntries.Count) CVE(s) in delta log." -ForegroundColor DarkGray
            foreach ($entry in $RecentEntries) {
                if (-not $CveList.Contains($entry.cve_id)) {
                    $CveList.Add($entry.cve_id)
                }
                $RecentMeta[$entry.cve_id] = $entry
            }
        } elseif ($CveList.Count -eq 0) {
            Write-Host "No CVEs found in the last $Hours hour(s)." -ForegroundColor Yellow
            exit 0
        }
    } catch {
        Write-Host "ERROR fetching delta log: $_" -ForegroundColor Red
        if ($CveList.Count -eq 0) { exit 2 }
    }
}

if ($CveList.Count -eq 0) {
    Write-Host "No valid CVE IDs to process." -ForegroundColor Yellow
    exit 0
}

Write-Host "  Fetching $($CveList.Count) CVE(s)..." -ForegroundColor DarkGray

$Results = [System.Collections.Generic.List[hashtable]]::new()
$counter = 0

foreach ($cve_id in $CveList) {
    $counter++
    Write-Progress -Activity "Fetching CVE Data" -Status "Processing $cve_id" -PercentComplete (($counter / $CveList.Count) * 100)

    $meta = $RecentMeta[$cve_id]
    $url = if ($meta -and $meta.github_url) { $meta.github_url } else { Get-CveUrl $cve_id }

    $resultObj = [ordered]@{
        cve_id = $cve_id; state = "N/A"; published = "N/A"; description = "N/A"
        severity = "N/A"; cvss_score = "N/A"; cvss_version = "N/A"; cvss_vector = "N/A"
        kev = "NO"; kev_date_added = "N/A"; kev_reference = "N/A"
        automatable = "N/A"; technical_impact = "N/A"; exploitation = "N/A"; ssvc_timestamp = "N/A"
        cwes = @(); affected = @(); references = @()
        timeline_if_exposed = ""; reason_if_exposed = ""
        timeline_if_not_exposed = ""; reason_if_not_exposed = ""; error = $null
        _change_type = if ($meta) { $meta.change_type } else { "" }
        _date_updated = if ($meta) { $meta.date_updated } else { "" }
    }

    try {
        $req = Invoke-RestMethod -Uri $url -Headers @{"User-Agent" = "BOD26-04-Lookup-PS/1.2.0"} -ErrorAction Stop
        
        $cveMeta = $req.cveMetadata
        $cna = $req.containers.cna
        $adpList = $req.containers.adp

        $resultObj.state = if ($cveMeta.state) { $cveMeta.state } else { "N/A" }
        if ($cveMeta.datePublished) { $resultObj.published = $cveMeta.datePublished.Substring(0,10) }

        # Description
        if ($cna.descriptions) {
            $enDesc = $cna.descriptions | Where-Object { $_.lang -match "^en" } | Select-Object -First 1
            if (-not $enDesc) { $enDesc = $cna.descriptions[0] }
            $resultObj.description = $enDesc.value.Trim()
        }

        # Metrics (CVSS)
        $vuln_metrics = @()
        if ($adpList) {
            $vuln_metrics = $adpList | Where-Object { $_.title -eq "CISA ADP Vulnrichment" } | Select-Object -ExpandProperty metrics
        }
        $all_metrics = @()
        if ($vuln_metrics) { $all_metrics += $vuln_metrics }
        if ($cna.metrics) { $all_metrics += $cna.metrics }

        $bestPri = 0
        $priority = @{ "cvssV4_0"=4; "cvssV3_1"=3; "cvssV3_0"=2; "cvssV2_0"=1 }
        foreach ($m in $all_metrics) {
            foreach ($key in $priority.Keys) {
                if ($null -ne $m.$key -and $priority[$key] -gt $bestPri) {
                    $bestPri = $priority[$key]
                    $resultObj.cvss_version = if ($m.$key.version) { $m.$key.version } else { $key }
                    $resultObj.cvss_score = [string]($m.$key.baseScore)
                    $resultObj.severity = if ($m.$key.baseSeverity) { $m.$key.baseSeverity.ToUpper() } else { "N/A" }
                    $resultObj.cvss_vector = if ($m.$key.vectorString) { $m.$key.vectorString } else { "N/A" }
                }
            }
        }

        # SSVC / KEV
        if ($adpList) {
            foreach ($adp in $adpList) {
                if ($adp.metrics) {
                    foreach ($m in $adp.metrics) {
                        if ($m.other) {
                            $mtype = [string]$m.other.type
                            $content = $m.other.content
                            if ($mtype.ToLower() -eq 'ssvc') {
                                if ($content.options) {
                                    foreach ($opt in $content.options) {
                                        if ($opt.Exploitation) { $resultObj.exploitation = $opt.Exploitation.ToLower() }
                                        if ($opt.Automatable) { $resultObj.automatable = (Get-Culture).TextInfo.ToTitleCase($opt.Automatable.ToLower()) }
                                        if ($opt.'Technical Impact') { $resultObj.technical_impact = (Get-Culture).TextInfo.ToTitleCase($opt.'Technical Impact'.ToLower()) }
                                    }
                                }
                                if ($content.timestamp) { $resultObj.ssvc_timestamp = $content.timestamp }
                            } elseif ($mtype.ToLower() -eq 'kev') {
                                $resultObj.kev = "YES"
                                if ($content.dateAdded) { $resultObj.kev_date_added = $content.dateAdded }
                                if ($content.reference) { $resultObj.kev_reference = $content.reference }
                            }
                        }
                    }
                }
            }
        }

        # CWEs
        $cwes = @()
        if ($cna.problemTypes) {
            foreach ($pt in $cna.problemTypes) {
                if ($pt.descriptions) {
                    foreach ($d in $pt.descriptions) {
                        $cid = $d.cweId
                        $name = $d.description
                        if ($cid) { $cwes += if ($name) { "$cid - $name" } else { $cid } }
                        elseif ($name -match "^CWE") { $cwes += $name }
                    }
                }
            }
        }
        $resultObj.cwes = if ($cwes.Count -gt 0) { $cwes } else { @("N/A") }

        # Affected
        $affected = @()
        if ($cna.affected) {
            foreach ($a in $cna.affected) {
                $versions = @()
                if ($a.versions) {
                    foreach ($v in $a.versions) {
                        if ($v.status -eq 'affected') {
                            $ver = $v.version
                            $les = $v.lessThanOrEqual
                            $lt  = $v.lessThan
                            if ($les) { $ver = "<= $les" } elseif ($lt) { $ver = "< $lt" }
                            if ($ver) { $versions += $ver }
                        }
                    }
                }
                $affected += @{ vendor = if ($a.vendor) {$a.vendor} else {"N/A"}; product = if ($a.product) {$a.product} else {"N/A"}; versions = if ($versions.Count -gt 0) {$versions} else {@("(unspecified)")} }
            }
        }
        $resultObj.affected = $affected

        # References
        if ($cna.references) {
            $resultObj.references = $cna.references | Where-Object { $_.url } | Select-Object -ExpandProperty url
        }

        # Assume KEV Override
        if ($AssumeKev -and $resultObj.kev -eq "NO") {
            $resultObj.kev = "YES"
            $resultObj.kev_date_added = "Assumed"
            $resultObj.kev_reference = "N/A"
        }

        # Timeline
        $tlE = Get-BodTimeline $resultObj.kev $true  $resultObj.automatable $resultObj.technical_impact
        $tlN = Get-BodTimeline $resultObj.kev $false $resultObj.automatable $resultObj.technical_impact
        $resultObj.timeline_if_exposed = $tlE[0]; $resultObj.reason_if_exposed = $tlE[1]
        $resultObj.timeline_if_not_exposed = $tlN[0]; $resultObj.reason_if_not_exposed = $tlN[1]

    } catch {
        $resultObj.error = $_.Exception.Message
    }

    $Results.Add($resultObj)
}


# ---------------------------------------------------------------------------
# Filter / Sort
# ---------------------------------------------------------------------------
if ($Recent) {
    if ($KevOnly) {
        $before = $Results.Count
        $filtered = $Results | Where-Object { $_.kev -eq "YES" }
        $Results = if ($filtered) { @($filtered) } else { @() }
        Write-Host "  KEV filter: $($Results.Count) of $before are in the KEV catalog." -ForegroundColor DarkGray
    }
    if ($Limit -gt 0 -and $Results.Count -gt $Limit) {
        $sorted = $Results | Sort-Object -Property @{Expression={if($_.kev -eq 'YES'){0}else{1}}; Ascending=$true}, @{Expression={$SEV_RANK[$_.severity]}; Ascending=$false} | Select-Object -First $Limit
        $Results = if ($sorted) { @($sorted) } else { @() }
        Write-Host "  Capped at $Limit result(s) (KEV-first, then by severity)." -ForegroundColor DarkGray
    }
}

if ($Results.Count -eq 0) {
    Write-Host "No results." -ForegroundColor Yellow
    exit 0
}

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
if ($JsonOut) {
    # Remove metadata keys that start with '_'
    $cleanResults = @()
    foreach ($r in $Results) {
        $obj = New-Object PSObject
        $r.Keys | Where-Object { $_ -notmatch "^_" } | ForEach-Object { $obj | Add-Member -MemberType NoteProperty -Name $_ -Value $r[$_] }
        $cleanResults += $obj
    }
    $cleanResults | ConvertTo-Json -Depth 10
    exit 0
}

foreach ($r in $Results) {
    $ct = $r._change_type
    $dt = $r._date_updated
    if ($ct -and $dt) {
        $r.state = "$($r.state) * $($ct.ToUpper()) $dt"
    }

    if ($Full) {
        if ($r.error) {
            Write-Host "`n[ERROR] $($r.cve_id): $($r.error)`n" -ForegroundColor Red
            continue
        }

        $sep = "-" * 74
        $kevTag = if ($r.kev -eq "YES") { if (-not $NoColor) { "  ${DIM}(added $($r.kev_date_added))${RST}" } else { "  (added $($r.kev_date_added))" } } else { "" }
        
        $hdr = if (-not $NoColor) { "${BOLD}${CYN}$($r.cve_id)${RST}  ${DIM}($($r.state) * Published: $($r.published))${RST}" } else { "$($r.cve_id)  ($($r.state) * Published: $($r.published))" }
        
        Write-Host "`n$hdr`n$sep"
        $desc = $r.description
        if ($desc.Length -gt 117) { $desc = $desc.Substring(0, 117) + "..." }
        Write-Field "Description:" $desc
        
        Write-Host ""
        Write-Section "BOD 26-04 INPUT FIELDS"
        Write-Field "KEV Status:"        "$((Format-Yn $r.kev))$kevTag"
        Write-Field "Automatable:"       "$(Format-Yn $r.automatable)"
        Write-Field "Technical Impact:"  "$(Format-Tech $r.technical_impact)"
        Write-Field "Severity (CVSS):"   "$(Format-Sev $r.severity)  $($r.cvss_score) ($($r.cvss_version))"
        Write-Field "Exploitation:"      "$(Format-Expl $r.exploitation)"

        Write-Host ""
        Write-Section "BOD 26-04 REMEDIATION TIMELINES"
        
        $tlEd = Format-Timeline $r.timeline_if_exposed
        $reaE = if (-not $NoColor) { "  ${DIM}$($r.reason_if_exposed)${RST}" } else { "  $($r.reason_if_exposed)" }
        Write-Field "  > If Asset EXPOSED:" "$tlEd$reaE"

        $tlNd = Format-Timeline $r.timeline_if_not_exposed
        $reaN = if (-not $NoColor) { "  ${DIM}$($r.reason_if_not_exposed)${RST}" } else { "  $($r.reason_if_not_exposed)" }
        Write-Field "  > If Asset NOT Exposed:" "$tlNd$reaN"

        Write-Host ""
        Write-Section "ADDITIONAL CONTEXT"
        Write-Field "CWE(s):"        ($r.cwes -join " | ")
        Write-Field "CVSS Vector:"   $r.cvss_vector
        $ssvcTime = if ($r.ssvc_timestamp -ne "N/A") { $r.ssvc_timestamp.Substring(0,10) } else { "N/A" }
        Write-Field "SSVC Scored:"   $ssvcTime

        Write-Field "Affected Products:" ""
        $bullet = if (-not $NoColor) { "${DIM}*${RST}" } else { "*" }
        for ($i=0; $i -lt [math]::Min($r.affected.Count, 5); $i++) {
            $prod = $r.affected[$i]
            $vers = ($prod.versions | Select-Object -First 3) -join ", "
            Write-Host "    $bullet $($prod.vendor) - $($prod.product) ($vers)"
        }
        if ($r.affected.Count -gt 5) {
            $moreTxt = "  ... and $($r.affected.Count - 5) more"
            if (-not $NoColor) { Write-Host "  ${DIM}${moreTxt}${RST}" } else { Write-Host $moreTxt }
        }

        Write-Field "References:" ""
        for ($i=0; $i -lt [math]::Min($r.references.Count, 4); $i++) {
            Write-Host "    $bullet $($r.references[$i])"
        }
        if ($r.kev_reference -ne "N/A" -and $r.references -notcontains $r.kev_reference) {
            Write-Host "    $bullet [KEV] $($r.kev_reference)"
        }
        Write-Host "$sep`n"
    }
}

# Summary Table
$hdrStr = "{0,-20} {1,-5} {2,-5} {3,-9} {4,-9} {5,-26} {6,-26}" -f "CVE ID", "KEV", "Auto", "Impact", "Sev", "If Exposed", "If Not Exposed"
$sep = "-" * $hdrStr.Length
if (-not $NoColor) { Write-Host "`n${BOLD}BOD 26-04 Summary${RST}`n$sep" } else { Write-Host "`nBOD 26-04 Summary`n$sep" }
Write-Host $hdrStr
Write-Host $sep

$urgent = $false
foreach ($r in $Results) {
    if ($r.error) {
        Write-Host ("{0,-20} ERROR: {1}" -f $r.cve_id, $r.error)
        continue
    }

    $tl_exp = $r.timeline_if_exposed
    $tl_unexp = $r.timeline_if_not_exposed

    if ($tl_exp -match "3 DAYS") { $urgent = $true }

    $rowStr = "{0,-20} {1,-5} {2,-5} {3,-9} {4,-9} {5,-26} {6,-26}" -f $r.cve_id, $r.kev, $r.automatable, $r.technical_impact, $r.severity, $tl_exp, $tl_unexp
    
    if (-not $NoColor) {
        if ($tl_exp -match "3 DAYS")       { Write-Host "${RED}${BOLD}${rowStr}${RST}" }
        elseif ($tl_exp -match "14 DAYS")  { Write-Host "${YEL}${rowStr}${RST}" }
        elseif ($tl_exp -match "30 DAYS")  { Write-Host "${YEL}${rowStr}${RST}" }
        else                               { Write-Host $rowStr }
    } else {
        Write-Host $rowStr
    }
}
Write-Host "$sep`n"

if ($urgent) { exit 1 } else { exit 0 }
