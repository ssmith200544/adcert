# Adcert.psm1 - humane periodic access reviews for AD-backed CUI enclaves.
# Windows PowerShell 5.1 compatible. No dependencies beyond RSAT AD module
# (and that only for collection; scoring/HTML/evidence are pure PowerShell).

Set-StrictMode -Version 2.0

$script:DormantDays = 90
$script:StaleNote = "lastLogonTimestamp replicates lazily and may be up to 14 days stale; treat dormancy as approximate."
$script:Controls = @("AC.L2-3.1.1", "AC.L2-3.1.2")

# ---------------------------------------------------------------- utilities

function Get-UtcNowIso {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+0000")
}

function ConvertFrom-IsoDate {
    param([string]$Iso)
    if ([string]::IsNullOrWhiteSpace($Iso)) { return $null }
    try {
        return [DateTimeOffset]::Parse($Iso,
            [System.Globalization.CultureInfo]::InvariantCulture).UtcDateTime
    } catch { return $null }
}

function Get-Sha256OfFile {
    param([Parameter(Mandatory)][string]$Path)
    (Get-FileHash -Path $Path -Algorithm SHA256).Hash.ToLower()
}

function Get-Sha256OfString {
    param([Parameter(Mandatory)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        ([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-', '').ToLower()
    } finally { $sha.Dispose() }
}

function ConvertTo-CanonicalJson {
    <# Deterministic JSON: object keys sorted, compact separators. Needed so
       attestation hashes are stable regardless of property order. #>
    param([Parameter(Mandatory)][AllowNull()]$Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long] -or $Value -is [double]) {
        return [string]$Value
    }
    if ($Value -is [string]) { return (ConvertTo-Json $Value -Compress) }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($k in ($Value.Keys | Sort-Object)) {
            (ConvertTo-Json ([string]$k) -Compress) + ':' + (ConvertTo-CanonicalJson $Value[$k])
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($item in $Value) { ConvertTo-CanonicalJson $item }
        return '[' + ($parts -join ',') + ']'
    }
    if ($Value -is [pscustomobject]) {
        $parts = foreach ($p in ($Value.PSObject.Properties | Sort-Object Name)) {
            (ConvertTo-Json $p.Name -Compress) + ':' + (ConvertTo-CanonicalJson $p.Value)
        }
        return '{' + ($parts -join ',') + '}'
    }
    return (ConvertTo-Json ([string]$Value) -Compress)
}

function ConvertTo-Hashtable {
    <# 5.1 lacks ConvertFrom-Json -AsHashtable; normalize PSCustomObject trees.

       Two PowerShell traps this deliberately avoids:
       1. -is [pscustomobject] is really -is [psobject], which is true for
          almost every object including arrays. So collections are tested
          FIRST; otherwise an array gets turned into a bag of its own
          metadata properties (Length, Rank, Count) and its real contents
          are lost.
       2. 'return @(...)' unrolls on output, so a single-element array
          collapses to a scalar at the call site. ',$list' forces it to
          stay an array. #>
    param([AllowNull()]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }

    if ($Value -is [System.Collections.IDictionary]) {
        $d = [ordered]@{}
        foreach ($k in $Value.Keys) { $d[[string]$k] = ConvertTo-Hashtable $Value[$k] }
        return $d
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = New-Object System.Collections.ArrayList
        foreach ($item in $Value) { [void]$list.Add((ConvertTo-Hashtable $item)) }
        return ,($list.ToArray())
    }

    $props = $Value.PSObject.Properties
    if ($props) {
        $h = [ordered]@{}
        foreach ($p in $props) { $h[$p.Name] = ConvertTo-Hashtable $p.Value }
        return $h
    }
    return $Value
}

function HtmlEnc {
    param([AllowNull()][string]$s)
    if ($null -eq $s) { return '' }
    [System.Net.WebUtility]::HtmlEncode($s)
}

# ------------------------------------------------------------------ scoring

function Get-EntryRisk {
    <# Returns @{ Risk = int; Flags = string[] } for one membership. #>
    param(
        [Parameter(Mandatory)]$Member,          # hashtable form
        [Parameter(Mandatory)][string]$GroupName,
        [string[]]$PrivilegedGroups = @(),
        [datetime]$Ref = (Get-Date).ToUniversalTime()
    )
    $risk = 0
    $flags = New-Object System.Collections.ArrayList

    $lastLogon = ConvertFrom-IsoDate $Member['last_logon']
    $days = $null
    if ($null -ne $lastLogon) {
        $days = [math]::Max(0, [int]($Ref - $lastLogon).TotalDays)
    }

    if (-not $Member['enabled']) {
        $risk += 50
        [void]$flags.Add("Account is DISABLED but still holds this membership")
    }
    if ($null -eq $days) {
        $risk += 30
        [void]$flags.Add("Account has never logged on")
    } elseif ($days -ge $script:DormantDays) {
        $risk += 20 + [math]::Min(30, [int][math]::Floor($days / 30))
        [void]$flags.Add("Dormant: last logon $days days ago")
    }

    $expires = ConvertFrom-IsoDate $Member['account_expires']
    if ($null -ne $expires) {
        $delta = [int]($expires - $Ref).TotalDays
        if ($delta -lt 0) {
            $risk += 40
            [void]$flags.Add("Account expiration date has passed")
        } elseif ($delta -le 30) {
            $risk += 10
            [void]$flags.Add("Account expires in $delta days")
        }
    }

    if ($PrivilegedGroups -contains $GroupName) {
        $risk = [int]($risk * 1.5) + 5
        [void]$flags.Add("Privileged group")
    }

    @{ Risk = $risk; Flags = @($flags); DaysSinceLogon = $days }
}

# ------------------------------------------------------------------ routing

function Build-ReviewPackages {
    <# Snapshot (hashtable) + config -> list of per-reviewer package hashtables.
       Group->reviewer mapping wins; falls back to the member's own AD manager;
       otherwise '_unrouted'. A reviewer never certifies their own access
       (rerouted to '_escalation' mapping, else '_unrouted'). #>
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][string]$SnapshotSha256,
        [Parameter(Mandatory)]$Config,
        $PriorSnapshot = $null,
        [string]$Campaign = ""
    )
    $ref = (Get-Date).ToUniversalTime()
    if (-not $Campaign) { $Campaign = "UAR-" + $ref.ToString("yyyy-MM") }

    $reviewerMap = @{}
    if ($Config.Contains('reviewers') -and $null -ne $Config['reviewers']) {
        foreach ($k in $Config['reviewers'].Keys) { $reviewerMap[$k] = $Config['reviewers'][$k] }
    }
    # normalize to a plain string array no matter how the JSON deserialized
    $privList = New-Object System.Collections.ArrayList
    if ($Config.Contains('privileged_groups') -and $null -ne $Config['privileged_groups']) {
        foreach ($pg in @($Config['privileged_groups'])) {
            if ($pg -and $pg -is [string]) { [void]$privList.Add($pg) }
        }
    }
    [string[]]$privileged = $privList.ToArray()

    $priorPairs = @{}
    if ($null -ne $PriorSnapshot) {
        foreach ($g in $PriorSnapshot['groups']) {
            foreach ($m in $g['members']) { $priorPairs[$g['name'] + '||' + $m['sam']] = $true }
        }
    }

    $buckets = @{}
    foreach ($g in $Snapshot['groups']) {
        foreach ($m in $g['members']) {
            $reviewer = $null
            if ($reviewerMap.ContainsKey($g['name'])) { $reviewer = $reviewerMap[$g['name']] }
            if (-not $reviewer) { $reviewer = $m['manager_sam'] }
            if (-not $reviewer) { $reviewer = '_unrouted' }
            if ($reviewer -eq $m['sam']) {
                if ($reviewerMap.ContainsKey('_escalation')) { $reviewer = $reviewerMap['_escalation'] }
                else { $reviewer = '_unrouted' }
            }

            $scored = Get-EntryRisk -Member $m -GroupName $g['name'] `
                                    -PrivilegedGroups $privileged -Ref $ref
            $plain = $g['plain_language']
            if (-not $plain) { $plain = $g['ad_description'] }

            $isNew = $false
            if ($PriorSnapshot -and -not $priorPairs.ContainsKey($g['name'] + '||' + $m['sam'])) {
                $isNew = $true
            }

            $entry = [ordered]@{
                group                 = $g['name']
                group_plain           = [string]$plain
                sam                   = $m['sam']
                display_name          = $m['display_name']
                title                 = [string]$m['title']
                department            = [string]$m['department']
                enabled               = [bool]$m['enabled']
                last_logon            = $m['last_logon']
                days_since_logon      = $scored.DaysSinceLogon
                account_expires       = $m['account_expires']
                flags                 = @($scored.Flags)
                risk                  = $scored.Risk
                new_since_last_review = $isNew
            }
            if (-not $buckets.ContainsKey($reviewer)) {
                $buckets[$reviewer] = New-Object System.Collections.ArrayList
            }
            [void]$buckets[$reviewer].Add($entry)
        }
    }

    $packages = New-Object System.Collections.ArrayList
    foreach ($reviewer in ($buckets.Keys | Sort-Object)) {
        $entries = @($buckets[$reviewer] | Sort-Object `
            @{ Expression = { $_['risk'] }; Descending = $true },
            @{ Expression = { $_['group'] } },
            @{ Expression = { $_['sam'] } })
        [void]$packages.Add([ordered]@{
            review_id       = ([guid]::NewGuid().ToString('N').Substring(0, 8))
            reviewer        = $reviewer
            campaign        = $Campaign
            snapshot_sha256 = $SnapshotSha256
            generated_at    = Get-UtcNowIso
            entries         = $entries
        })
    }
    @($packages)
}

# -------------------------------------------------------- reviewer HTML page

$script:ReviewPageTemplate = @'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Review - __REVIEWER__ - __CAMPAIGN__</title>
<style>
  :root {
    --ink:#1b2733; --paper:#f6f7f8; --card:#ffffff; --line:#d7dde3;
    --muted:#5b6b7a; --accent:#7a0019; --accent-ink:#ffffff;
    --ok:#1e7145; --warn:#a15c00; --bad:#a11a1a; --chip:#eef1f4;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--paper); color:var(--ink);
         font:15px/1.5 "Segoe UI", system-ui, sans-serif; }
  header { background:var(--ink); color:#fff; padding:20px 28px; }
  header h1 { margin:0 0 2px; font-size:19px; font-weight:600; letter-spacing:.2px; }
  header .sub { color:#aebbc7; font-size:13px; }
  header .sub code { color:#cdd6de; }
  .wrap { max-width:980px; margin:0 auto; padding:22px 20px 80px; }
  .intro { background:var(--card); border:1px solid var(--line); border-left:4px solid var(--accent);
            border-radius:6px; padding:14px 18px; margin-bottom:18px; font-size:14px; }
  .intro b { color:var(--accent); }
  .prog { position:sticky; top:0; z-index:5; background:var(--paper);
           padding:10px 0 12px; border-bottom:1px solid var(--line); margin-bottom:14px;
           display:flex; align-items:center; gap:14px; }
  .bar { flex:1; height:8px; background:var(--chip); border-radius:4px; overflow:hidden; }
  .bar i { display:block; height:100%; width:0; background:var(--accent); transition:width .2s; }
  .prog span { font-size:13px; color:var(--muted); white-space:nowrap; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:6px;
           padding:14px 18px; margin-bottom:12px; }
  .card.done { opacity:.62; }
  .row1 { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }
  .who b { font-size:16px; }
  .who .meta { color:var(--muted); font-size:13px; }
  .grp { font-size:13px; margin-top:6px; }
  .grp code { background:var(--chip); padding:1px 6px; border-radius:3px; font-size:12px; }
  .grp .plain { color:var(--muted); }
  .chips { margin-top:8px; display:flex; gap:6px; flex-wrap:wrap; }
  .chip { font-size:12px; padding:2px 9px; border-radius:10px; background:var(--chip); color:var(--muted); }
  .chip.bad { background:#fbe9e9; color:var(--bad); font-weight:600; }
  .chip.warn { background:#fdf3e3; color:var(--warn); font-weight:600; }
  .chip.new { background:#e8f0fb; color:#1c4f9c; font-weight:600; }
  .logon { text-align:right; font-size:13px; color:var(--muted); min-width:130px; }
  .logon .big { font-size:15px; font-weight:600; color:var(--ink); }
  .logon .big.bad { color:var(--bad); }
  .acts { margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }
  .acts button { font:inherit; font-size:13px; padding:7px 16px; border-radius:4px;
                  border:1px solid var(--line); background:#fff; cursor:pointer; }
  .acts button:hover { border-color:var(--muted); }
  .acts button.sel-retain { background:var(--ok); border-color:var(--ok); color:#fff; }
  .acts button.sel-revoke { background:var(--bad); border-color:var(--bad); color:#fff; }
  .acts button.sel-modify { background:var(--warn); border-color:var(--warn); color:#fff; }
  .just { margin-top:10px; }
  .just textarea { width:100%; min-height:52px; font:inherit; font-size:13px;
                    border:1px solid var(--line); border-radius:4px; padding:8px; }
  .just label { font-size:12px; color:var(--muted); display:block; margin-bottom:3px; }
  .just.required label { color:var(--bad); font-weight:600; }
  footer { position:fixed; bottom:0; left:0; right:0; background:var(--ink);
            padding:12px 28px; display:flex; align-items:center; gap:16px; }
  footer .status { color:#aebbc7; font-size:13px; flex:1; }
  footer button { font:inherit; font-size:14px; font-weight:600; padding:10px 22px;
                   border:0; border-radius:4px; background:var(--accent); color:var(--accent-ink);
                   cursor:pointer; }
  footer button:disabled { background:#5b6b7a; cursor:not-allowed; }
  .note { color:var(--muted); font-size:12px; margin-top:14px; }
</style>
</head>
<body>
<header>
  <h1>Periodic Access Review</h1>
  <div class="sub">Reviewer: <code>__REVIEWER__</code> &nbsp;&middot;&nbsp; Campaign: __CAMPAIGN__
    &nbsp;&middot;&nbsp; Review ID: <code>__REVIEW_ID__</code></div>
</header>
<div class="wrap">
  <div class="intro">
    You are certifying <b>__N__ access grants</b> for people you supervise.
    For each row decide whether the access is still required. <b>Revoke</b> and
    <b>Modify</b> require a short justification; a comment on Retain is optional
    but encouraged for privileged or dormant accounts. Your decisions become part
    of the enclave's access-control evidence (NIST SP 800-171 3.1.1 / 3.1.2).
  </div>
  <div class="prog"><div class="bar"><i id="fill"></i></div><span id="count"></span></div>
  <div id="list"></div>
  <p class="note">__STALE_NOTE__</p>
</div>
<footer>
  <div class="status" id="footStatus"></div>
  <button id="export" disabled>Export decisions</button>
</footer>
<script>
const PKG = __PAYLOAD__;
const state = {};   // key -> {decision, justification}
const keyOf = e => e.group + "||" + e.sam;

function fmtLogon(e) {
  if (e.days_since_logon === null) return ["Never logged on", true];
  if (e.days_since_logon === 0) return ["Today", false];
  return [e.days_since_logon + " days ago", e.days_since_logon >= 90];
}

function render() {
  const list = document.getElementById("list");
  list.innerHTML = "";
  PKG.entries.forEach(e => {
    const k = keyOf(e);
    const st = state[k] || {};
    const [logonTxt, logonBad] = fmtLogon(e);
    const card = document.createElement("div");
    card.className = "card" + (st.decision ? " done" : "");
    const chips = [];
    if (e.new_since_last_review) chips.push('<span class="chip new">New since last review</span>');
    e.flags.forEach(f => {
      const cls = /DISABLED|expiration|Never/i.test(f) ? "bad"
                : /Dormant|expires|Privileged/i.test(f) ? "warn" : "";
      chips.push('<span class="chip ' + cls + '">' + f + '</span>');
    });
    const needJust = st.decision === "revoke" || st.decision === "modify";
    card.innerHTML = `
      <div class="row1">
        <div class="who">
          <b>${e.display_name}</b> <span class="meta">(${e.sam})</span>
          <div class="meta">${e.title || "&mdash;"} &middot; ${e.department || "&mdash;"}${e.enabled ? "" : " &middot; ACCOUNT DISABLED"}</div>
          <div class="grp">Access: <code>${e.group}</code>
            <span class="plain">&mdash; ${e.group_plain}</span></div>
          <div class="chips">${chips.join("")}</div>
        </div>
        <div class="logon"><div class="big ${logonBad ? "bad" : ""}">${logonTxt}</div>last logon</div>
      </div>
      <div class="acts">
        <button data-d="retain" class="${st.decision === "retain" ? "sel-retain" : ""}">Retain</button>
        <button data-d="revoke" class="${st.decision === "revoke" ? "sel-revoke" : ""}">Revoke</button>
        <button data-d="modify" class="${st.decision === "modify" ? "sel-modify" : ""}">Modify</button>
      </div>
      <div class="just ${needJust ? "required" : ""}">
        <label>${needJust ? "Justification (required)" : "Comment (optional)"}</label>
        <textarea>${st.justification || ""}</textarea>
      </div>`;
    card.querySelectorAll(".acts button").forEach(b => b.onclick = () => {
      state[k] = state[k] || {};
      state[k].decision = b.dataset.d;
      render(); update();
    });
    card.querySelector("textarea").oninput = ev => {
      state[k] = state[k] || {};
      state[k].justification = ev.target.value;
      update();
    };
    list.appendChild(card);
  });
  update();
}

function ready() {
  return PKG.entries.every(e => {
    const st = state[keyOf(e)];
    if (!st || !st.decision) return false;
    if ((st.decision === "revoke" || st.decision === "modify")
        && !(st.justification || "").trim()) return false;
    return true;
  });
}

function update() {
  const done = PKG.entries.filter(e => (state[keyOf(e)] || {}).decision).length;
  document.getElementById("fill").style.width = (100 * done / PKG.entries.length) + "%";
  document.getElementById("count").textContent = done + " / " + PKG.entries.length + " decided";
  const ok = ready();
  document.getElementById("export").disabled = !ok;
  document.getElementById("footStatus").textContent = ok
    ? "All entries decided. Click Export and save the file back into the campaign folder (or send it to your security administrator)."
    : "Export unlocks when every entry has a decision (and justifications where required).";
}

document.getElementById("export").onclick = async () => {
  const out = {
    reviewer: PKG.reviewer,
    review_id: PKG.review_id,
    campaign: PKG.campaign,
    snapshot_sha256: PKG.snapshot_sha256,
    decided_at: new Date().toISOString(),
    decisions: PKG.entries.map(e => {
      const st = state[keyOf(e)];
      return { group: e.group, sam: e.sam,
               decision: st.decision, justification: (st.justification || "").trim() };
    })
  };
  const fname = "decisions_" + PKG.reviewer + "_" + PKG.review_id + ".json";
  const text = JSON.stringify(out, null, 2);
  // Prefer a real Save As dialog (Edge/Chrome) so the reviewer can save
  // straight into the campaign folder; fall back to a plain download.
  if (window.showSaveFilePicker) {
    try {
      const handle = await window.showSaveFilePicker({
        suggestedName: fname,
        types: [{ description: "adcert decisions", accept: { "application/json": [".json"] } }]
      });
      const w = await handle.createWritable();
      await w.write(text);
      await w.close();
      document.getElementById("footStatus").textContent =
        "Saved " + fname + ". If you saved it into the campaign folder, the review is done.";
      return;
    } catch (err) {
      if (err && err.name === "AbortError") return;  // user cancelled
      // fall through to download on any other failure
    }
  }
  const blob = new Blob([text], {type: "application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = fname;
  a.click();
  document.getElementById("footStatus").textContent =
    "Downloaded " + fname + " - move it into the campaign folder.";
};

render();
</script>
</body>
</html>
'@

function New-ReviewHtml {
    param([Parameter(Mandatory)]$Package)
    $payload = ConvertTo-Json $Package -Depth 10 -Compress
    $html = $script:ReviewPageTemplate
    $html = $html.Replace('__PAYLOAD__', $payload)
    $html = $html.Replace('__REVIEWER__', (HtmlEnc $Package['reviewer']))
    $html = $html.Replace('__CAMPAIGN__', (HtmlEnc $Package['campaign']))
    $html = $html.Replace('__REVIEW_ID__', (HtmlEnc $Package['review_id']))
    $html = $html.Replace('__N__', [string]@($Package['entries']).Count)
    $html = $html.Replace('__STALE_NOTE__', (HtmlEnc $script:StaleNote))
    $html
}

# ----------------------------------------------------------------- evidence

function Test-DecisionFile {
    <# Returns string[] of problems (empty = clean). #>
    param(
        [Parameter(Mandatory)]$Decision,        # hashtable form of decisions_*.json
        [Parameter(Mandatory)][string]$SnapshotSha256,
        [Parameter(Mandatory)]$ExpectedPairs    # hashtable set: "group||sam" -> $true
    )
    $problems = New-Object System.Collections.ArrayList
    if ($Decision['snapshot_sha256'] -ne $SnapshotSha256) {
        [void]$problems.Add("decision file references a different snapshot hash (integrity chain broken)")
    }
    $valid = @('retain', 'revoke', 'modify')
    $seen = @{}
    foreach ($d in $Decision['decisions']) {
        $pair = $d['group'] + '||' + $d['sam']
        if ($valid -notcontains $d['decision']) {
            [void]$problems.Add("$pair : invalid decision '$($d['decision'])'")
        }
        if (($d['decision'] -eq 'revoke' -or $d['decision'] -eq 'modify') -and
            [string]::IsNullOrWhiteSpace($d['justification'])) {
            [void]$problems.Add("$pair : '$($d['decision'])' without justification")
        }
        if ($seen.ContainsKey($pair)) { [void]$problems.Add("$pair : duplicate decision") }
        if (-not $ExpectedPairs.ContainsKey($pair)) {
            [void]$problems.Add("$pair : not part of this reviewer's package")
        }
        $seen[$pair] = $true
    }
    foreach ($pair in ($ExpectedPairs.Keys | Sort-Object)) {
        if (-not $seen.ContainsKey($pair)) {
            [void]$problems.Add("$pair : no decision recorded")
        }
    }
    @($problems)
}

function New-Attestation {
    param(
        [Parameter(Mandatory)]$Decision,
        [Parameter(Mandatory)][string]$SnapshotSha256
    )
    $decisions = @()
    foreach ($d in $Decision['decisions']) {
        $decisions += [ordered]@{
            group = $d['group']; sam = $d['sam']
            decision = $d['decision']; justification = [string]$d['justification']
        }
    }
    $body = [ordered]@{
        type               = "adcert.attestation"
        version            = 1
        campaign_review_id = $Decision['review_id']
        reviewer           = $Decision['reviewer']
        decided_at         = $Decision['decided_at']
        compiled_at        = Get-UtcNowIso
        snapshot_sha256    = $SnapshotSha256
        controls           = $script:Controls
        decisions          = $decisions
    }
    $body['attestation_sha256'] = Get-Sha256OfString (ConvertTo-CanonicalJson $body)
    $body
}

function New-RevocationScript {
    param([Parameter(Mandatory)][AllowEmptyCollection()]$Attestations)
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("# adcert revocation worklist - generated $(Get-UtcNowIso)")
    [void]$lines.Add("# Review before executing. Commands run with -WhatIf by default;")
    [void]$lines.Add("# set `$Commit = `$true only after verifying the worklist.")
    [void]$lines.Add('$Commit = $false')
    [void]$lines.Add('$Flag = if ($Commit) { @{} } else { @{ WhatIf = $true } }')
    [void]$lines.Add('Import-Module ActiveDirectory')
    [void]$lines.Add('')
    $n = 0
    foreach ($att in $Attestations) {
        foreach ($d in $att['decisions']) {
            if ($d['decision'] -ne 'revoke') { continue }
            $n++
            $just = ($d['justification'] -replace '[`\r\n]', ' ')
            [void]$lines.Add("# $($d['sam']) <- $($d['group'])  (reviewer: $($att['reviewer'])) - $just")
            [void]$lines.Add("Remove-ADGroupMember -Identity '$($d['group'])' -Members '$($d['sam'])' -Confirm:`$false @Flag")
            [void]$lines.Add('')
        }
    }
    if ($n -eq 0) { [void]$lines.Add('# No revocations were recorded in this campaign.') }
    ($lines -join "`r`n") + "`r`n"
}

$script:ReportTemplate = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Access Review Evidence - __CAMPAIGN__</title>
<style>
 body{font:15px/1.55 Georgia,serif;color:#1b2733;max-width:860px;margin:36px auto;padding:0 20px}
 h1{font-size:23px;border-bottom:3px solid #7a0019;padding-bottom:8px}
 h2{font-size:17px;margin-top:30px}
 table{border-collapse:collapse;width:100%;font-size:14px;font-family:"Segoe UI",sans-serif}
 th,td{border:1px solid #d7dde3;padding:6px 10px;text-align:left;vertical-align:top}
 th{background:#f0f2f4}
 .kv{font-family:"Segoe UI",sans-serif;font-size:14px}
 .kv b{display:inline-block;min-width:220px}
 code{font-size:12px;background:#f0f2f4;padding:1px 5px;border-radius:3px;word-break:break-all}
 .controls{background:#f6f7f8;border-left:4px solid #7a0019;padding:10px 16px;
            font-family:"Segoe UI",sans-serif;font-size:14px}
</style></head><body>
<h1>Periodic Access Review &mdash; Evidence Report</h1>
<p class="kv">
 <b>Campaign:</b> __CAMPAIGN__<br>
 <b>Compiled:</b> __COMPILED__<br>
 <b>Snapshot (SHA-256):</b> <code>__SNAP__</code><br>
 <b>Reviewers completed:</b> __DONE__ of __TOTAL__<br>
 <b>Access grants reviewed:</b> __REVIEWED__
</p>
<div class="controls"><b>Control mapping:</b> This artifact evidences periodic
review of authorized access and enforcement of least privilege under
NIST SP 800-171 / CMMC L2 controls <b>AC.L2-3.1.1</b> (limit system access to
authorized users) and <b>AC.L2-3.1.2</b> (limit access to authorized
transactions and functions). Revocations executed following personnel
separations additionally support <b>PS.L2-3.9.2</b>.</div>
<h2>Decision summary</h2>
<table><tr><th>Decision</th><th>Count</th></tr>__SUMMARY_ROWS__</table>
<h2>Reviewer attestations</h2>
<table><tr><th>Reviewer</th><th>Decided</th><th>Entries</th>
<th>Revoke</th><th>Attestation hash</th></tr>__ATT_ROWS__</table>
<h2>Revocations and modifications</h2>
__REV_SECTION__
<h2>Outstanding reviewers</h2>
__OUTSTANDING__
<p style="color:#5b6b7a;font-family:'Segoe UI',sans-serif;font-size:12px">
Generated by adcert. Integrity chain: snapshot hash &rarr; reviewer decision files &rarr;
attestation hashes above. Recompute any attestation hash from its JSON record
to verify no post-review modification.</p>
</body></html>
'@

function New-EvidenceReport {
    param(
        [Parameter(Mandatory)][string]$Campaign,
        [Parameter(Mandatory)][string]$SnapshotSha256,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Attestations,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedReviewers
    )
    $counts = @{ retain = 0; revoke = 0; modify = 0 }
    $doneReviewers = @{}
    foreach ($a in $Attestations) {
        $doneReviewers[$a['reviewer']] = $true
        foreach ($d in $a['decisions']) { $counts[$d['decision']]++ }
    }
    $outstanding = @($ExpectedReviewers | Where-Object { -not $doneReviewers.ContainsKey($_) })

    $summaryRows = ''
    foreach ($k in @('retain', 'revoke', 'modify')) {
        $label = $k.Substring(0,1).ToUpper() + $k.Substring(1)
        $summaryRows += "<tr><td>$label</td><td>$($counts[$k])</td></tr>"
    }

    $attRows = ''
    foreach ($a in $Attestations) {
        $rev = @($a['decisions'] | Where-Object { $_['decision'] -eq 'revoke' }).Count
        $attRows += "<tr><td>$(HtmlEnc $a['reviewer'])</td>" +
                    "<td>$(HtmlEnc $a['decided_at'])</td>" +
                    "<td>$(@($a['decisions']).Count)</td><td>$rev</td>" +
                    "<td><code>$($a['attestation_sha256'].Substring(0,16))&hellip;</code></td></tr>"
    }
    if (-not $attRows) { $attRows = '<tr><td colspan=5>None returned yet.</td></tr>' }

    $revRows = ''
    foreach ($a in $Attestations) {
        foreach ($d in $a['decisions']) {
            if ($d['decision'] -eq 'revoke' -or $d['decision'] -eq 'modify') {
                $label = $d['decision'].Substring(0,1).ToUpper() + $d['decision'].Substring(1)
                $revRows += "<tr><td>$(HtmlEnc $d['sam'])</td>" +
                            "<td><code>$(HtmlEnc $d['group'])</code></td>" +
                            "<td>$label</td>" +
                            "<td>$(HtmlEnc $a['reviewer'])</td>" +
                            "<td>$(HtmlEnc $d['justification'])</td></tr>"
            }
        }
    }
    $revSection = if ($revRows) {
        '<table><tr><th>Account</th><th>Group</th><th>Decision</th>' +
        '<th>Reviewer</th><th>Justification</th></tr>' + $revRows + '</table>'
    } else { '<p>No revocations or modifications this cycle.</p>' }

    $outHtml = if (@($outstanding).Count -eq 0) {
        '<p>All assigned reviewers have completed their review.</p>'
    } else {
        '<ul>' + (@($outstanding | ForEach-Object { "<li>$(HtmlEnc $_)</li>" }) -join '') + '</ul>'
    }

    $html = $script:ReportTemplate
    $html = $html.Replace('__CAMPAIGN__', (HtmlEnc $Campaign))
    $html = $html.Replace('__COMPILED__', (Get-UtcNowIso))
    $html = $html.Replace('__SNAP__', $SnapshotSha256)
    $html = $html.Replace('__DONE__', [string]$doneReviewers.Count)
    $html = $html.Replace('__TOTAL__', [string]@($ExpectedReviewers).Count)
    $html = $html.Replace('__REVIEWED__', [string]($counts['retain'] + $counts['revoke'] + $counts['modify']))
    $html = $html.Replace('__SUMMARY_ROWS__', $summaryRows)
    $html = $html.Replace('__ATT_ROWS__', $attRows)
    $html = $html.Replace('__REV_SECTION__', $revSection)
    $html = $html.Replace('__OUTSTANDING__', $outHtml)
    $html
}

Export-ModuleMember -Function Get-UtcNowIso, ConvertFrom-IsoDate, Get-Sha256OfFile,
    Get-Sha256OfString, ConvertTo-CanonicalJson, ConvertTo-Hashtable, Get-EntryRisk,
    Build-ReviewPackages, New-ReviewHtml, Test-DecisionFile, New-Attestation,
    New-RevocationScript, New-EvidenceReport
