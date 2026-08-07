# Adcert.psm1 - humane periodic user access reviews for Active Directory.
# Helps satisfy the access-review / access-recertification control common to
# SOC 2, ISO 27001, HIPAA, PCI DSS, NIST 800-53/800-171 and general IT audit.
# Windows PowerShell 5.1 compatible. No dependencies beyond RSAT AD module
# (and that only for collection; scoring/HTML/evidence are pure PowerShell).

Set-StrictMode -Version 2.0

$script:DormantDays = 90
$script:StaleNote = "lastLogonTimestamp replicates lazily and may be up to 14 days stale; treat dormancy as approximate."
# Default compliance framing, used when the config does not supply its own.
# Override per-campaign with a "compliance" block in the config JSON so the
# same tool serves SOC 2, ISO 27001, HIPAA, PCI DSS, NIST, or internal audit.
$script:DefaultCompliance = [ordered]@{
    framework = "User Access Review"
    summary   = "Evidences periodic review of user access rights and enforcement of least privilege, supporting access-recertification controls across common frameworks (SOC 2 CC6.x, ISO 27001 A.5.18, HIPAA 164.308(a)(4), PCI DSS 7, NIST 800-53 AC-2)."
    controls  = @("Periodic access review", "Least-privilege enforcement")
}

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
    of the organization's access-review evidence.
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

// The folder this page was opened from. Reviewers save their decisions file
// back here, so showing the literal path removes the guesswork.
function myFolder() {
  try {
    var p = decodeURIComponent(location.pathname);
    p = p.replace(/^\/([A-Za-z]:)/, "$1");
    p = p.replace(/\/[^\/]*$/, "");
    return p.replace(/\//g, "\\");
  } catch (e) { return ""; }
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
    ? ("All entries decided. Click Export and save the file into: " + (myFolder() || "this page's folder"))
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
        "Saved " + fname + ". Your review is complete - let your administrator know.";
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
    "Downloaded " + fname + " - move it into: " + (myFolder() || "this page's folder");
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
        [Parameter(Mandatory)][string]$SnapshotSha256,
        [string[]]$Controls = @()
    )
    if (-not $Controls -or $Controls.Count -eq 0) { $Controls = @($script:DefaultCompliance.controls) }
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
        controls           = $Controls
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
<div class="controls"><b>Control mapping:</b> __COMPLIANCE_SUMMARY__<br>
<b>Controls covered:</b> __COMPLIANCE_CONTROLS__</div>
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
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$ExpectedReviewers,
        $Compliance = $null
    )
    if ($null -eq $Compliance) { $Compliance = $script:DefaultCompliance }
    $complianceSummary = [string]$Compliance['summary']
    $complianceControls = (@($Compliance['controls']) | ForEach-Object { HtmlEnc $_ }) -join ', '
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
    $html = $html.Replace('__COMPLIANCE_SUMMARY__', (HtmlEnc $complianceSummary))
    $html = $html.Replace('__COMPLIANCE_CONTROLS__', $complianceControls)
    $html
}



# ============================================================== orchestration
# The functions below are the campaign lifecycle. adcert.ps1 is a thin verb
# dispatcher over them, so the user only ever invokes one file.

function Get-AdcertConfig {
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path $Path)) { throw "Config file not found: $Path" }
    ConvertTo-Hashtable (Get-Content -Raw -Path $Path | ConvertFrom-Json)
}

function Get-AdcertCampaignContext {
    <# Loads and cross-checks a campaign folder. Returns a hashtable with the
       manifest, snapshot hash, and resolved paths, or throws with a message
       that says what is wrong. #>
    param([Parameter(Mandatory)][string]$CampaignDir)
    $manifestPath = Join-Path $CampaignDir 'campaign_manifest.json'
    $snapshotPath = Join-Path $CampaignDir 'snapshot.json'
    if (-not (Test-Path $manifestPath)) {
        throw "No campaign_manifest.json in '$CampaignDir' - is this a campaign folder created by 'adcert.ps1 new'?"
    }
    $manifest = ConvertTo-Hashtable (Get-Content -Raw -Path $manifestPath | ConvertFrom-Json)
    $snapHash = Get-Sha256OfFile $snapshotPath
    @{
        ManifestPath = $manifestPath
        SnapshotPath = $snapshotPath
        Manifest     = $manifest
        SnapshotHash = $snapHash
        HashMatches  = ($manifest['snapshot_sha256'] -eq $snapHash)
        EvidenceDir  = (Join-Path $CampaignDir 'evidence')
    }
}

# ------------------------------------------------------------------ preflight

function Invoke-AdcertPreflight {
    <# Data-quality gate. Checks the config, and (unless -SkipAD) the directory,
       for the things that silently degrade a campaign: groups that do not
       exist, missing plain-language descriptions, members with no manager and
       no group mapping (which become _unrouted), reviewer mappings pointing at
       accounts that are not there, and self-certification with no escalation
       target.

       Returns @{ Errors=@(); Warnings=@(); Info=@() } so the caller decides
       how to report and what exit code to use. #>
    param(
        [Parameter(Mandatory)]$Config,
        [switch]$SkipAD
    )
    $errors   = New-Object System.Collections.ArrayList
    $warnings = New-Object System.Collections.ArrayList
    $info     = New-Object System.Collections.ArrayList

    # ---- config shape
    if (-not $Config.Contains('groups') -or -not @($Config['groups']).Count) {
        [void]$errors.Add("Config has no 'groups' list - nothing would be collected.")
        return @{ Errors = @($errors); Warnings = @($warnings); Info = @($info) }
    }

    $configured = New-Object System.Collections.ArrayList
    foreach ($g in $Config['groups']) {
        if (-not $g.Contains('name') -or -not $g['name']) {
            [void]$errors.Add("A group entry in the config has no 'name'.")
            continue
        }
        [void]$configured.Add($g['name'])
        if (-not $g.Contains('plain_language') -or
            [string]::IsNullOrWhiteSpace([string]$g['plain_language'])) {
            [void]$warnings.Add("Group '$($g['name'])' has no plain_language description - reviewers will see the raw group name and the AD description only.")
        }
    }
    [void]$info.Add("Config lists $(@($configured).Count) group(s) for review.")

    $reviewerMap = @{}
    if ($Config.Contains('reviewers') -and $null -ne $Config['reviewers']) {
        foreach ($k in $Config['reviewers'].Keys) { $reviewerMap[$k] = $Config['reviewers'][$k] }
    }
    foreach ($k in $reviewerMap.Keys) {
        if ($k -eq '_escalation') { continue }
        if ($configured -notcontains $k) {
            [void]$warnings.Add("Reviewer mapping targets group '$k', which is not in the config's group list - that mapping will never be used.")
        }
    }
    if ($Config.Contains('privileged_groups')) {
        foreach ($pg in @($Config['privileged_groups'])) {
            if ($pg -and $configured -notcontains $pg) {
                [void]$warnings.Add("privileged_groups names '$pg', which is not in the config's group list - no entry will get the privileged multiplier from it.")
            }
        }
    }
    if (-not $reviewerMap.ContainsKey('_escalation')) {
        [void]$warnings.Add("No '_escalation' reviewer is configured. If a reviewer would have to certify their own access, that entry falls to '_unrouted' instead of a named person.")
    }

    if ($SkipAD) {
        [void]$info.Add("Directory checks skipped (-SkipAD).")
        return @{ Errors = @($errors); Warnings = @($warnings); Info = @($info) }
    }

    # ---- directory checks
    try { Import-Module ActiveDirectory -ErrorAction Stop }
    catch {
        [void]$errors.Add("The ActiveDirectory module could not be loaded. Install RSAT (Add-WindowsFeature RSAT-AD-PowerShell) or re-run with -SkipAD for config-only checks.")
        return @{ Errors = @($errors); Warnings = @($warnings); Info = @($info) }
    }

    foreach ($sam in ($reviewerMap.Values | Sort-Object -Unique)) {
        if (-not $sam) { continue }
        if (-not (Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue)) {
            [void]$warnings.Add("Configured reviewer '$sam' does not exist in Active Directory - their review package would be addressed to nobody.")
        }
    }

    $totalGrants = 0
    $noOwner     = New-Object System.Collections.ArrayList
    $disabled    = New-Object System.Collections.ArrayList
    $selfCert    = New-Object System.Collections.ArrayList
    $seenUser    = @{}

    foreach ($gName in $configured) {
        $adGroup = Get-ADGroup -Filter "Name -eq '$gName'" -ErrorAction SilentlyContinue
        if (-not $adGroup) {
            [void]$errors.Add("Group '$gName' does not exist in Active Directory - it would be skipped and its access never reviewed.")
            continue
        }
        $members = @(Get-ADGroupMember -Identity $gName -Recursive -ErrorAction SilentlyContinue |
                     Where-Object objectClass -eq 'user')
        if (-not $members.Count) {
            [void]$warnings.Add("Group '$gName' has no user members - it will produce no review entries.")
            continue
        }
        foreach ($m in $members) {
            $totalGrants++
            $u = Get-ADUser -Identity $m.SamAccountName -Properties Manager, Enabled -ErrorAction SilentlyContinue
            if (-not $u) { continue }
            $mgrSam = ""
            if ($u.Manager) {
                try { $mgrSam = (Get-ADUser -Identity $u.Manager -ErrorAction Stop).SamAccountName } catch { $mgrSam = "" }
            }
            $mapped = $reviewerMap[$gName]
            if (-not $mapped -and -not $mgrSam) {
                [void]$noOwner.Add("$($u.SamAccountName) in $gName")
            }
            if ($mapped -and $mapped -eq $u.SamAccountName) {
                [void]$selfCert.Add("$($u.SamAccountName) would review their own membership in $gName")
            }
            if (-not $u.Enabled -and -not $seenUser.ContainsKey($u.SamAccountName)) {
                [void]$disabled.Add($u.SamAccountName)
            }
            $seenUser[$u.SamAccountName] = $true
        }
    }

    [void]$info.Add("$totalGrants access grant(s) across $(@($configured).Count) group(s), $($seenUser.Count) distinct account(s).")

    if ($noOwner.Count) {
        [void]$warnings.Add("$($noOwner.Count) grant(s) have no manager set and no group mapping - these land in the '_unrouted' package and need manual assignment: " + (($noOwner | Select-Object -First 8) -join '; ') + $(if ($noOwner.Count -gt 8) { " ... and $($noOwner.Count - 8) more" } else { "" }))
    } else {
        [void]$info.Add("Every grant routes to a named reviewer.")
    }
    if ($selfCert.Count) {
        [void]$warnings.Add("$($selfCert.Count) self-certification case(s) detected; they will be rerouted: " + (($selfCert | Select-Object -First 5) -join '; '))
    }
    if ($disabled.Count) {
        [void]$info.Add("$($disabled.Count) disabled account(s) still hold membership - expect these at the top of the review.")
    }

    @{ Errors = @($errors); Warnings = @($warnings); Info = @($info) }
}

# ------------------------------------------------------------------- confirm

function Get-AdcertRevocations {
    <# Pulls every 'revoke' decision out of a compiled attestations file. #>
    param([Parameter(Mandatory)][string]$AttestationsPath)
    if (-not (Test-Path $AttestationsPath)) {
        throw "No attestations.json at '$AttestationsPath' - run 'adcert.ps1 compile' first."
    }
    $atts = ConvertTo-Hashtable (Get-Content -Raw -Path $AttestationsPath | ConvertFrom-Json)
    $out = New-Object System.Collections.ArrayList
    foreach ($a in @($atts)) {
        foreach ($d in @($a['decisions'])) {
            if ($d['decision'] -eq 'revoke') {
                [void]$out.Add([ordered]@{
                    group         = $d['group']
                    sam           = $d['sam']
                    reviewer      = $a['reviewer']
                    justification = [string]$d['justification']
                    decided_at    = $a['decided_at']
                })
            }
        }
    }
    ,@($out.ToArray())
}

function Test-AdcertRevocationApplied {
    <# Re-queries the directory for one revoked grant. Returns a status string:
       removed | still_present | group_missing | user_missing | unknown #>
    param(
        [Parameter(Mandatory)][string]$Group,
        [Parameter(Mandatory)][string]$Sam
    )
    if (-not (Get-ADGroup -Filter "Name -eq '$Group'" -ErrorAction SilentlyContinue)) {
        return 'group_missing'
    }
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$Sam'" -ErrorAction SilentlyContinue)) {
        return 'user_missing'
    }
    $members = @(Get-ADGroupMember -Identity $Group -Recursive -ErrorAction SilentlyContinue |
                 Where-Object objectClass -eq 'user' |
                 ForEach-Object { $_.SamAccountName })
    if ($members -contains $Sam) { return 'still_present' }
    return 'removed'
}

$script:RemediationTemplate = @'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>Remediation Verification - __CAMPAIGN__</title>
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
 .ok{color:#1e7145;font-weight:600}
 .bad{color:#a11a1a;font-weight:600}
 .warn{color:#a15c00;font-weight:600}
 .banner{background:#f6f7f8;border-left:4px solid #7a0019;padding:10px 16px;
         font-family:"Segoe UI",sans-serif;font-size:14px}
</style></head><body>
<h1>Remediation Verification</h1>
<p class="kv">
 <b>Campaign:</b> __CAMPAIGN__<br>
 <b>Verified:</b> __CHECKED__<br>
 <b>Directory:</b> __DOMAIN__<br>
 <b>Revocations decided:</b> __TOTAL__<br>
 <b>Confirmed applied:</b> __APPLIED__<br>
 <b>Still outstanding:</b> __OUTSTANDING__
</p>
<div class="banner"><b>Why this exists:</b> an access review is only a control
if the decisions take effect. This artifact re-queries the directory after the
fact and records, per revoked grant, whether the access was actually removed.
It closes the loop between the reviewer's decision and the state of the system.</div>
<h2>Revoked grants</h2>
<table><tr><th>Account</th><th>Group</th><th>Reviewer</th><th>Status</th><th>Justification</th></tr>
__ROWS__
</table>
<p style="color:#5b6b7a;font-family:'Segoe UI',sans-serif;font-size:12px">
Generated by adcert. Status is read live from Active Directory at the time
shown above; re-run the verification at any point to refresh it.</p>
</body></html>
'@

function New-RemediationReport {
    param(
        [Parameter(Mandatory)][string]$Campaign,
        [Parameter(Mandatory)][string]$Domain,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Results
    )
    $labels = @{
        removed       = '<span class="ok">Removed</span>'
        still_present = '<span class="bad">STILL PRESENT</span>'
        group_missing = '<span class="warn">Group no longer exists</span>'
        user_missing  = '<span class="warn">Account no longer exists</span>'
        unknown       = '<span class="warn">Unknown</span>'
    }
    $rows = ''
    $applied = 0
    foreach ($r in $Results) {
        $st = [string]$r['status']
        if ($st -eq 'removed' -or $st -eq 'user_missing' -or $st -eq 'group_missing') { $applied++ }
        $lbl = $labels[$st]
        if (-not $lbl) { $lbl = $labels['unknown'] }
        $rows += "<tr><td>$(HtmlEnc $r['sam'])</td><td><code>$(HtmlEnc $r['group'])</code></td>" +
                 "<td>$(HtmlEnc $r['reviewer'])</td><td>$lbl</td>" +
                 "<td>$(HtmlEnc $r['justification'])</td></tr>"
    }
    if (-not $rows) { $rows = '<tr><td colspan=5>No revocations were recorded in this campaign.</td></tr>' }

    $html = $script:RemediationTemplate
    $html = $html.Replace('__CAMPAIGN__', (HtmlEnc $Campaign))
    $html = $html.Replace('__CHECKED__', (Get-UtcNowIso))
    $html = $html.Replace('__DOMAIN__', (HtmlEnc $Domain))
    $html = $html.Replace('__TOTAL__', [string]@($Results).Count)
    $html = $html.Replace('__APPLIED__', [string]$applied)
    $html = $html.Replace('__OUTSTANDING__', [string](@($Results).Count - $applied))
    $html = $html.Replace('__ROWS__', $rows)
    $html
}

# -------------------------------------------------------------------- verify

function Test-AdcertChain {
    <# Independent verification of the evidence integrity chain. Returns a list
       of @{ link; detail; ok } so an auditor can confirm nothing was edited
       after the fact without having to trust the tool that produced it. #>
    param([Parameter(Mandatory)][string]$CampaignDir)
    $results = New-Object System.Collections.ArrayList
    $ctx = Get-AdcertCampaignContext -CampaignDir $CampaignDir

    [void]$results.Add(@{ link = 'snapshot -> manifest'
        detail = "snapshot.json hashes to $($ctx.SnapshotHash.Substring(0,16))..."
        ok = $ctx.HashMatches })

    foreach ($pj in (Get-ChildItem -Path $CampaignDir -Filter 'review_*.json' -Recurse -ErrorAction SilentlyContinue)) {
        $pkg = ConvertTo-Hashtable (Get-Content -Raw -Path $pj.FullName | ConvertFrom-Json)
        [void]$results.Add(@{ link = "review package: $($pkg['reviewer'])"
            detail = $pj.Name
            ok = ($pkg['snapshot_sha256'] -eq $ctx.SnapshotHash) })
    }

    foreach ($dj in (Get-ChildItem -Path $CampaignDir -Filter 'decisions_*.json' -Recurse -ErrorAction SilentlyContinue |
                     Where-Object { $_.FullName -notlike (Join-Path $ctx.EvidenceDir '*') })) {
        $df = ConvertTo-Hashtable (Get-Content -Raw -Path $dj.FullName | ConvertFrom-Json)
        [void]$results.Add(@{ link = "decision file: $($df['reviewer'])"
            detail = $dj.Name
            ok = ($df['snapshot_sha256'] -eq $ctx.SnapshotHash) })
    }

    $attPath = Join-Path $ctx.EvidenceDir 'attestations.json'
    if (Test-Path $attPath) {
        $atts = ConvertTo-Hashtable (Get-Content -Raw -Path $attPath | ConvertFrom-Json)
        foreach ($a in @($atts)) {
            $recorded = [string]$a['attestation_sha256']
            $body = [ordered]@{}
            foreach ($k in $a.Keys) { if ($k -ne 'attestation_sha256') { $body[$k] = $a[$k] } }
            $recomputed = Get-Sha256OfString (ConvertTo-CanonicalJson $body)
            [void]$results.Add(@{ link = "attestation: $($a['reviewer'])"
                detail = "recorded $($recorded.Substring(0,16))... / recomputed $($recomputed.Substring(0,16))..."
                ok = ($recorded -eq $recomputed) })
        }
    }
    ,@($results.ToArray())
}

# ------------------------------------------------------------------ campaign

function Get-AdcertSnapshot {
    <# Collects membership for the configured groups from Active Directory.
       -Recursive resolves nested groups so nesting cannot hide a grant. #>
    param([Parameter(Mandatory)]$Config)
    Import-Module ActiveDirectory -ErrorAction Stop

    $groups = @()
    foreach ($entry in $Config['groups']) {
        $gName = $entry['name']
        try { $adGroup = Get-ADGroup -Identity $gName -Properties Description }
        catch { Write-Warning "Group not found, skipping: $gName"; continue }

        $members = @()
        foreach ($u in (Get-ADGroupMember -Identity $gName -Recursive |
                        Where-Object objectClass -eq 'user')) {
            $user = Get-ADUser -Identity $u.SamAccountName -Properties `
                DisplayName, Title, Department, Manager, Enabled, `
                lastLogonTimestamp, lastLogon, pwdLastSet, whenCreated, accountExpires

            # Take the more recent of the replicated (lastLogonTimestamp) and
            # per-DC (lastLogon) attributes. On a single-DC domain the per-DC
            # value updates immediately, so labs and small sites see fresh
            # activity instead of the up-to-14-day replication lag.
            $llt = 0; $ll = 0
            if ($user.lastLogonTimestamp) { $llt = [long]$user.lastLogonTimestamp }
            if ($user.lastLogon)          { $ll  = [long]$user.lastLogon }
            $best = [math]::Max($llt, $ll)

            $managerSam = ""
            if ($user.Manager) {
                try { $managerSam = (Get-ADUser -Identity $user.Manager).SamAccountName }
                catch { $managerSam = "" }
            }

            $members += [ordered]@{
                sam             = $user.SamAccountName
                display_name    = "$($user.DisplayName)"
                title           = "$($user.Title)"
                department      = "$($user.Department)"
                manager_sam     = $managerSam
                enabled         = [bool]$user.Enabled
                last_logon      = Convert-AdFileTimeIso $best
                pwd_last_set    = Convert-AdFileTimeIso $user.pwdLastSet
                when_created    = $user.whenCreated.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+0000")
                account_expires = Convert-AdFileTimeIso $user.accountExpires
            }
        }

        $groups += [ordered]@{
            name           = $gName
            ad_description = "$($adGroup.Description)"
            plain_language = "$($entry['plain_language'])"
            members        = @($members | Sort-Object { $_['sam'] })
        }
        Write-Host "[+] Collected $gName ($(@($members).Count) members)"
    }

    [ordered]@{
        generated_at = Get-UtcNowIso
        source       = "AD:$((Get-ADDomain).DNSRoot)"
        groups       = $groups
    }
}

function Convert-AdFileTimeIso {
    param($ft)
    if (-not $ft -or $ft -eq 0 -or $ft -eq 0x7FFFFFFFFFFFFFFF) { return $null }
    [DateTime]::FromFileTimeUtc($ft).ToString("yyyy-MM-ddTHH:mm:ss+0000")
}

function Invoke-AdcertCampaign {
    <# Collects, scores, routes, and writes a complete campaign folder. #>
    param(
        [Parameter(Mandatory)]$Config,
        [Parameter(Mandatory)][string]$OutDir,
        [string]$Campaign = "",
        [string]$PriorSnapshot = "",
        [string]$InputSnapshot = ""
    )
    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    $snapshotPath = Join-Path $OutDir 'snapshot.json'

    if ($InputSnapshot) {
        Copy-Item -Path $InputSnapshot -Destination $snapshotPath -Force
        Write-Host "[=] Using existing snapshot: $InputSnapshot"
    } else {
        $snapshot = Get-AdcertSnapshot -Config $Config
        ConvertTo-Json $snapshot -Depth 10 | Set-Content -Path $snapshotPath -Encoding UTF8
    }

    $snapHash = Get-Sha256OfFile $snapshotPath
    Write-Host "[+] Snapshot: $snapshotPath"
    Write-Host "    SHA-256: $snapHash"

    $snap = ConvertTo-Hashtable (Get-Content -Raw -Path $snapshotPath | ConvertFrom-Json)

    $prior = $null
    if ($PriorSnapshot) {
        $prior = ConvertTo-Hashtable (Get-Content -Raw -Path $PriorSnapshot | ConvertFrom-Json)
        Write-Host "[+] Diffing against prior snapshot: $PriorSnapshot"
    }

    $packages = Build-ReviewPackages -Snapshot $snap -SnapshotSha256 $snapHash `
                                     -Config $Config -PriorSnapshot $prior -Campaign $Campaign

    $manifest = [ordered]@{
        campaign        = if (@($packages).Count) { $packages[0]['campaign'] } else { $Campaign }
        snapshot_sha256 = $snapHash
        reviewers       = @()
    }
    # carry the compliance framing (if the config supplies one) into the manifest
    # so the evidence report is mapped to whatever framework this campaign serves
    if ($Config.Contains('compliance') -and $null -ne $Config['compliance']) {
        $manifest['compliance'] = $Config['compliance']
    }
    # One subfolder per reviewer. Keeps the campaign root to three items and
    # gives each reviewer a single folder to be sent, and an obvious place to
    # save their decisions file back to.
    $reviewersRoot = Join-Path $OutDir 'reviewers'
    New-Item -ItemType Directory -Path $reviewersRoot -Force | Out-Null
    foreach ($pkg in $packages) {
        $who = $pkg['reviewer']
        $folder = Join-Path $reviewersRoot $who
        New-Item -ItemType Directory -Path $folder -Force | Out-Null
        $base = Join-Path $folder ("review_{0}" -f $who)
        ConvertTo-Json $pkg -Depth 10 | Set-Content -Path "$base.json" -Encoding UTF8
        New-ReviewHtml -Package $pkg | Set-Content -Path "$base.html" -Encoding UTF8
        $manifest['reviewers'] += $who
        $tag = ""
        if ($who -eq '_unrouted') { $tag = "  [UNROUTED - assign manually]" }
        Write-Host ("[+] {0,-16} {1,3} entries -> reviewers\{0}\{2}{3}" -f `
            $who, @($pkg['entries']).Count, (Split-Path "$base.html" -Leaf), $tag)
    }
    ConvertTo-Json $manifest -Depth 5 |
        Set-Content -Path (Join-Path $OutDir 'campaign_manifest.json') -Encoding UTF8

    New-CampaignReadme -Manifest $manifest -Packages $packages |
        Set-Content -Path (Join-Path $OutDir 'README.txt') -Encoding UTF8

    (Resolve-Path $OutDir).Path
}

function New-CampaignReadme {
    <# A plain-language map of the campaign folder, dropped in the root so
       anyone who opens it knows what they are looking at without the docs. #>
    param(
        [Parameter(Mandatory)]$Manifest,
        [Parameter(Mandatory)][AllowEmptyCollection()]$Packages
    )
    $lines = New-Object System.Collections.ArrayList
    [void]$lines.Add("ACCESS REVIEW CAMPAIGN: $($Manifest['campaign'])")
    [void]$lines.Add("Created: $(Get-UtcNowIso)")
    [void]$lines.Add("")
    [void]$lines.Add("WHAT IS IN THIS FOLDER")
    [void]$lines.Add("  reviewers\              one subfolder per reviewer")
    foreach ($pkg in $Packages) {
        [void]$lines.Add(("    {0,-16} {1} access grant(s) to review" -f $pkg['reviewer'], @($pkg['entries']).Count))
    }
    [void]$lines.Add("  snapshot.json           what the directory looked like at collection time")
    [void]$lines.Add("  campaign_manifest.json  campaign metadata (do not edit)")
    [void]$lines.Add("  evidence\               created later, when decisions are compiled")
    [void]$lines.Add("")
    [void]$lines.Add("IF YOU ARE A REVIEWER")
    [void]$lines.Add("  1. Open the review_<yourname>.html file in your own subfolder.")
    [void]$lines.Add("     Any browser works. Nothing is installed and nothing is sent anywhere.")
    [void]$lines.Add("  2. Decide every row: Retain, Revoke, or Modify.")
    [void]$lines.Add("     Revoke and Modify need a short written reason.")
    [void]$lines.Add("  3. Click 'Export decisions' and save the file into that same subfolder.")
    [void]$lines.Add("     The page shows you the exact path to save to.")
    [void]$lines.Add("")
    [void]$lines.Add("IF YOU ARE THE ADMINISTRATOR")
    [void]$lines.Add("  Send reviewers their folder:   .\adcert.ps1 send <this folder>")
    [void]$lines.Add("  Rescue files from Downloads:   .\adcert.ps1 collect <this folder>")
    [void]$lines.Add("  Compile the evidence:          .\adcert.ps1 compile <this folder>")
    [void]$lines.Add("  Confirm revocations applied:   .\adcert.ps1 confirm <this folder>")
    [void]$lines.Add("  Re-check the integrity chain:  .\adcert.ps1 verify <this folder>")
    [void]$lines.Add("")
    [void]$lines.Add("Do not edit any file in this folder by hand. Every artifact is")
    [void]$lines.Add("hash-chained to the snapshot, and manual edits will fail verification.")
    ($lines -join "`r`n") + "`r`n"
}

# ------------------------------------------------------------------- compile

function Invoke-AdcertCompile {
    <# Validates returned decision files and writes the evidence set.
       Returns @{ Outstanding=@(); StrictFail=$bool; EvidenceDir=path } #>
    param(
        [Parameter(Mandatory)][string]$CampaignDir,
        [string]$DecisionsDir = "",
        [string]$OutDir = "",
        [switch]$Strict
    )
    $ctx = Get-AdcertCampaignContext -CampaignDir $CampaignDir
    if (-not $ctx.HashMatches) {
        throw "snapshot.json in '$CampaignDir' does not match the manifest hash - wrong or modified file."
    }
    $manifest = $ctx.Manifest
    $snapHash = $ctx.SnapshotHash
    if (-not $OutDir) { $OutDir = $ctx.EvidenceDir }

    # expected (group||sam) pairs per reviewer, from the review packages
    $expected = @{}
    foreach ($pj in (Get-ChildItem -Path $CampaignDir -Filter 'review_*.json' -Recurse)) {
        $pkg = ConvertTo-Hashtable (Get-Content -Raw -Path $pj.FullName | ConvertFrom-Json)
        $pairs = @{}
        foreach ($e in $pkg['entries']) { $pairs[$e['group'] + '||' + $e['sam']] = $true }
        $expected[$pkg['reviewer']] = $pairs
    }

    if ($DecisionsDir) {
        $decisionFiles = @(Get-ChildItem -Path $DecisionsDir -Filter 'decisions_*.json' -Recurse)
    } else {
        $decisionFiles = @(Get-ChildItem -Path $CampaignDir -Filter 'decisions_*.json' -Recurse |
                           Where-Object { $_.FullName -notlike (Join-Path $OutDir '*') })
    }
    if (-not $decisionFiles.Count) {
        Write-Host "[!] No decisions_*.json files found in $CampaignDir yet." -ForegroundColor Yellow
        Write-Host "    Reviewers export them from their review_*.html page; save or copy"
        Write-Host "    them anywhere inside the campaign folder, then run this again."
    }

    $controls = @()
    if ($manifest.Contains('compliance') -and $null -ne $manifest['compliance'] -and
        $manifest['compliance'].Contains('controls')) {
        $controls = @($manifest['compliance']['controls'])
    }

    $attestations = New-Object System.Collections.ArrayList
    $strictFail = $false
    foreach ($dfile in ($decisionFiles | Sort-Object Name)) {
        $df = ConvertTo-Hashtable (Get-Content -Raw -Path $dfile.FullName | ConvertFrom-Json)
        $pairs = $expected[$df['reviewer']]
        if ($null -eq $pairs) { $pairs = @{} }
        $problems = Test-DecisionFile -Decision $df -SnapshotSha256 $snapHash -ExpectedPairs $pairs
        if (@($problems).Count) {
            Write-Host "[!] $($dfile.Name):" -ForegroundColor Yellow
            foreach ($p in $problems) { Write-Host "      - $p" -ForegroundColor Yellow }
            if ($Strict) { $strictFail = $true; continue }
        }
        [void]$attestations.Add((New-Attestation -Decision $df -SnapshotSha256 $snapHash -Controls $controls))
        Write-Host "[+] Attested: $($df['reviewer']) ($(@($df['decisions']).Count) decisions)"
    }

    $compliance = $null
    if ($manifest.Contains('compliance')) { $compliance = $manifest['compliance'] }

    New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
    ConvertTo-Json @($attestations) -Depth 10 |
        Set-Content -Path (Join-Path $OutDir 'attestations.json') -Encoding UTF8
    New-RevocationScript -Attestations @($attestations) |
        Set-Content -Path (Join-Path $OutDir 'revocation_worklist.ps1') -Encoding UTF8
    New-EvidenceReport -Campaign $manifest['campaign'] -SnapshotSha256 $snapHash `
        -Attestations @($attestations) -ExpectedReviewers @($manifest['reviewers']) `
        -Compliance $compliance |
        Set-Content -Path (Join-Path $OutDir 'evidence_report.html') -Encoding UTF8

    $done = @{}
    foreach ($a in $attestations) { $done[$a['reviewer']] = $true }
    $outstanding = @($manifest['reviewers'] | Where-Object { -not $done.ContainsKey($_) })

    @{ Outstanding = @($outstanding); StrictFail = $strictFail; EvidenceDir = $OutDir }
}

function Invoke-AdcertConfirm {
    <# Re-queries the directory for every revoked grant and records whether the
       access was actually removed. Returns the result rows. #>
    param([Parameter(Mandatory)][string]$CampaignDir)
    Import-Module ActiveDirectory -ErrorAction Stop
    $ctx = Get-AdcertCampaignContext -CampaignDir $CampaignDir
    $revocations = Get-AdcertRevocations -AttestationsPath (Join-Path $ctx.EvidenceDir 'attestations.json')

    $results = New-Object System.Collections.ArrayList
    foreach ($r in $revocations) {
        $status = Test-AdcertRevocationApplied -Group $r['group'] -Sam $r['sam']
        $row = [ordered]@{
            sam = $r['sam']; group = $r['group']; reviewer = $r['reviewer']
            justification = $r['justification']; decided_at = $r['decided_at']
            status = $status; checked_at = Get-UtcNowIso
        }
        [void]$results.Add($row)
    }

    $domain = (Get-ADDomain).DNSRoot
    New-Item -ItemType Directory -Path $ctx.EvidenceDir -Force | Out-Null
    ConvertTo-Json @($results) -Depth 5 |
        Set-Content -Path (Join-Path $ctx.EvidenceDir 'remediation_status.json') -Encoding UTF8
    New-RemediationReport -Campaign $ctx.Manifest['campaign'] -Domain $domain -Results @($results) |
        Set-Content -Path (Join-Path $ctx.EvidenceDir 'remediation_report.html') -Encoding UTF8

    ,@($results.ToArray())
}


# ---------------------------------------------------------------- exports
Export-ModuleMember -Function `
    Get-UtcNowIso, ConvertFrom-IsoDate, Get-Sha256OfFile, Get-Sha256OfString, `
    ConvertTo-CanonicalJson, ConvertTo-Hashtable, Get-EntryRisk, `
    Build-ReviewPackages, New-ReviewHtml, Test-DecisionFile, New-Attestation, `
    New-RevocationScript, New-EvidenceReport, `
    Get-AdcertConfig, Get-AdcertCampaignContext, `
    Invoke-AdcertPreflight, Invoke-AdcertCampaign, Invoke-AdcertCompile, `
    Invoke-AdcertConfirm, Get-AdcertRevocations, Test-AdcertRevocationApplied, `
    New-RemediationReport, Test-AdcertChain, Get-AdcertSnapshot, `
    New-CampaignReadme, Get-AdcertReviewerFolder, Invoke-AdcertCollect, `
    Get-AdcertReviewerEmail, Send-AdcertReviews

# --------------------------------------------------------- collect / deliver

function Get-AdcertReviewerFolder {
    <# Where a given reviewer's package lives. Falls back to the campaign root
       for campaigns created before the per-reviewer layout. #>
    param(
        [Parameter(Mandatory)][string]$CampaignDir,
        [Parameter(Mandatory)][string]$Reviewer
    )
    $sub = Join-Path (Join-Path $CampaignDir 'reviewers') $Reviewer
    if (Test-Path $sub) { return $sub }
    $CampaignDir
}

function Invoke-AdcertCollect {
    <# Reviewers' browsers often drop the exported decisions file into
       Downloads instead of the campaign folder. This finds those files,
       checks that each one actually belongs to this campaign (snapshot hash
       and a known reviewer), and files it into that reviewer's subfolder.

       Returns a list of @{ File; Reviewer; Action; Reason }. #>
    param(
        [Parameter(Mandatory)][string]$CampaignDir,
        [string]$From = "",
        [switch]$DryRun
    )
    $ctx = Get-AdcertCampaignContext -CampaignDir $CampaignDir
    $known = @{}
    foreach ($r in @($ctx.Manifest['reviewers'])) { $known[$r] = $true }

    $searchDirs = New-Object System.Collections.ArrayList
    if ($From) {
        [void]$searchDirs.Add($From)
    } else {
        foreach ($d in @("$env:USERPROFILE\Downloads", "$env:USERPROFILE\Desktop",
                         "$env:USERPROFILE\Documents")) {
            if (Test-Path $d) { [void]$searchDirs.Add($d) }
        }
    }

    $results = New-Object System.Collections.ArrayList
    foreach ($dir in $searchDirs) {
        if (-not (Test-Path $dir)) { continue }
        foreach ($f in (Get-ChildItem -Path $dir -Filter 'decisions_*.json' -ErrorAction SilentlyContinue)) {
            $reason = ''; $action = 'skipped'; $reviewer = ''
            try {
                $df = ConvertTo-Hashtable (Get-Content -Raw -Path $f.FullName | ConvertFrom-Json)
                $reviewer = [string]$df['reviewer']
                if ($df['snapshot_sha256'] -ne $ctx.SnapshotHash) {
                    $reason = 'belongs to a different campaign'
                } elseif (-not $known.ContainsKey($reviewer)) {
                    $reason = "reviewer '$reviewer' is not part of this campaign"
                } else {
                    $dest = Get-AdcertReviewerFolder -CampaignDir $CampaignDir -Reviewer $reviewer
                    $target = Join-Path $dest $f.Name
                    if ($DryRun) {
                        $action = 'would move'; $reason = $target
                    } else {
                        Move-Item -Path $f.FullName -Destination $target -Force
                        $action = 'moved'; $reason = $target
                    }
                }
            } catch {
                $reason = 'not readable as an adcert decisions file'
            }
            [void]$results.Add(@{ File = $f.FullName; Reviewer = $reviewer
                                  Action = $action; Reason = $reason })
        }
    }
    ,@($results.ToArray())
}

function Get-AdcertReviewerEmail {
    <# Reads the reviewer's mail attribute from AD. Returns $null if absent. #>
    param([Parameter(Mandatory)][string]$Sam)
    try {
        $u = Get-ADUser -Identity $Sam -Properties mail, DisplayName -ErrorAction Stop
        if ($u.mail) { return @{ Address = [string]$u.mail; Name = [string]$u.DisplayName } }
    } catch { }
    $null
}

function Send-AdcertReviews {
    <# Emails each reviewer their own review page as an attachment.

       SMTP settings come from an 'smtp' block in the campaign config:
         "smtp": { "server": "...", "port": 25, "from": "...", "use_ssl": false,
                   "subject": "Access review due: {campaign}" }

       -DryRun prints exactly what would be sent without contacting the server,
       which is what you want the first time and in any demo.

       Returns a list of @{ Reviewer; Address; Status; Detail }. #>
    param(
        [Parameter(Mandatory)][string]$CampaignDir,
        [Parameter(Mandatory)]$Smtp,
        [switch]$DryRun,
        [System.Management.Automation.PSCredential]$Credential
    )
    $ctx = Get-AdcertCampaignContext -CampaignDir $CampaignDir
    $campaign = [string]$ctx.Manifest['campaign']

    $subjectTpl = 'Access review: {campaign}'
    if ($Smtp.Contains('subject') -and $Smtp['subject']) { $subjectTpl = [string]$Smtp['subject'] }

    $results = New-Object System.Collections.ArrayList
    foreach ($reviewer in @($ctx.Manifest['reviewers'])) {
        if ($reviewer -eq '_unrouted') {
            [void]$results.Add(@{ Reviewer = $reviewer; Address = ''; Status = 'skipped'
                                  Detail = 'unrouted package - assign an owner manually' })
            continue
        }
        $folder = Get-AdcertReviewerFolder -CampaignDir $CampaignDir -Reviewer $reviewer
        $page = @(Get-ChildItem -Path $folder -Filter 'review_*.html' -ErrorAction SilentlyContinue)
        if (-not $page.Count) {
            [void]$results.Add(@{ Reviewer = $reviewer; Address = ''; Status = 'error'
                                  Detail = 'no review page found' })
            continue
        }

        $who = Get-AdcertReviewerEmail -Sam $reviewer
        if (-not $who) {
            [void]$results.Add(@{ Reviewer = $reviewer; Address = ''; Status = 'error'
                                  Detail = 'no mail attribute in Active Directory' })
            continue
        }

        $entries = 0
        $pkgJson = @(Get-ChildItem -Path $folder -Filter 'review_*.json' -ErrorAction SilentlyContinue)
        if ($pkgJson.Count) {
            $pkg = ConvertTo-Hashtable (Get-Content -Raw -Path $pkgJson[0].FullName | ConvertFrom-Json)
            $entries = @($pkg['entries']).Count
        }

        $subject = $subjectTpl.Replace('{campaign}', $campaign).Replace('{reviewer}', $reviewer)
        $body = @"
Hello $($who.Name),

You have $entries access grant(s) to review for $campaign.

1. Open the attached review page in your browser. Nothing is installed and
   nothing leaves your machine.
2. Decide each row: Retain, Revoke, or Modify. Revoke and Modify need a
   short written reason.
3. Click 'Export decisions' and send the saved file back to me.

The page shows, for each person, what the access actually lets them do and
when they last signed in, so you have what you need to decide without
looking anything up.

Thank you,
Access review administrator
"@

        if ($DryRun) {
            [void]$results.Add(@{ Reviewer = $reviewer; Address = $who.Address
                                  Status = 'would send'
                                  Detail = "$($page[0].Name) ($entries entries), subject: $subject" })
            continue
        }

        try {
            $params = @{
                To = $who.Address; From = [string]$Smtp['from']
                Subject = $subject; Body = $body
                SmtpServer = [string]$Smtp['server']
                Attachments = $page[0].FullName
            }
            if ($Smtp.Contains('port') -and $Smtp['port']) { $params['Port'] = [int]$Smtp['port'] }
            if ($Smtp.Contains('use_ssl') -and $Smtp['use_ssl']) { $params['UseSsl'] = $true }
            if ($Credential) { $params['Credential'] = $Credential }
            Send-MailMessage @params -ErrorAction Stop
            [void]$results.Add(@{ Reviewer = $reviewer; Address = $who.Address
                                  Status = 'sent'; Detail = $page[0].Name })
        } catch {
            [void]$results.Add(@{ Reviewer = $reviewer; Address = $who.Address
                                  Status = 'error'; Detail = $_.Exception.Message })
        }
    }
    ,@($results.ToArray())
}
