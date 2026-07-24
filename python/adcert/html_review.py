"""Generates a self-contained HTML review page per reviewer.

Design constraints (deliberate):
  * single file, zero server, zero install -- opens in any browser, works in
    an air-gapped enclave, nothing to accredit
  * three-decision model (Retain / Revoke / Modify) with justification
    required for anything other than Retain
  * risky rows first; flags rendered as plain-language chips
  * "Export decisions" produces the JSON decision file the evidence engine
    consumes; export is blocked until every row is decided
"""
from __future__ import annotations

import json

from .review import ReviewPackage

_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Review — {reviewer} — {campaign}</title>
<style>
  :root {{
    --ink:#1b2733; --paper:#f6f7f8; --card:#ffffff; --line:#d7dde3;
    --muted:#5b6b7a; --accent:#7a0019; --accent-ink:#ffffff;
    --ok:#1e7145; --warn:#a15c00; --bad:#a11a1a; --chip:#eef1f4;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--paper); color:var(--ink);
         font:15px/1.5 "Segoe UI", system-ui, sans-serif; }}
  header {{ background:var(--ink); color:#fff; padding:20px 28px; }}
  header h1 {{ margin:0 0 2px; font-size:19px; font-weight:600; letter-spacing:.2px; }}
  header .sub {{ color:#aebbc7; font-size:13px; }}
  header .sub code {{ color:#cdd6de; }}
  .wrap {{ max-width:980px; margin:0 auto; padding:22px 20px 80px; }}
  .intro {{ background:var(--card); border:1px solid var(--line); border-left:4px solid var(--accent);
            border-radius:6px; padding:14px 18px; margin-bottom:18px; font-size:14px; }}
  .intro b {{ color:var(--accent); }}
  .prog {{ position:sticky; top:0; z-index:5; background:var(--paper);
           padding:10px 0 12px; border-bottom:1px solid var(--line); margin-bottom:14px;
           display:flex; align-items:center; gap:14px; }}
  .bar {{ flex:1; height:8px; background:var(--chip); border-radius:4px; overflow:hidden; }}
  .bar i {{ display:block; height:100%; width:0; background:var(--accent); transition:width .2s; }}
  .prog span {{ font-size:13px; color:var(--muted); white-space:nowrap; }}
  .card {{ background:var(--card); border:1px solid var(--line); border-radius:6px;
           padding:14px 18px; margin-bottom:12px; }}
  .card.done {{ opacity:.62; }}
  .row1 {{ display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }}
  .who b {{ font-size:16px; }}
  .who .meta {{ color:var(--muted); font-size:13px; }}
  .grp {{ font-size:13px; margin-top:6px; }}
  .grp code {{ background:var(--chip); padding:1px 6px; border-radius:3px; font-size:12px; }}
  .grp .plain {{ color:var(--muted); }}
  .chips {{ margin-top:8px; display:flex; gap:6px; flex-wrap:wrap; }}
  .chip {{ font-size:12px; padding:2px 9px; border-radius:10px; background:var(--chip); color:var(--muted); }}
  .chip.bad {{ background:#fbe9e9; color:var(--bad); font-weight:600; }}
  .chip.warn {{ background:#fdf3e3; color:var(--warn); font-weight:600; }}
  .chip.new {{ background:#e8f0fb; color:#1c4f9c; font-weight:600; }}
  .logon {{ text-align:right; font-size:13px; color:var(--muted); min-width:130px; }}
  .logon .big {{ font-size:15px; font-weight:600; color:var(--ink); }}
  .logon .big.bad {{ color:var(--bad); }}
  .acts {{ margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; align-items:center; }}
  .acts button {{ font:inherit; font-size:13px; padding:7px 16px; border-radius:4px;
                  border:1px solid var(--line); background:#fff; cursor:pointer; }}
  .acts button:hover {{ border-color:var(--muted); }}
  .acts button.sel-retain {{ background:var(--ok); border-color:var(--ok); color:#fff; }}
  .acts button.sel-revoke {{ background:var(--bad); border-color:var(--bad); color:#fff; }}
  .acts button.sel-modify {{ background:var(--warn); border-color:var(--warn); color:#fff; }}
  .just {{ margin-top:10px; }}
  .just textarea {{ width:100%; min-height:52px; font:inherit; font-size:13px;
                    border:1px solid var(--line); border-radius:4px; padding:8px; }}
  .just label {{ font-size:12px; color:var(--muted); display:block; margin-bottom:3px; }}
  .just.required label {{ color:var(--bad); font-weight:600; }}
  footer {{ position:fixed; bottom:0; left:0; right:0; background:var(--ink);
            padding:12px 28px; display:flex; align-items:center; gap:16px; }}
  footer .status {{ color:#aebbc7; font-size:13px; flex:1; }}
  footer button {{ font:inherit; font-size:14px; font-weight:600; padding:10px 22px;
                   border:0; border-radius:4px; background:var(--accent); color:var(--accent-ink);
                   cursor:pointer; }}
  footer button:disabled {{ background:#5b6b7a; cursor:not-allowed; }}
  .note {{ color:var(--muted); font-size:12px; margin-top:14px; }}
</style>
</head>
<body>
<header>
  <h1>Periodic Access Review</h1>
  <div class="sub">Reviewer: <code>{reviewer}</code> &nbsp;·&nbsp; Campaign: {campaign}
    &nbsp;·&nbsp; Review ID: <code>{review_id}</code></div>
</header>
<div class="wrap">
  <div class="intro">
    You are certifying <b>{n} access grants</b> for people you supervise.
    For each row decide whether the access is still required. <b>Revoke</b> and
    <b>Modify</b> require a short justification; a comment on Retain is optional
    but encouraged for privileged or dormant accounts. Your decisions become part
    of the enclave's access-control evidence (NIST SP 800-171 3.1.1 / 3.1.2).
  </div>
  <div class="prog"><div class="bar"><i id="fill"></i></div><span id="count"></span></div>
  <div id="list"></div>
  <p class="note">{stale_note}</p>
</div>
<footer>
  <div class="status" id="footStatus"></div>
  <button id="export" disabled>Export decisions</button>
</footer>
<script>
const PKG = {payload};
const state = {{}};   // key -> {{decision, justification}}
const keyOf = e => e.group + "||" + e.sam;

function fmtLogon(e) {{
  if (e.days_since_logon === null) return ["Never logged on", true];
  if (e.days_since_logon === 0) return ["Today", false];
  return [e.days_since_logon + " days ago", e.days_since_logon >= 90];
}}

function render() {{
  const list = document.getElementById("list");
  list.innerHTML = "";
  PKG.entries.forEach(e => {{
    const k = keyOf(e);
    const st = state[k] || {{}};
    const [logonTxt, logonBad] = fmtLogon(e);
    const card = document.createElement("div");
    card.className = "card" + (st.decision ? " done" : "");
    const chips = [];
    if (e.new_since_last_review) chips.push('<span class="chip new">New since last review</span>');
    e.flags.forEach(f => {{
      const cls = /DISABLED|expiration|Never/i.test(f) ? "bad"
                : /Dormant|expires|Privileged/i.test(f) ? "warn" : "";
      chips.push('<span class="chip ' + cls + '">' + f + '</span>');
    }});
    const needJust = st.decision === "revoke" || st.decision === "modify";
    card.innerHTML = `
      <div class="row1">
        <div class="who">
          <b>${{e.display_name}}</b> <span class="meta">(${{e.sam}})</span>
          <div class="meta">${{e.title || "—"}} · ${{e.department || "—"}}${{e.enabled ? "" : " · ACCOUNT DISABLED"}}</div>
          <div class="grp">Access: <code>${{e.group}}</code>
            <span class="plain">— ${{e.group_plain}}</span></div>
          <div class="chips">${{chips.join("")}}</div>
        </div>
        <div class="logon"><div class="big ${{logonBad ? "bad" : ""}}">${{logonTxt}}</div>last logon</div>
      </div>
      <div class="acts">
        <button data-d="retain" class="${{st.decision === "retain" ? "sel-retain" : ""}}">Retain</button>
        <button data-d="revoke" class="${{st.decision === "revoke" ? "sel-revoke" : ""}}">Revoke</button>
        <button data-d="modify" class="${{st.decision === "modify" ? "sel-modify" : ""}}">Modify</button>
      </div>
      <div class="just ${{needJust ? "required" : ""}}">
        <label>${{needJust ? "Justification (required)" : "Comment (optional)"}}</label>
        <textarea>${{st.justification || ""}}</textarea>
      </div>`;
    card.querySelectorAll(".acts button").forEach(b => b.onclick = () => {{
      state[k] = state[k] || {{}};
      state[k].decision = b.dataset.d;
      render(); update();
    }});
    card.querySelector("textarea").oninput = ev => {{
      state[k] = state[k] || {{}};
      state[k].justification = ev.target.value;
      update();
    }};
    list.appendChild(card);
  }});
  update();
}}

function ready() {{
  return PKG.entries.every(e => {{
    const st = state[keyOf(e)];
    if (!st || !st.decision) return false;
    if ((st.decision === "revoke" || st.decision === "modify")
        && !(st.justification || "").trim()) return false;
    return true;
  }});
}}

function update() {{
  const done = PKG.entries.filter(e => (state[keyOf(e)] || {{}}).decision).length;
  document.getElementById("fill").style.width = (100 * done / PKG.entries.length) + "%";
  document.getElementById("count").textContent = done + " / " + PKG.entries.length + " decided";
  const ok = ready();
  document.getElementById("export").disabled = !ok;
  document.getElementById("footStatus").textContent = ok
    ? "All entries decided. Export and return the file to your security administrator."
    : "Export unlocks when every entry has a decision (and justifications where required).";
}}

document.getElementById("export").onclick = () => {{
  const out = {{
    reviewer: PKG.reviewer,
    review_id: PKG.review_id,
    campaign: PKG.campaign,
    snapshot_sha256: PKG.snapshot_sha256,
    decided_at: new Date().toISOString(),
    decisions: PKG.entries.map(e => {{
      const st = state[keyOf(e)];
      return {{ group: e.group, sam: e.sam,
                decision: st.decision, justification: (st.justification || "").trim() }};
    }})
  }};
  const blob = new Blob([JSON.stringify(out, null, 2)], {{type: "application/json"}});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "decisions_" + PKG.reviewer + "_" + PKG.review_id + ".json";
  a.click();
}};

render();
</script>
</body>
</html>
"""


def render_review_html(pkg: ReviewPackage, stale_note: str = "") -> str:
    payload = json.dumps(pkg.to_dict())
    return _PAGE.format(
        reviewer=pkg.reviewer,
        campaign=pkg.campaign,
        review_id=pkg.review_id,
        n=len(pkg.entries),
        payload=payload,
        stale_note=stale_note,
    )
