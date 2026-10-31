from __future__ import annotations

import ast
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import PurePosixPath

import streamlit as st

# ----------------------------- Page setup ----------------------------------
st.set_page_config(page_title="BugOut | Code Security Review", page_icon="🛡️", layout="wide", initial_sidebar_state="expanded")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root { --ink:#edf3ff; --muted:#91a0b8; --panel:#111a2a; --line:#26344b; --cyan:#62e6d2; --violet:#9d91ff; }
html, body, [class*="css"] { font-family:'Manrope',sans-serif; }
.stApp { background: radial-gradient(ellipse at 12% 0%, #1b2a45 0%, #0a1020 44%, #080d18 100%); color:var(--ink); }
[data-testid="stHeader"] { background:transparent; }
.block-container { padding-top:2rem; padding-bottom:3rem; max-width:1400px; }
section[data-testid="stSidebar"] { background:#0c1423; border-right:1px solid var(--line); }
section[data-testid="stSidebar"] * { color:var(--ink); }
h1,h2,h3 { color:var(--ink)!important; letter-spacing:-.035em; }
p, label, .stMarkdown { color:#c4cee0; }
.hero { padding:2rem 2.2rem; border:1px solid #30415c; border-radius:22px; background:linear-gradient(120deg,rgba(27,43,68,.96),rgba(17,27,45,.86)); box-shadow:0 20px 70px rgba(0,0,0,.22); margin-bottom:1.35rem; }
.eyebrow { color:var(--cyan); text-transform:uppercase; letter-spacing:.18em; font-size:.72rem; font-weight:800; }
.hero h1 { font-size:2.65rem; margin:.35rem 0 .45rem; }
.hero p { max-width:780px; color:#aebbd0; margin:0; font-size:1rem; line-height:1.7; }
.panel { border:1px solid var(--line); background:rgba(17,26,42,.88); border-radius:17px; padding:1.1rem 1.25rem; }
.metric { border:1px solid var(--line); border-radius:15px; background:linear-gradient(145deg,#142139,#101827); padding:1rem 1.1rem; min-height:112px; }
.metric .label { color:var(--muted); font-size:.78rem; font-weight:700; text-transform:uppercase; letter-spacing:.08em; }
.metric .value { color:var(--ink); font-size:2rem; font-weight:800; margin-top:.25rem; }
.metric .hint { color:#8091ac; font-size:.76rem; margin-top:.1rem; }
.pill { display:inline-block; padding:.28rem .62rem; border:1px solid #38506b; border-radius:999px; color:#a9f3e8; background:#15313a; font-size:.72rem; font-weight:800; }
.muted { color:var(--muted); }
.smallcaps { color:#7f91ad; font-size:.72rem; font-weight:800; text-transform:uppercase; letter-spacing:.12em; }
div.stButton > button, div.stDownloadButton > button { border-radius:10px; border:1px solid #45617d; background:linear-gradient(120deg,#5de0cd,#a7f1df); color:#07151d; font-weight:800; min-height:2.7rem; }
div.stButton > button:hover, div.stDownloadButton > button:hover { border-color:#a7f1df; color:#07151d; filter:brightness(1.05); }
.stTabs [data-baseweb="tab-list"] { gap:1rem; border-bottom:1px solid var(--line); }
.stTabs [data-baseweb="tab"] { color:#aab8ce; font-weight:700; }
.stTabs [aria-selected="true"] { color:var(--cyan)!important; }
[data-testid="stExpander"] { border:1px solid var(--line); border-radius:13px; background:rgba(17,26,42,.7); }
[data-testid="stFileUploader"] { border:1px dashed #526987; border-radius:15px; background:rgba(20,33,54,.55); padding:.5rem; }
code, pre { font-family:'DM Mono',monospace!important; }
hr { border-color:var(--line); }
footer { visibility:hidden; }
</style>
""", unsafe_allow_html=True)

MAX_BYTES = 500_000
MAX_FILES = 100
SUPPORTED_SUFFIXES = {".py"}
PATCH_PATTERN = re.compile(r"^(?P<indent>\s*)cursor\.execute\(\s*f[\"']SELECT \* FROM users WHERE username = ['\"]\{username\}['\"][\"']\s*\)\s*$")

# ----------------------------- Analysis ------------------------------------
def _call_name(node: ast.Call) -> str:
    fn = node.func
    return fn.attr if isinstance(fn, ast.Attribute) else fn.id if isinstance(fn, ast.Name) else ""


def _is_dynamic_sql(node: ast.AST, assignments: dict[str, ast.AST], depth: int = 0) -> tuple[bool, str]:
    if depth > 5:
        return False, ""
    if isinstance(node, ast.Name) and node.id in assignments:
        return _is_dynamic_sql(assignments[node.id], assignments, depth + 1)
    if isinstance(node, ast.JoinedStr):
        return True, "SQL passed as an f-string; interpolated values can become SQL syntax."
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True, "SQL appears to be assembled with string concatenation or formatting."
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True, "SQL appears to use string .format(); interpolated values can become SQL syntax."
    return False, ""


def scan_python(source: str) -> list[dict]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return [{"rule": "PYTHON_SYNTAX_ERROR", "line": exc.lineno or 1, "severity": "Review", "message": exc.msg}]

    findings: list[dict] = []
    assignments: dict[str, ast.AST] = {}
    # Collect simple module/function assignments to detect `query = f"..."; execute(query)`.
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and value is not None:
                    assignments[target.id] = value

    seen = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or _call_name(node) not in {"execute", "executemany"} or not node.args:
            continue
        risky, explanation = _is_dynamic_sql(node.args[0], assignments)
        if risky:
            key = (node.lineno, explanation)
            if key not in seen:
                seen.add(key)
                findings.append({"rule": "POSSIBLE_SQL_INJECTION", "line": node.lineno, "severity": "High", "message": explanation})
    return sorted(findings, key=lambda x: x["line"])


def propose_patch(source: str) -> tuple[str, int | None, bool]:
    out, changed, line_no = [], False, None
    for i, line in enumerate(source.splitlines(keepends=True), 1):
        content = line.rstrip("\r\n")
        ending = line[len(content):]
        match = PATCH_PATTERN.match(content)
        if match:
            out.append(match.group("indent") + 'cursor.execute("SELECT * FROM users WHERE username = ?", (username,))' + ending)
            changed, line_no = True, i
        else:
            out.append(line)
    return "".join(out), line_no, changed


def verify_patch(source: str) -> tuple[bool, str]:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        return False, f"Syntax check failed: {exc.msg}"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _call_name(node) in {"execute", "executemany"} and node.args and isinstance(node.args[0], ast.JoinedStr):
            return False, "A direct f-string remains in execute()."
    return True, "Syntax is valid and no direct f-string remains in execute(). This is a limited static check, not proof of security."


def confidence_assessment(source: str, patched: str, findings: list[dict], changed: bool, verified: bool):
    supported = changed and any(f["rule"] == "POSSIBLE_SQL_INJECTION" for f in findings)
    try:
        ast.parse(patched if changed else source)
        syntax_ok = True
    except SyntaxError:
        syntax_ok = False
    focused = changed and source.count("\n") == patched.count("\n") and sum(a != b for a, b in zip(source.splitlines(), patched.splitlines())) == 1
    parts = [
        ("Recognized supported pattern", 30 if supported else 0, 30, "Exact supported SQL demo pattern matched." if supported else "No supported exact patch pattern matched."),
        ("Python syntax check", 20 if syntax_ok else 0, 20, "Python AST parsing passed." if syntax_ok else "Python syntax check failed."),
        ("Risky query replacement verified", 20 if changed and verified else 0, 20, "Recognized query replaced with a parameterized query." if changed and verified else "Safe replacement could not be confirmed."),
        ("Patch scope", 10 if focused else 0, 10, "Exactly one source line changed." if focused else "A one-line focused change was not confirmed."),
        ("Runtime, regression and exploit tests", 0, 20, "Not run: uploaded code is never executed by this prototype."),
    ]
    score = sum(p for _, p, _, _ in parts)
    return score, parts, "Human review required"


def read_files(upload) -> dict[str, str]:
    result = {}
    raw = upload.getvalue()
    if len(raw) > 20 * 1024 * 1024:
        raise ValueError("Upload exceeds the 20 MB total limit.")
    if upload.name.lower().endswith(".py"):
        if len(raw) > MAX_BYTES:
            raise ValueError("Python file is larger than 500 KB.")
        result[PurePosixPath(upload.name).name] = raw.decode("utf-8", errors="replace")
    else:
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                members = [m for m in archive.infolist() if not m.is_dir() and PurePosixPath(m.filename).suffix.lower() in SUPPORTED_SUFFIXES]
                if len(members) > MAX_FILES:
                    raise ValueError("ZIP contains more than 100 Python files.")
                for item in members:
                    path = PurePosixPath(item.filename)
                    if path.is_absolute() or ".." in path.parts or item.file_size > MAX_BYTES:
                        continue
                    if item.flag_bits & 0x1:
                        continue
                    result[str(path)] = archive.read(item).decode("utf-8", errors="replace")
        except zipfile.BadZipFile as exc:
            raise ValueError("That ZIP file is invalid or corrupted.") from exc
    if not result:
        raise ValueError("No eligible Python files found. Upload a .py file or a ZIP containing Python files.")
    return result


def analyze_project(project_name: str, sources: dict[str, str]) -> tuple[dict, dict]:
    report = {
        "product": "BugOut", "project": project_name,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "score_definition": "Evidence score out of 100; not a probability or proof of security. Runtime, regression and exploit tests are not run.",
        "files": [], "summary": {"files_scanned": len(sources), "findings": 0, "patches_prepared": 0, "needs_review": 0},
    }
    outputs = dict(sources)
    for filename, source in sources.items():
        findings = scan_python(source)
        patched, line_no, changed = propose_patch(source)
        passed, verification = verify_patch(patched) if changed else (False, "No supported patch proposed.")
        score, parts, decision = confidence_assessment(source, patched, findings, changed, passed)
        if changed and passed:
            outputs[filename] = patched
            status = "Patch prepared · review required"
            report["summary"]["patches_prepared"] += 1
        elif findings:
            status = "Needs human review"
        else:
            status = "No supported finding detected"
        if findings and decision == "Human review required":
            report["summary"]["needs_review"] += 1
        report["summary"]["findings"] += len(findings)
        report["files"].append({
            "file": filename, "status": status, "findings": findings,
            "patch_line": line_no, "verification": verification,
            "confidence_score": score, "confidence_decision": decision,
            "confidence_breakdown": [{"factor": n, "points_awarded": p, "max_points": m, "evidence": e} for n, p, m, e in parts],
            "patch_prepared": bool(changed and passed),
        })
    return report, outputs

# ----------------------------- Sidebar -------------------------------------
with st.sidebar:
    st.markdown("<div style='font-size:1.45rem;font-weight:800;letter-spacing:-.04em'>🛡️ BugOut</div><div class='muted' style='font-size:.78rem;margin-top:.15rem'>SECURITY REVIEW WORKSPACE</div>", unsafe_allow_html=True)
    st.divider()
    st.markdown("**Workspace**")
    st.markdown("<span class='pill'>● Local analysis</span>", unsafe_allow_html=True)
    st.markdown("<br><div class='smallcaps'>Analysis pipeline</div><div style='line-height:2.1;color:#aebbd0;font-size:.88rem'>01 &nbsp; Upload codebase<br>02 &nbsp; Static analysis<br>03 &nbsp; Review evidence<br>04 &nbsp; Export results</div>", unsafe_allow_html=True)
    st.divider()
    st.markdown("<div class='smallcaps'>Safety boundaries</div><p style='font-size:.8rem;color:#91a0b8;line-height:1.6'>Code is parsed as text and never executed. Patches are proposals only. Human review is always required.</p>", unsafe_allow_html=True)
    st.caption("BugOut · Hackathon build")

# ----------------------------- Main view -----------------------------------
st.markdown("""
<div class="hero">
  <div class="eyebrow">Intelligent code security review</div>
  <h1>Find the flaw.<br>Understand the fix.</h1>
  <p>Scan Python codebases for risky SQL construction, inspect evidence behind every confidence score, and prepare focused patch proposals — with human review in control.</p>
</div>
""", unsafe_allow_html=True)

left, right = st.columns([1.45, 1], gap="large")
with left:
    st.markdown("### Start a security scan")
    st.markdown("<p class='muted'>Upload a Python file or a ZIP archive. Your source is analyzed statically and is never run.</p>", unsafe_allow_html=True)
    upload = st.file_uploader("Drop your codebase here", type=["py", "zip"], label_visibility="collapsed", help="Up to 20 MB per upload, 100 Python files, 500 KB per file.")
    st.caption("SUPPORTED INPUTS  ·  .PY  ·  .ZIP   |   MAX 20 MB")
with right:
    st.markdown("### What BugOut checks")
    st.markdown("""
    <div class="panel" style="margin-bottom:.65rem"><div style="color:#62e6d2;font-weight:800">01 / SQL injection signals</div><div class="muted" style="font-size:.86rem;margin-top:.25rem">F-strings, concatenation, percent formatting, and .format() in database execute calls.</div></div>
    <div class="panel" style="margin-bottom:.65rem"><div style="color:#9d91ff;font-weight:800">02 / Patch evidence</div><div class="muted" style="font-size:.86rem;margin-top:.25rem">A transparent score with explicit checks and missing evidence.</div></div>
    <div class="panel"><div style="color:#f3c875;font-weight:800">03 / Human review</div><div class="muted" style="font-size:.86rem;margin-top:.25rem">No automatic changes. Download proposals and review before applying.</div></div>
    """, unsafe_allow_html=True)

if "bugout_result" not in st.session_state:
    st.session_state.bugout_result = None

if upload is not None:
    try:
        sources = read_files(upload)
        if st.button("Run security scan", type="primary", use_container_width=True):
            report, outputs = analyze_project(upload.name, sources)
            st.session_state.bugout_result = {"report": report, "outputs": outputs, "sources": sources}
    except Exception as exc:
        st.error(f"Upload could not be processed: {exc}")

result = st.session_state.bugout_result
if result:
    report, outputs, sources = result["report"], result["outputs"], result["sources"]
    st.divider()
    st.markdown("### Scan overview")
    st.caption(f"{report['project']}  ·  {report['generated_at']}  ·  {report['summary']['files_scanned']} file(s) analyzed")
    m1, m2, m3, m4 = st.columns(4)
    for col, label, value, hint in [
        (m1, "Files scanned", report["summary"]["files_scanned"], "Python source files"),
        (m2, "Potential findings", report["summary"]["findings"], "Static risk signals"),
        (m3, "Patches prepared", report["summary"]["patches_prepared"], "Not auto-applied"),
        (m4, "Need review", report["summary"]["needs_review"], "Human decision required"),
    ]:
        col.markdown(f"<div class='metric'><div class='label'>{label}</div><div class='value'>{value}</div><div class='hint'>{hint}</div></div>", unsafe_allow_html=True)

    tab_findings, tab_patches, tab_report = st.tabs(["Findings & confidence", "Patch proposals", "Export & methodology"])
    with tab_findings:
        if not any(f["findings"] for f in report["files"]):
            st.success("No supported SQL injection signals were detected in the uploaded Python files.")
            st.caption("This does not mean the codebase is vulnerability-free; BugOut currently checks a limited set of static patterns.")
        for item in report["files"]:
            with st.expander(f"{'⚠️' if item['findings'] else '✓'}  {item['file']}  ·  {item['status']}", expanded=bool(item["findings"])):
                if item["findings"]:
                    for finding in item["findings"]:
                        st.error(f"{finding['severity']}  ·  Line {finding['line']}  ·  {finding['message']}")
                else:
                    st.info("No supported finding detected in this file.")
                a, b = st.columns([1, 2])
                a.metric("Evidence score", f"{item['confidence_score']} / 100")
                b.warning(item["confidence_decision"])
                st.progress(item["confidence_score"] / 100)
                st.markdown("**Evidence breakdown**")
                for factor in item["confidence_breakdown"]:
                    st.markdown(f"- **{factor['factor']}** — {factor['points_awarded']}/{factor['max_points']} points  \n  <span class='muted'>{factor['evidence']}</span>", unsafe_allow_html=True)
                st.caption(item["verification"])
    with tab_patches:
        patches = [x for x in report["files"] if x["patch_prepared"]]
        if not patches:
            st.info("No automatic patch proposal is available for this upload. Findings outside the exact supported demo pattern are routed to human review.")
        for item in patches:
            st.markdown(f"**{item['file']}** · proposed change at line {item['patch_line']}")
            st.code(outputs[item["file"]], language="python", line_numbers=True)
            st.caption("Review this proposal in context before applying it. It has not changed your original upload.")
    with tab_report:
        st.markdown("**How the confidence score works**")
        st.markdown("The score is an evidence checklist, not a statistical probability. Up to 80 points come from static checks; 20 points for runtime, regression, and exploit testing remain unavailable because uploaded code is never executed.")
        st.markdown("**Current scope**")
        st.markdown("- Python files only; SQL injection signals in `execute()` and `executemany()` calls.\n- A narrowly scoped parameterized-query patch for one exact supported example.\n- No dependency, secrets, authentication, authorization, or non-Python scanning.\n- No runtime sandbox, exploit testing, regression suite, or automatic patch application.")
        json_bytes = json.dumps(report, indent=2).encode("utf-8")
        st.download_button("Download scan report · JSON", json_bytes, file_name="bugout_report.json", mime="application/json", use_container_width=True)
        if outputs != sources:
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
                for name, content in outputs.items():
                    archive.writestr(name, content)
                archive.writestr("bugout_report.json", json.dumps(report, indent=2))
            st.download_button("Download proposed patch + report · ZIP", buf.getvalue(), file_name="bugout_patch_and_report.zip", mime="application/zip", use_container_width=True)

st.divider()
st.markdown("<div style='display:flex;justify-content:space-between;gap:1rem;flex-wrap:wrap;color:#74849e;font-size:.76rem'><span>BUGOUT · STATIC ANALYSIS WORKSPACE</span><span>Never execute untrusted uploads · Always review patches before use</span></div>", unsafe_allow_html=True)
