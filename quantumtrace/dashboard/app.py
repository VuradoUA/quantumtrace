"""QuantumTrace dashboard (Phase 4).

    quantumtrace dashboard [PATH]          # opens http://localhost:8501
    streamlit run quantumtrace/dashboard/app.py

The page only DISPLAYS what the engine produced (quantumtrace.report.analyse): every number here is
the same number the CLI, report.json and cbom.json contain.
Environment (set by `quantumtrace dashboard`): QT_TARGET = default path to scan, QT_REPORT = a report
folder to open, QT_NOW = YYYY-MM-DD to pretend today is (reproducible demos).
"""
from __future__ import annotations

import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

from quantumtrace.dashboard import data as D

st.set_page_config(page_title="QuantumTrace", page_icon="🛡️", layout="wide")

DOWNLOAD_LABELS = {"cbom.json": "Download CBOM (CycloneDX 1.6, standard inventory)",
                   "report.json": "Download risk report (score + roadmap)",
                   "findings.json": "Download raw findings (every occurrence)"}
NOW = datetime.fromisoformat(os.environ["QT_NOW"]).replace(tzinfo=timezone.utc) if os.environ.get("QT_NOW") else None


@st.cache_data(show_spinner=False)
def _scan(path: str, now_iso: str | None, stamp: float) -> D.Bundle:      # stamp: re-scan when files change
    now = datetime.fromisoformat(now_iso) if now_iso else None
    return D.scan_to_bundle(path, now=now)


def _mtime(path: str) -> float:
    p = Path(path).expanduser()
    if p.is_file():
        return p.stat().st_mtime
    return max((f.stat().st_mtime for f in p.rglob("*") if f.is_file()), default=0.0) if p.is_dir() else 0.0


def _dark() -> bool:
    try:
        return st.context.theme.type == "dark"
    except Exception:
        return False


# ====================================================================== sidebar: where the data comes from
with st.sidebar:
    st.header("QuantumTrace")
    st.caption("Post-quantum cryptography discovery")
    modes = ["Scan a folder or file", "Upload files", "Open a report folder"]
    default_mode = 2 if os.environ.get("QT_REPORT") else 0
    mode = st.radio("Data source", modes, index=default_mode, key="mode")
    bundle: D.Bundle | None = st.session_state.get("bundle")
    error = None
    if bundle is None and os.environ.get("QT_REPORT") and not st.session_state.get("auto_opened"):
        st.session_state["auto_opened"] = True          # started with --report (e.g. by demo.sh): open it once
        try:
            st.session_state["bundle"] = bundle = D.load_folder(os.environ["QT_REPORT"])
        except D.DashboardError as e:
            error = str(e)
    try:
        if mode == modes[0]:
            path = st.text_input("Path on this computer", value=os.environ.get("QT_TARGET", "."), key="path")
            st.caption("PCAP, source code, JSON cloud exports, configs, certificates, dependency files.")
            if st.button("Scan", type="primary", key="scan"):
                with st.spinner(f"Scanning {path} ..."):
                    st.session_state["bundle"] = bundle = _scan(path, NOW.isoformat() if NOW else None, _mtime(path))
        elif mode == modes[1]:
            ups = st.file_uploader("Files or .zip archives", accept_multiple_files=True, key="upload")
            if ups and st.button("Scan uploaded files", type="primary", key="scan_upload"):
                with tempfile.TemporaryDirectory(prefix="qt-upload-") as tmp:
                    D.save_uploads([(u.name, u.getvalue()) for u in ups], Path(tmp))
                    with st.spinner("Scanning upload ..."):
                        st.session_state["bundle"] = bundle = D.scan_to_bundle(tmp, now=NOW,
                                                                               label=f"upload ({len(ups)} file(s))")
        else:
            folder = st.text_input("Folder written by `quantumtrace scan --out`",
                                   value=os.environ.get("QT_REPORT", "report"), key="folder")
            if st.button("Open", type="primary", key="open"):
                st.session_state["bundle"] = bundle = D.load_folder(folder)
    except D.DashboardError as e:
        error = str(e)
    if bundle is not None:
        st.divider()
        st.caption(f"Showing: {bundle.origin}")
        files = D.downloads(bundle)
        for name, label in DOWNLOAD_LABELS.items():
            if name in files:
                st.download_button(label, files[name], file_name=name, mime="application/json", key=f"dl-{name}")

st.title("Quantum readiness")
if error:
    st.error(error)
if bundle is None:
    st.info("Choose a data source in the sidebar and press **Scan** / **Open**.\n\n"
            "Example: scan the organisers' starter kit `../JunctionX-QuantumTrace`.")
    st.stop()

h = D.headline(bundle)

# ====================================================================== headline numbers
for w in h["warnings"]:
    st.warning(w)
c = st.columns([1.4, 1, 1, 1, 1])
score = h["score"]
c[0].metric("Quantum Risk Score", f"{score:.0f} / 100" if score is not None else "n/a",
            help="0 = nothing left to migrate, 100 = everything exposed. Mean of the per-source scores.")
c[1].metric("HNDL-exposed assets", f"{h['hndl_assets']}",
            help="CRITICAL assets whose encrypted data can be recorded today and decrypted later")
c[2].metric("Broken already", f"{h['broken_assets']}",
            help="Assets that use crypto broken without a quantum computer (MD5, SHA-1 signatures, RSA-1024, ...)")
c[3].metric("Quantum-safe assets", f"{h['quantum_safe_assets']} / {h['assets_scored']}")
if h["pqc_readiness"] is not None:
    c[4].metric("PQC readiness", f"{h['pqc_readiness']:.0%}",
                help=f"{h['pqc_sessions']} of {h['tls_sessions']} TLS sessions use a post-quantum key exchange")
else:
    c[4].metric("Findings", f"{h['findings']}")

if h["by_source"]:
    cols = st.columns(len(h["by_source"]))
    for col, (src, val) in zip(cols, h["by_source"].items()):
        col.caption(f"{src} risk")
        col.progress(min(max(val / 100, 0.0), 1.0), text=f"{val:.0f} / 100")

if h["cbom_valid"] is True:
    st.success("CBOM: valid CycloneDX 1.6 (official schema + reference check)", icon="✅")
elif h["cbom_valid"] is False:
    st.error("CBOM failed validation: " + "; ".join(h["cbom_messages"][:3]), icon="❌")
elif bundle.cbom is not None:
    st.warning("CBOM not validated (cyclonedx-python-lib not installed)", icon="⚠️")

# ====================================================================== assets by tier, per source
st.subheader("Assets by verdict")
rows = D.tier_rows(bundle)
if rows:
    df = pd.DataFrame(rows)
    surface = "#0e1117" if _dark() else "#ffffff"           # Streamlit's page colour: 2px gap between segments
    tiers_present = [t for t in D.TIER_ORDER if t in set(df["tier"])]
    chart = (alt.Chart(df).mark_bar(stroke=surface, strokeWidth=2, cornerRadius=2)
             .encode(y=alt.Y("source:N", title=None, sort=list(D.SOURCE_LABELS.values())),
                     x=alt.X("assets:Q", title="assets", stack="zero",
                             axis=alt.Axis(format="d", tickMinStep=1)),    # whole assets, no "2.5"
                     color=alt.Color("tier:N", title="verdict", sort=D.TIER_ORDER,
                                     scale=alt.Scale(domain=tiers_present,
                                                     range=[D.TIER_COLORS[t] for t in tiers_present]),
                                     legend=alt.Legend()),          # (orient="top" collapses the plot in st)
                     order=alt.Order("order:Q"),
                     tooltip=[alt.Tooltip("source:N"), alt.Tooltip("tier:N", title="verdict"),
                              alt.Tooltip("assets:Q")])
             .properties(height=max(190, 60 * df["source"].nunique())))
    st.altair_chart(chart, width="stretch")
    with st.expander("Same numbers as a table"):
        st.dataframe(df.pivot_table(index="source", columns="tier", values="assets", fill_value=0)
                     .reindex(columns=tiers_present), width="stretch")

# ====================================================================== tabs
t_road, t_assets, t_libs, t_cbom, t_how = st.tabs(
    ["Migration roadmap", "Assets", "Libraries", "CBOM", "How the score works"])

with t_road:
    st.caption("One row per change: replace X with Y. P1 = exposed today (HNDL / plaintext), P2 = long-lived or "
               "already broken, P3 = future forgery, P4 = Grover hardening, P5 = library upgrades first.")
    pri = st.multiselect("Priority", ["P1", "P2", "P3", "P4", "P5"], default=["P1", "P2", "P3", "P4", "P5"],
                         key="prio")
    road = D.roadmap_rows(bundle, [int(p[1]) for p in pri] or None)
    st.dataframe(pd.DataFrame(road), hide_index=True, width="stretch",
                 column_config={"risk": st.column_config.NumberColumn(format="%.2f"),
                                "why": st.column_config.TextColumn(width="large")})

with t_assets:
    f1, f2, f3, f4 = st.columns([1.2, 1.6, 0.8, 1.4])
    sources = f1.multiselect("Source", sorted({r["source"] for r in D.asset_rows(bundle)}), key="src")
    tiers = f2.multiselect("Verdict", D.TIER_ORDER, key="tiers")
    hndl = f3.checkbox("HNDL only", key="hndl")
    text = f4.text_input("Search asset / algorithm", key="search")
    arows = D.asset_rows(bundle, sources, tiers, hndl, text)
    st.caption(f"{len(arows)} asset(s)")
    st.dataframe(pd.DataFrame(arows), hide_index=True, width="stretch",
                 column_config={"risk": st.column_config.ProgressColumn(min_value=0, max_value=1.5, format="%.2f")})
    if arows:
        pick = st.selectbox("Inspect an asset", [r["asset"] for r in arows], key="pick")
        frows = D.findings_for_asset(bundle, pick)
        if frows:
            st.dataframe(pd.DataFrame(frows), hide_index=True, width="stretch")
        else:
            st.caption("No finding details loaded (open a folder that contains findings.json).")

with t_libs:
    libs = D.library_rows(bundle)
    if libs:
        st.dataframe(pd.DataFrame(libs), hide_index=True, width="stretch")
    else:
        st.caption("No dependency manifests (requirements.txt, go.mod, package.json, pom.xml, ...) in this scan.")

with t_cbom:
    crow = D.cbom_rows(bundle)
    if crow:
        st.caption(f"CycloneDX {bundle.cbom.get('specVersion')} · serial {bundle.cbom.get('serialNumber')}")
        st.dataframe(pd.DataFrame(crow), hide_index=True)
        st.caption("Each component carries evidence (file + line, JSON path or packet), its tier, HNDL flag and "
                   "the PQC replacement with its NIST FIPS 203 / 204 / 205 reference. Download it from the sidebar.")
    else:
        st.caption("No CBOM in this report folder.")

with t_how:
    s = bundle.score
    st.markdown(f"**Formula** — {s.get('formula', '')}")
    w = s.get("weights", {})
    if w:
        st.json(w, expanded=False)
    st.markdown(f"Pooled over all assets (for comparison): **{s.get('pooled_score')}** · "
                f"assets scored: {s.get('assets_scored')} · not scored (INFO / UNKNOWN): {s.get('assets_not_scored')}")
