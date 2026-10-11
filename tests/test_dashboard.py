"""Phase 4: the dashboard.

Part 1 tests the data layer (plain Python): loading a report folder, scanning, safe uploads, tables.
Part 2 runs the real Streamlit page headlessly (streamlit.testing AppTest) and clicks through it.
Part 3 tests the `quantumtrace dashboard` command without starting a server.
"""
import io
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quantumtrace.cli import main
from quantumtrace.dashboard import data as D

HERE = Path(__file__).parent
KIT = Path(os.environ.get("QT_KIT", HERE.parents[1] / "JunctionX-QuantumTrace"))
INFRA = HERE / "fixtures" / "sample-infra"
APP = HERE.parent / "quantumtrace" / "dashboard" / "app.py"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
needs_kit = pytest.mark.skipif(not (KIT / "network-capture").is_dir(), reason=f"starter kit not found at {KIT}")


@pytest.fixture(scope="module")
def kit():
    return D.scan_to_bundle(KIT, now=NOW)


@pytest.fixture(scope="module")
def infra():
    return D.scan_to_bundle(INFRA, now=NOW)


# ===================================================================== part 1: data layer
@needs_kit
def test_headline_is_the_engine_numbers(kit):
    h = D.headline(kit)
    assert h["score"] == 75.3 and h["by_source"] == {"network": 96.5, "code": 47.5, "cloud": 81.9}
    assert (h["assets"], h["findings"], h["hndl_assets"]) == (183, 416, 120)
    assert (h["pqc_sessions"], h["tls_sessions"]) == (7, 97) and h["cbom_valid"] is True


@needs_kit
def test_tier_rows_add_up_to_every_asset(kit):
    rows = D.tier_rows(kit)
    assert sum(r["assets"] for r in rows) == 183
    assert {r["source"] for r in rows} == {"network", "code", "cloud"}
    assert all(r["tier"] in D.TIER_COLORS for r in rows)
    net = {r["tier"]: r["assets"] for r in rows if r["source"] == "network"}
    assert net == {"SAFE": 7, "CRITICAL": 114, "PLAINTEXT": 14}


@needs_kit
def test_asset_filters(kit):
    assert len(D.asset_rows(kit)) == 183
    assert len(D.asset_rows(kit, hndl_only=True)) == 120
    assert len(D.asset_rows(kit, sources=["code"], tiers=["MEDIUM"])) == 9
    hits = D.asset_rows(kit, text="vault")
    assert hits and all("vault" in r["asset"].lower() for r in hits)          # case-insensitive
    assert D.asset_rows(kit, text="ed25519")                       # search also matches the worst algorithm
    assert D.asset_rows(kit, text="VAULT") == hits                 # case does not matter


@needs_kit
def test_roadmap_filter_and_findings_drilldown(kit):
    p1 = D.roadmap_rows(kit, [1])
    assert p1 and all(r["priority"] == "P1" for r in p1)
    assert len(D.roadmap_rows(kit)) == len(kit.report["roadmap"])
    rows = D.findings_for_asset(kit, "sample-repos/python/report_export.py")
    assert rows and {"AES", "insecure-random"} <= {r["algorithm"] for r in rows}
    assert all(r["location"].startswith("sample-repos/python/report_export.py:") for r in rows)


def test_libraries_and_cbom_tables(infra):
    libs = {r["library"]: r for r in D.library_rows(infra)}
    assert libs["liboqs-python"]["status"] == "post-quantum library"
    assert libs["stdlib"]["status"] == "no PQC API in this version"
    assert libs["cryptography"]["status"] == "depends on the installed version"
    assert libs["pycrypto"]["deprecated"] == "yes"
    assert libs["org.bouncycastle:bcprov-jdk18on"]["status"] == "PQC API available"
    assert libs["golang.org/x/crypto"]["status"] == "classical only / unknown"
    counts = {r["component"]: r["count"] for r in D.cbom_rows(infra)}
    assert counts["certificates"] == 4 and counts["libraries"] >= 16 and counts["service (endpoint)"] == 6
    assert sum(counts.values()) == len(infra.cbom["components"]) + len(infra.cbom["services"])
    assert set(D.downloads(infra)) == {"report.json", "cbom.json", "findings.json"}


def test_load_folder_round_trip(tmp_path, infra):
    assert main(["scan", str(INFRA), "--out", str(tmp_path), "--now", "2026-10-11"]) == 0
    b = D.load_folder(tmp_path)
    assert D.headline(b)["score"] == D.headline(infra)["score"]
    assert len(b.findings) == len(infra.findings) and b.cbom["specVersion"] == "1.6"


def test_load_folder_errors(tmp_path):
    with pytest.raises(D.DashboardError, match="no report.json"):
        D.load_folder(tmp_path)
    (tmp_path / "report.json").write_text("{not json")
    with pytest.raises(D.DashboardError, match="not valid JSON"):
        D.load_folder(tmp_path)
    (tmp_path / "report.json").write_text('{"hello": 1}')
    with pytest.raises(D.DashboardError, match="not a QuantumTrace report"):
        D.load_folder(tmp_path)


def test_scan_errors(tmp_path):
    with pytest.raises(D.DashboardError, match="does not exist"):
        D.scan_to_bundle(tmp_path / "nope")
    (tmp_path / "notes.md").write_text("nothing to see")
    with pytest.raises(D.DashboardError, match="nothing QuantumTrace can read"):
        D.scan_to_bundle(tmp_path)


# ---------------------------------------------------------------- uploads
def _zip(entries: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_upload_files_and_zip_then_scan(tmp_path):
    zipped = _zip({"nginx/sites-enabled/vault.conf": (INFRA / "nginx/sites-enabled/vault.conf").read_bytes(),
                   "nginx/certs/vault-mldsa.pem": (INFRA / "nginx/certs/vault-mldsa.pem").read_bytes()})
    written = D.save_uploads([("infra.zip", zipped),
                              ("requirements.txt", (INFRA / "app-python/requirements.txt").read_bytes())], tmp_path)
    assert sorted(written) == ["infra/nginx/certs/vault-mldsa.pem", "infra/nginx/sites-enabled/vault.conf",
                               "requirements.txt"]
    b = D.scan_to_bundle(tmp_path, now=NOW, label="upload")
    assets = {a["asset"]: a for a in b.report["assets"]}
    assert assets["vault.example.lab:443"]["tier"] == "SAFE"
    assert any(lib["library"] == "pycrypto" for lib in b.report["libraries"])


@pytest.mark.parametrize("bad", ["../escape.txt", "/etc/passwd", "a/../../escape.txt", "C:/windows/x.ini"])
def test_zip_slip_is_refused(tmp_path, bad):
    with pytest.raises(D.DashboardError, match="refused"):
        D.save_uploads([("evil.zip", _zip({bad: b"x"}))], tmp_path / "up")
    assert not (tmp_path / "escape.txt").exists()


def test_zip_symlink_and_bomb_and_garbage_are_refused(tmp_path, monkeypatch):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        info = zipfile.ZipInfo("link")
        info.external_attr = (0o120777 << 16)
        z.writestr(info, "/etc/passwd")
    with pytest.raises(D.DashboardError, match="symlink"):
        D.save_uploads([("s.zip", buf.getvalue())], tmp_path / "a")
    monkeypatch.setattr(D, "MAX_UPLOAD_BYTES", 1000)
    with pytest.raises(D.DashboardError, match="too large"):
        D.save_uploads([("big.zip", _zip({"big.txt": b"0" * 5000}))], tmp_path / "b")
    with pytest.raises(D.DashboardError, match="not a valid zip"):
        D.save_uploads([("fake.zip", b"PK nope")], tmp_path / "c")
    with pytest.raises(D.DashboardError, match="refused file name"):
        D.save_uploads([("", b"x")], tmp_path / "d")


# ===================================================================== part 2: the page itself
@pytest.fixture()
def app(monkeypatch):
    from streamlit.testing.v1 import AppTest
    monkeypatch.setenv("QT_NOW", "2026-10-11")
    monkeypatch.setenv("QT_TARGET", str(INFRA))
    monkeypatch.delenv("QT_REPORT", raising=False)
    return AppTest.from_file(str(APP), default_timeout=120)


def metrics(at):
    return {m.label: m.value for m in at.metric}


def test_page_starts_empty_then_scans(app):
    app.run()
    assert not app.exception and app.info and not app.metric
    app.button(key="scan").click().run()
    assert not app.exception
    m = metrics(app)
    assert m["Quantum Risk Score"] == "92 / 100" and m["HNDL-exposed assets"] == "6"
    assert any("valid CycloneDX 1.6" in s.value for s in app.success)
    assert [t.label for t in app.tabs] == ["Migration roadmap", "Assets", "Libraries", "CBOM", "How the score works"]
    assert [b.label for b in app.get("download_button")] == [
        "Download CBOM (CycloneDX 1.6, standard inventory)", "Download risk report (score + roadmap)",
        "Download raw findings (every occurrence)"]


def test_page_filters_and_drilldown(app):
    app.run()
    app.button(key="scan").click().run()
    app.multiselect(key="tiers").set_value(["PLAINTEXT"]).run()
    assert not app.exception
    assert app.selectbox(key="pick").options == ["intranet.example.lab:8080"]
    frames = [d.value for d in app.dataframe]
    assert any("plaintext" in set(df.get("algorithm", [])) for df in frames)        # findings of that asset
    app.multiselect(key="prio").set_value(["P5"]).run()
    road = next(d.value for d in app.dataframe if "priority" in d.value.columns)
    assert set(road["priority"]) == {"P5"}


def test_page_opens_a_report_folder_and_shows_errors(app, tmp_path):
    main(["scan", str(INFRA), "--out", str(tmp_path / "rep"), "--now", "2026-10-11"])
    app.run()
    app.radio(key="mode").set_value("Open a report folder").run()
    app.text_input(key="folder").set_value(str(tmp_path / "missing")).run()
    app.button(key="open").click().run()
    assert not app.exception and any("no report.json" in e.value for e in app.error)
    app.text_input(key="folder").set_value(str(tmp_path / "rep")).run()
    app.button(key="open").click().run()
    assert not app.exception and metrics(app)["Quantum Risk Score"] == "92 / 100"


def test_page_opens_the_report_given_on_the_command_line(app, tmp_path, monkeypatch):
    main(["scan", str(INFRA), "--out", str(tmp_path / "rep"), "--now", "2026-10-11"])
    monkeypatch.setenv("QT_REPORT", str(tmp_path / "rep"))           # what `dashboard --report` / demo.sh sets
    app.run()                                                       # no click needed
    assert not app.exception and metrics(app)["Quantum Risk Score"] == "92 / 100"
    assert app.radio(key="mode").value == "Open a report folder"
    app.radio(key="mode").set_value("Scan a folder or file").run()   # the user can still switch away
    assert not app.exception and metrics(app)["Quantum Risk Score"] == "92 / 100"


def test_page_reports_a_missing_report_folder_without_crashing(app, tmp_path, monkeypatch):
    monkeypatch.setenv("QT_REPORT", str(tmp_path / "nope"))
    app.run()
    assert not app.exception and any("no report.json" in e.value for e in app.error) and not app.metric
    app.run()                                                       # tried once, not on every rerun
    assert not app.error


def test_page_upload_mode_renders(app):
    app.run()
    app.radio(key="mode").set_value("Upload files").run()
    assert not app.exception


# ===================================================================== part 3: the command
def test_dashboard_command(monkeypatch, tmp_path):
    import quantumtrace.cli as cli
    seen = {}
    monkeypatch.setattr("subprocess.call", lambda cmd, env: seen.update(cmd=cmd, env=env) or 0)
    assert cli.main(["dashboard", str(INFRA), "--now", "2026-10-11", "--port", "8600", "--headless"]) == 0
    assert seen["cmd"][1:4] == ["-m", "streamlit", "run"] and seen["cmd"][4].endswith("dashboard/app.py")
    assert "8600" in seen["cmd"] and "--server.headless" in seen["cmd"]
    assert seen["env"]["QT_TARGET"] == str(INFRA.resolve()) and seen["env"]["QT_NOW"] == "2026-10-11"
    monkeypatch.setattr("importlib.util.find_spec", lambda name: None)
    assert cli.main(["dashboard"]) == 1


def test_dashboard_picks_a_free_port(monkeypatch, capsys):
    import socket

    import quantumtrace.cli as cli
    with socket.socket() as busy:
        busy.bind(("", 0))
        busy.listen()
        taken = busy.getsockname()[1]
        free = cli._free_port(taken, tries=5)
        assert free is not None and free != taken
    seen = {}
    monkeypatch.setattr("subprocess.call", lambda cmd, env: seen.update(cmd=cmd) or 0)
    monkeypatch.setattr(cli, "_free_port", lambda start: 8503)
    assert cli.main(["dashboard", str(INFRA)]) == 0
    assert seen["cmd"][seen["cmd"].index("--server.port") + 1] == "8503"
    assert "8501 is busy" in capsys.readouterr().out
    monkeypatch.setattr(cli, "_free_port", lambda start: None)
    assert cli.main(["dashboard"]) == 1
