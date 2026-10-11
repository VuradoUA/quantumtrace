"""Phase 2d: server configs (nginx, Apache httpd, OpenSSH) -> what each server ALLOWS.

Part 1 scans the sample infrastructure folder (tests/fixtures/sample-infra) end to end and checks every server's verdict.
Part 2 checks the building blocks on small snippets: OpenSSL cipher-string expansion,
inheritance / includes, defaults, certificate-type filtering, SSH +/-/^ lists, detection.
"""
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from quantumtrace.catalog import load_catalog
from quantumtrace.classify import classify
from quantumtrace.models import Tier, Usage
from quantumtrace.parsers.config import detect, parse_config_files
from quantumtrace.parsers.config.tls import expand_cipher_string, parse_groups, parse_protocols, resolve_path
from quantumtrace.scan import scan_path
from quantumtrace.summary import summarise

INFRA = Path(__file__).parent / "fixtures" / "sample-infra"
NOW = datetime(2026, 10, 11, tzinfo=timezone.utc)
CAT = load_catalog()


# ===================================================================== part 1: the sample infrastructure
@pytest.fixture(scope="module")
def infra():
    return scan_path(INFRA, now=NOW)


@pytest.fixture(scope="module")
def assets(infra):
    return {a.asset: a for a in summarise(infra.findings)}


EXPECTED = [
    # asset                          tier         hndl   flags that must be present
    ("api.example.lab:443",          "CRITICAL",  True,  {"tls1.0-enabled", "tls1.1-enabled", "no-forward-secrecy", "default-groups"}),
    ("vault.example.lab:443",        "SAFE",      False, set()),
    ("www.example.lab:80",           "INFO",      False, {"redirect-to-https"}),
    ("intranet.example.lab:8080",    "PLAINTEXT", False, set()),
    ("shop.example.lab:443",         "CRITICAL",  True,  {"tls1.0-enabled", "tls1.1-enabled", "downgrade-risk"}),
    ("shop.example.lab:80",          "INFO",      False, {"redirect-to-https"}),
    ("ssh/sshd_config",              "CRITICAL",  True,  {"downgrade-risk", "appended-to-default", "host-key"}),
    ("ssh/ssh_config [Host legacy-router]", "CRITICAL", True, {"appended-to-default", "weak-key-size"}),
]


@pytest.mark.parametrize("asset,tier,hndl,flags", EXPECTED, ids=[e[0] for e in EXPECTED])
def test_infra_server_verdicts(assets, asset, tier, hndl, flags):
    a = assets[asset]
    assert a.tier is Tier(tier)
    assert a.hndl is hndl
    assert flags <= a.flags, f"missing {flags - a.flags}"
    assert all(f.source == "config" for f in a.findings)


def test_infra_files_are_detected(infra):
    assert sorted(infra.files["config"]) == ["apache/ssl.conf", "nginx/nginx.conf", "nginx/sites-enabled/legacy-api",
                                           "nginx/sites-enabled/vault.conf", "nginx/sites-enabled/www.conf",
                                           "ssh/ssh_config", "ssh/sshd_config"]
    assert infra.skipped == []


def test_nginx_inherits_http_level_protocols_through_include(assets):
    """legacy-api has no ssl_protocols; nginx.conf's http{} (TLSv1 TLSv1.1 TLSv1.2) applies via include."""
    api = assets["api.example.lab:443"].findings
    assert all("tls1.0-enabled" in f.flags for f in api)
    suites = [f for f in api if f.usage is Usage.PROTOCOL]
    assert all(f.location == "nginx/sites-enabled/legacy-api:5" for f in suites)   # the ssl_ciphers line
    assert not any("TLS_AES" in f.algorithm for f in suites)                          # TLS 1.3 not enabled


def test_nginx_explicit_legacy_ciphers_are_kept_and_ecdsa_dropped(assets):
    """RC4-SHA / DES-CBC3-SHA are not in modern OpenSSL builds but the config asks for them;
    the ECDSA suite is dropped because api.pem holds an RSA certificate."""
    names = {f.algorithm for f in assets["api.example.lab:443"].findings}
    comps = {c.name for f in assets["api.example.lab:443"].findings for c in f.classification.components}
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in names and "TLS_RSA_WITH_AES_128_CBC_SHA" in names
    assert {"RC4", "3DES-CBC"} <= comps
    assert not any("ECDSA" in n for n in names)
    assert "default-groups" in next(f for f in assets["api.example.lab:443"].findings if f.algorithm == "ECDHE").flags


def test_post_quantum_vault_is_safe_and_linked_to_its_ml_dsa_certificate(assets):
    vault = assets["vault.example.lab:443"].findings
    assert sorted(f.algorithm for f in vault) == ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                                                  "X25519MLKEM768"]
    assert all(f.related == ["nginx/certs/vault-mldsa.pem"] for f in vault)
    assert "vault.example.lab:443" in assets["nginx/certs/vault-mldsa.pem"].findings[0].related
    assert assets["nginx/certs/vault-mldsa.pem"].tier is Tier.SAFE


def test_apache_all_minus_sslv3_and_hybrid_groups(assets):
    shop = assets["shop.example.lab:443"].findings
    groups = {f.algorithm: f for f in shop if f.usage is Usage.KEY_EXCHANGE}
    assert set(groups) == {"X25519MLKEM768", "X25519"}
    assert "downgrade-risk" in groups["X25519"].flags and "downgrade-risk" not in groups["X25519MLKEM768"].flags
    assert not any("ssl2-enabled" in f.flags or "ssl3-enabled" in f.flags for f in shop)
    tls13 = {f.algorithm for f in shop if f.algorithm in ("TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256",
                                                          "TLS_AES_128_GCM_SHA256")}
    assert tls13 == {"TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"}     # SSLCipherSuite TLSv1.3 ...
    # Apache uses built-in DH parameters, so DHE suites stay (nginx would need ssl_dhparam)
    assert any(f.algorithm.startswith("TLS_DHE_") for f in shop)
    assert not any("PSK" in f.algorithm for f in shop)


def test_sshd_lists(assets):
    sshd = {f.algorithm: f for f in assets["ssh/sshd_config"].findings}
    assert sshd["mlkem768x25519-sha256"].classification.tier is Tier.SAFE
    assert "downgrade-risk" in sshd["curve25519-sha256"].flags
    assert "downgrade-risk" in sshd["diffie-hellman-group14-sha1"].flags
    assert "appended-to-default" in sshd["ssh-rsa"].flags
    assert sshd["aes128-cbc"].classification.tier is Tier.MEDIUM
    host = sshd["Ed25519"]
    assert host.related == ["ssh/ssh_host_ed25519_key.pub"]      # HostKey -> the .pub file in the scan


def test_ssh_client_minus_removes_nothing_to_report(assets):
    assert not any(a.startswith("ssh/ssh_config [Host *]") for a in assets)


# ===================================================================== part 2: building blocks
def test_cipher_string_alias_expansion():
    suites = {s.name for s in expand_cipher_string("HIGH:!aNULL:!MD5", CAT)}
    assert "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" in suites
    assert "TLS_RSA_WITH_AES_256_CBC_SHA" in suites               # static RSA is in HIGH
    assert not any("anon" in s for s in suites)
    assert all(not s.startswith("TLS_AES_") for s in suites)      # TLS 1.3 suites are configured separately


def test_cipher_string_exclusions_apply_to_explicit_names():
    names = {s.name for s in expand_cipher_string("ECDHE-RSA-AES128-GCM-SHA256:RC4-SHA:!RC4", CAT)}
    assert names == {"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"}
    names = {s.openssl for s in expand_cipher_string("RC4-SHA:DES-CBC3-SHA", CAT)}   # nothing this OpenSSL has
    assert names == {"RC4-SHA", "DES-CBC3-SHA"}


def test_every_expanded_suite_is_understood_by_the_classifier():
    for s in expand_cipher_string("ALL:COMPLEMENTOFALL", CAT):
        if "PSK" in s.openssl or "SRP" in s.openssl:
            continue
        c = classify_name_ok(s.name)
        assert c, f"classifier does not understand {s.name} ({s.openssl})"


def classify_name_ok(name):
    from quantumtrace.classify import classify_name
    return all(comp.catalog_key for comp in classify_name(name).components)


def test_protocol_and_group_parsing():
    assert parse_protocols("TLSv1.2 TLSv1.3") == {"1.2", "1.3"}
    assert parse_protocols("all -SSLv3 -TLSv1 -TLSv1.1") == {"1.2", "1.3"}
    assert parse_protocols("all -SSLv3") == {"1.0", "1.1", "1.2", "1.3"}
    assert parse_groups("?*X25519MLKEM768 / ?*X25519:?secp256r1:-ffdhe2048") == (
        ["X25519MLKEM768", "X25519", "secp256r1"], False)
    assert parse_groups("DEFAULT:X25519MLKEM768") == (["X25519MLKEM768"], True)


def test_resolve_configured_paths():
    known = ["deploy/nginx/certs/api.pem", "other/api.pem", "deploy/nginx/sites/site.conf"]
    assert resolve_path("/etc/nginx/certs/api.pem", "deploy/nginx/sites/site.conf", known) == "deploy/nginx/certs/api.pem"
    assert resolve_path("../certs/api.pem", "deploy/nginx/sites/site.conf", known) == "deploy/nginx/certs/api.pem"
    assert resolve_path("/etc/ssl/missing.pem", "x.conf", known) is None
    assert resolve_path("/etc/nginx/certs/$host.pem", "x.conf", known) is None


def write(tmp_path, name, text):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text))
    return p


def config_findings(tmp_path, *paths, **kw):
    found = parse_config_files(list(paths), root=tmp_path, catalog=CAT, **kw)
    for f in found:
        classify(f)
    return found


def test_nginx_defaults_and_dhparam_rule(tmp_path):
    """No ssl_* at all: TLS 1.2+1.3, HIGH:!aNULL:!MD5, and NO DHE (no ssl_dhparam)."""
    p = write(tmp_path, "site.conf", """
        server {
            listen 443 ssl;
            server_name plain-defaults.lab;
        }""")
    found = config_findings(tmp_path, p)
    names = {f.algorithm for f in found}
    assert "TLS_AES_128_GCM_SHA256" in names and "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" in names
    assert not any(n.startswith("TLS_DHE_") for n in names)
    assert all("default-ciphers" in f.flags for f in found if f.usage is Usage.PROTOCOL)
    assert not any("tls1.0-enabled" in f.flags for f in found)
    with_dh = write(tmp_path, "dh/site.conf", """
        server { listen 443 ssl; server_name dh.lab; ssl_dhparam /etc/nginx/dhparam.pem; }""")
    assert any(f.algorithm.startswith("TLS_DHE_") for f in config_findings(tmp_path, with_dh))


def test_nginx_ssl_conf_command_inheritance(tmp_path):
    """ssl_conf_command is inherited only when the server has none of its own."""
    p = write(tmp_path, "nginx.conf", """
        http {
            ssl_protocols TLSv1.3;
            ssl_conf_command Groups X25519MLKEM768;
            server { listen 443 ssl; server_name a.lab; }
            server { listen 443 ssl; server_name b.lab; ssl_conf_command Ciphersuites TLS_AES_256_GCM_SHA384; }
        }""")
    found = config_findings(tmp_path, p)
    a = {f.algorithm for f in found if f.asset == "a.lab:443" and f.usage is Usage.KEY_EXCHANGE}
    b = {f.algorithm for f in found if f.asset == "b.lab:443" and f.usage is Usage.KEY_EXCHANGE}
    assert a == {"X25519MLKEM768"}
    assert b == {"ECDHE"}                       # own ssl_conf_command -> the http-level Groups is NOT inherited


def test_nginx_mixed_listen_and_quotes_and_comments(tmp_path):
    p = write(tmp_path, "mixed.conf", """
        server {
            listen 80;                      # plain
            listen [::]:8443 ssl http2;     # TLS
            server_name "mixed.lab";
            ssl_protocols TLSv1.2;  # ssl_protocols TLSv1;  <- commented out
            if ($scheme = http) { return 301 https://$host$request_uri; }
        }""")
    found = config_findings(tmp_path, p)
    assets = {f.asset for f in found}
    assert assets == {"mixed.lab:80", "mixed.lab:8443"}
    plain = next(f for f in found if f.asset == "mixed.lab:80")
    assert "redirect-to-https" in plain.flags and plain.classification.tier is Tier.INFO
    assert not any("tls1.0-enabled" in f.flags for f in found)


def test_cert_type_filtering_needs_the_certificate(tmp_path):
    p = write(tmp_path, "s.conf", """
        server { listen 443 ssl; server_name ec.lab; ssl_certificate /etc/ssl/ec.pem;
                 ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256; }""")
    unknown = {f.algorithm for f in config_findings(tmp_path, p) if f.usage is Usage.PROTOCOL}
    ec_only = {f.algorithm for f in config_findings(tmp_path, p, cert_families={"certs/ec.pem": {"ec"}},
                                                    known_files=["certs/ec.pem", "s.conf"]) if f.usage is Usage.PROTOCOL}
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" in unknown and "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" in unknown
    assert "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" not in ec_only
    assert "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" in ec_only


def test_apache_main_server_settings_are_inherited(tmp_path):
    p = write(tmp_path, "httpd.conf", """
        SSLProtocol -all +TLSv1.2
        SSLCipherSuite AES128-SHA
        <IfModule mod_ssl.c>
        <VirtualHost 192.0.2.10:8443>
            ServerName pay.lab
            SSLEngine on
            <Directory /var/www>
                SSLCipherSuite RC4-SHA
            </Directory>
        </VirtualHost>
        </IfModule>""")
    found = config_findings(tmp_path, p)
    assert {f.asset for f in found} == {"pay.lab:8443"}
    assert {f.algorithm for f in found if f.usage is Usage.PROTOCOL} == {"TLS_RSA_WITH_AES_128_CBC_SHA"}
    assert found[0].location == "httpd.conf:3"          # the main-server SSLCipherSuite line
    assert not any(f.usage is Usage.KEY_EXCHANGE for f in found)   # static RSA only: no group used


def test_apache_vhost_without_sslengine_is_plaintext(tmp_path):
    p = write(tmp_path, "sites/app.conf", """
        <VirtualHost *:80>
            ServerName app.lab
        </VirtualHost>""")
    found = config_findings(tmp_path, p)
    assert [(f.asset, f.classification.tier) for f in found] == [("app.lab:80", Tier.PLAINTEXT)]


def test_ssh_prefixes_and_match_blocks(tmp_path):
    p = write(tmp_path, "etc/ssh/sshd_config", """
        Ciphers ^aes256-ctr
        MACs -hmac-sha1
        Match User deploy
            KexAlgorithms=sntrup761x25519-sha512@openssh.com
            PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com
        """)
    found = config_findings(tmp_path, p)
    assert [(f.asset, f.algorithm) for f in found] == [
        ("etc/ssh/sshd_config", "aes256-ctr"),
        ("etc/ssh/sshd_config [Match User deploy]", "sntrup761x25519-sha512@openssh.com"),
        ("etc/ssh/sshd_config [Match User deploy]", "ssh-ed25519-cert-v01@openssh.com"),
        ("etc/ssh/sshd_config [Match User deploy]", "sk-ssh-ed25519@openssh.com")]
    assert {"ssh-certificate"} <= found[2].classification.flags
    assert {"security-key"} <= found[3].classification.flags


def test_detection_by_content(tmp_path):
    assert detect(write(tmp_path, "sites-enabled/shop", "server {\n listen 443 ssl;\n}\n")) == "nginx"
    assert detect(write(tmp_path, "vhosts/x.conf", "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n")) == "apache"
    assert detect(write(tmp_path, "hardening.conf", "KexAlgorithms curve25519-sha256\nCiphers aes256-ctr\n")) == "ssh"
    assert detect(write(tmp_path, "notes.conf", "Ciphers are explained in the wiki\n")) is None
    assert detect(write(tmp_path, "app.conf", "[server]\nport = 8080\n")) is None
    assert detect(write(tmp_path, "README", "server { is a word here\n")) is None
