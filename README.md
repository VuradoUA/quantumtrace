# QuantumTrace

**Find the cryptography a quantum computer will break, before someone records your traffic today.**

QuantumTrace is a non-intrusive scanner for post-quantum readiness. It reads what you already have:
network captures, source code, cloud exports, server configs, certificates and dependency manifests.
It reports every cryptographic algorithm it finds and how urgent the fix is, and lists what to migrate
first. The output is a Quantum Risk Score, a migration roadmap and a CycloneDX 1.6 CBOM mapped to
NIST FIPS 203 / 204 / 205. Nothing is sent anywhere and no system is probed.

```
./demo.sh            # scan the starter kit, validate the CBOM, measure accuracy, open the dashboard
```

---

## Quick start

### Option 1: Docker (nothing else to install, tshark included)

```bash
docker build -t quantumtrace .
KIT="$PWD/../JunctionX-QuantumTrace"

docker run --rm -p 8501:8501 -v "$KIT:/data:ro" quantumtrace            # dashboard on http://localhost:8501
docker run --rm -v "$KIT:/data:ro" quantumtrace scan /data                # terminal report
docker run --rm -v "$KIT:/data:ro" -v "$PWD/report:/out" --user "$(id -u):$(id -g)" \
           quantumtrace scan /data --out /out                             # JSON report + CBOM in ./report
docker run --rm -v "$KIT:/data:ro" quantumtrace benchmark                 # accuracy against labelled data
```

### Option 2: local install (Python 3.10+)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dashboard]"          # add ,dev for the test suite
sudo apt install tshark                # only needed for PCAP files
quantumtrace scan ../JunctionX-QuantumTrace --out report
quantumtrace dashboard ../JunctionX-QuantumTrace --report report
```

### Option 3: one command

`./demo.sh [PATH] [--docker | --local]` scans PATH (default: the starter kit next to this folder) and
writes `report/`. It then validates the CBOM, runs the benchmark and opens the dashboard. It uses
QuantumTrace if it is installed, otherwise Docker, and otherwise creates `.venv`. If port 8501 is
busy, the dashboard takes the next free port.

---

## What it reads

| Source | Files | What is extracted |
|---|---|---|
| **Network** | `.pcap`, `.pcapng`, `.cap` (via tshark) | Per session, what was *negotiated*: TLS version, cipher suite, key-exchange group (incl. X25519MLKEM768), signature scheme, server certificate; SSH KEX / host key / cipher / MAC; plaintext protocols. What clients *offer* goes into the PQC-readiness statistics. |
| **Code** | Python, Java and Go, the challenge languages, with full syntax-tree parsers (tree-sitter) | Library calls (hashlib, pyca/cryptography, PyCryptodome, Fernet, PyJWT, JCA, Go crypto/*, x/crypto, crypto/tls), key sizes (also from constants), cipher modes, hardcoded keys, insecure RNG, hand-rolled ECB / PBKDF2, embedded PEM blocks. Comments, strings and look-alike names are not findings. |
| **Cloud** | JSON exports: AWS KMS, ACM, ELB/ALB listeners; GCP KMS, Azure Key Vault, JWK and other JSON (generic) | Key specs and usage, signing / encryption algorithms, TLS policies expanded to their cipher suites, certificate key and signature, expiry, rotation, pending deletion. Listeners are linked to their certificates. |
| **Config** | nginx, Apache httpd, OpenSSH `sshd_config` / `ssh_config` | Per server/host: protocols, cipher string expanded with OpenSSL, groups / curves, certificate used, inherited settings and includes, plaintext listeners and redirects. |
| **Certificates & keys** | PEM / DER / PKCS#12 / PKCS#7 / OpenSSH keys | Key algorithm and size, signature algorithm, validity, CA flag. ML-DSA and SLH-DSA certificates are recognised. Private key material is never copied into the output. |
| **Dependencies** | requirements*.txt, pyproject.toml, Pipfile, go.mod, package.json, pom.xml, build.gradle(.kts), Cargo.toml | Crypto libraries with a package URL. Each is checked for whether the declared version already has a post-quantum API (e.g. cryptography ≥ 48, Go ≥ 1.24), or is deprecated (pycrypto). The library is linked to the code that uses it. |

Results are grouped into **four sections, one per source** (network, code, cloud, config). Each
section gets its own sub-score, so 135 PCAP sessions cannot drown 24 code files.

---

## How a finding is classified

| Tier | Meaning | Examples |
|---|---|---|
| **CRITICAL** | Broken by Shor's algorithm at any key size | RSA, DSA, DH, ECDSA, ECDH, Ed25519, X25519 |
| **MEDIUM** | Weakened by Grover below 256-bit strength, or broken today | AES-128/192, 3DES, SHA-1, MD5, HMAC-SHA1 |
| **SAFE** | 256-bit symmetric strength, large hashes, NIST PQC and PQ hybrids | AES-256, SHA-384, ML-KEM, ML-DSA, SLH-DSA, X25519MLKEM768 |
| **PLAINTEXT** | No encryption | HTTP, NULL cipher suites |
| INFO / UNKNOWN | Listed, not scored | Library inventory, HTTP→HTTPS redirect, AES with unknown key size |

* **HNDL (Harvest Now, Decrypt Later)** means a Shor-breakable algorithm protects *confidentiality*
  (key exchange or encryption). The traffic can be recorded today and decrypted later. Signatures
  are "CRITICAL – future": they can be forged once a quantum computer exists, but nothing recorded
  today leaks.
* Composite names are split into their parts and the worst part decides. For example,
  `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` becomes ECDH + RSA + AES-128-CBC + HMAC-SHA1.
* Flags add context: `classically-broken`, `weak-key-size`, `no-forward-secrecy`, `downgrade-risk`
  (a weak option that is only a fallback), `insecure-mode` (ECB), `hardcoded-key`, `expired`,
  `long-lived`, `tls1.0-enabled` …
* Every algorithm has a NIST replacement: ML-KEM-768 (FIPS 203) for key exchange and encryption,
  ML-DSA-65 (FIPS 204) for signatures, SLH-DSA (FIPS 205) for long-lived roots and code signing.
  Hybrids are X25519MLKEM768 for TLS and mlkem768x25519-sha256 for SSH.

All rules live in one file, `quantumtrace/catalog.yaml`: 63 algorithms with aliases, 45 composite
names, the IANA TLS registries, AWS ELB policies and crypto libraries. To try a single name:
`quantumtrace classify "SHA1withRSA"`.

---

## Quantum Risk Score

0 means nothing left to migrate. 100 means everything is exposed. The unit scored is the **asset**
(a file, a host:port, a KMS key, a certificate), because that is what gets fixed.

```
severity  S = worst finding:  CRITICAL 1.0 · PLAINTEXT 1.0 · MEDIUM 0.4 · SAFE 0
              ×0.5 if it is only a fallback option · +0.3 if also broken today (max 1.0)
exposure  E = 1.5  HNDL or not encrypted        1.3  long-lived key / certificate        1.0  otherwise

source score        = 100 × Σ(S·E) / Σ E          over the scored assets of that source
Quantum Risk Score  = mean of the source scores   (network, code, cloud, config weigh the same)
```

The starter kit scores **75** (network 96.5, code 47.5, cloud 81.9). Of its 183 assets, 136 are
CRITICAL, and 120 of those are HNDL-exposed. 7 of its 97 TLS sessions already use a post-quantum
key exchange.

**Migration roadmap:** one row per change ("replace X with Y"), ranked by priority and then by risk:

| Priority | Meaning |
|---|---|
| P1 | Exposed today: HNDL or plaintext |
| P2 | Long-lived key / certificate, or already broken without a quantum computer |
| P3 | Shor-breakable signature: forgeable in the future |
| P4 | Grover hardening: move to 256-bit |
| P5 | Enabler: upgrade the library first |

---

## Outputs

`quantumtrace scan PATH --out DIR` writes:

* **`cbom.json`** is a CycloneDX 1.6 CBOM. It holds algorithm, certificate, key (related crypto
  material), protocol and library components, plus services for endpoints. Each component carries:
  * `cryptoProperties` (primitive, mode, parameter set, NIST quantum security level, functions, OID)
  * `evidence.occurrences` with file and line, JSON path or packet frame
  * dependency links (`dependsOn` / `provides`)
  * the tier, HNDL flag and replacement as properties
  * a reference to FIPS 203 / 204 / 205 in `definitions.standards`

  Every CBOM is checked against the official CycloneDX 1.6 JSON schema, plus a check that all
  references resolve. `quantumtrace validate FILE` checks any CBOM, ours or someone else's.
* **`report.json`** holds the score with its formula and weights, a summary per source, every asset
  with its verdict, the roadmap, the libraries and the PCAP PQC readiness.
* **`findings.json`** holds every individual occurrence with its exact location and evidence.

## Dashboard

`quantumtrace dashboard [PATH] [--report DIR]` (Streamlit) has three ways in: scan a path, upload
files or a zip, or open a report folder. The page shows:

* the score, HNDL-exposed assets, assets broken already, quantum-safe assets and PQC readiness
* assets by verdict for each source
* a roadmap that can be filtered by priority
* an asset table that can be searched, with a drill-down to each finding
* the library inventory and a CBOM summary, with downloads of all three JSON files

Uploads are unpacked safely: path traversal, symlinks and zip bombs are refused.

---

## Accuracy

`quantumtrace benchmark` compares scan results with labels written by hand. For each source it
reports precision and recall on:

* **assets** found
* **algorithms**, compared as families, so spelling does not matter but a missing or extra
  algorithm does
* the **verdict** (tier)
* the **HNDL** call
* **key sizes**

Decoy files contain crypto words but no cryptography. Any finding in a decoy counts as a false
positive.

| Dataset | What it is | First run | Now |
|---|---|---|---|
| **Hold-out** (5 assets + 5 decoys) | Written and labelled *before* QuantumTrace ever saw them, frozen by SHA-256 | Verdicts 5/5, HNDL 2/2, algorithms F1 100%, decoys 5/5 clean, key sizes 3/4 | 100% |
| **Adversarial** (12 assets + 4 decoys) | Written to break the parsers: Fernet, JWT, Go `tls.Config`, GCP / Azure keys, look-alike names | Verdicts 67%, algorithm recall 74%, decoys 2/4 | 100% |
| **Starter kit** (181 assets) | The organisers' kit, every file verified by hand / with tshark | – | 100% |
| **Sample infrastructure** (19 assets) | nginx / Apache / SSH configs, certificates, keys, manifests in `tests/fixtures/sample-infra` | – | 100% |
| **Classification** (85 names) | Algorithm names labelled from the challenge definitions, not from the catalog | Tier 100%, HNDL 99% | 100% |

These numbers need careful reading. Only the hold-out is blind, and it is small. The starter kit and
the sample infrastructure were used while building the tool, so they are regression checks. The
adversarial "now" column comes after fixing what it found. Both first runs are kept unchanged in
`tests/benchmarks/results/`.

---

## Project layout

```
quantumtrace/
  catalog.yaml / catalog.py   all classification knowledge (algorithms, aliases, TLS registries, libraries)
  classify.py                 name -> components -> tier, HNDL, flags, replacement
  parsers/                    pcap.py · code/ (python, java, go, fallback) · cloud.py · config/ (nginx, apache, ssh) · certs.py · manifests.py
  scan.py                     detects file kinds, runs the parsers, links libraries <-> code, listeners <-> certificates
  score.py · report.py        Quantum Risk Score, roadmap, report.json
  cbom.py                     CycloneDX 1.6 CBOM + validation
  benchmark.py                precision / recall against labelled datasets
  dashboard/                  Streamlit page (app.py) over a plain-Python data layer (data.py)
  cli.py                      `quantumtrace scan | dashboard | benchmark | validate | classify | catalog`
tests/                        pytest suite, ground_truth.yaml, fixtures, benchmarks/
Dockerfile · demo.sh
```

## Tests

```bash
pip install -e ".[dev]"
python -m pytest -q          # the starter-kit tests run when ../JunctionX-QuantumTrace exists (or QT_KIT=...)
```

The suite has been run on Python 3.10, 3.13 and 3.14, with OpenSSL 3.0 and 3.5, and with both the
oldest and the newest supported dependency versions. Every rule was also checked by breaking it on purpose
and confirming that a test fails.

## Limits

* Static analysis: code is not executed. Keys, algorithms or sizes built at runtime from outside
  input can be missed.
* Other languages (JS/TS, C/C++, Rust …) are outside the challenge scope: they only get a best-effort,
  low-confidence match of algorithm names in strings.
* PCAP: only unencrypted handshake data is visible. In TLS 1.3 the server certificate is encrypted.
* Cipher strings such as `HIGH:!aNULL` are expanded with the local OpenSSL, so the exact suite count
  can differ between OpenSSL versions. Verdicts do not change.
* Not covered: compiled binary artefacts and live endpoint probing. Both are optional in the
  challenge, and no binaries or endpoints were provided. HAProxy and other server formats are also
  not covered.
