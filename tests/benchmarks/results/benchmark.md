# QuantumTrace benchmark (2026-10-11)

## All datasets, per source

| source | assets | detection P / R | algorithms P / R (F1) | verdict acc. | HNDL P / R | key sizes |
|---|---:|---|---|---:|---|---:|
| network | 135 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 0/0 |
| code | 39 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 18/18 |
| cloud | 27 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 2/2 |
| config | 16 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 2/2 |
| **all** | 217 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 22/22 |

## holdout

Scanned `tests/benchmarks/holdout`: {'cloud': 1, 'code': 8, 'config': 1}

| source | assets | detection P / R | algorithms P / R (F1) | verdict acc. | HNDL P / R | key sizes |
|---|---:|---|---|---:|---|---:|
| code | 4 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 4/4 |
| config | 1 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 0/0 |
| **all** | 5 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 4/4 |

Decoys clean: 5 / 5

No differences from the labels.

## adversarial

Scanned `tests/benchmarks/adversarial`: {'cloud': 2, 'code': 8, 'config': 2}

| source | assets | detection P / R | algorithms P / R (F1) | verdict acc. | HNDL P / R | key sizes |
|---|---:|---|---|---:|---|---:|
| code | 4 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 4/4 |
| cloud | 5 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 2/2 |
| config | 3 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 0/0 |
| **all** | 12 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 6/6 |

Decoys clean: 4 / 4

No differences from the labels.

## sample-infra

Scanned `tests/fixtures/sample-infra`: {'code': 2, 'manifest': 5, 'cert': 4, 'config': 7}

| source | assets | detection P / R | algorithms P / R (F1) | verdict acc. | HNDL P / R | key sizes |
|---|---:|---|---|---:|---|---:|
| code | 7 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 1/1 |
| config | 12 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 2/2 |
| **all** | 19 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 3/3 |

Libraries: precision 100%, recall 100%

No differences from the labels.

## kit

Scanned `../JunctionX-QuantumTrace`: {'cloud': 3, 'code': 24, 'manifest': 2, 'pcap': 1}

| source | assets | detection P / R | algorithms P / R (F1) | verdict acc. | HNDL P / R | key sizes |
|---|---:|---|---|---:|---|---:|
| network | 135 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 0/0 |
| code | 24 | 100% / 100% | 100% / 100% (100%) | 100% | – / – | 9/9 |
| cloud | 22 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 0/0 |
| **all** | 181 | 100% / 100% | 100% / 100% (100%) | 100% | 100% / 100% | 9/9 |

Libraries: precision 100%, recall 100%

PCAP setups: tls12-static-rsa 54/54, tls13-x25519 36/36, tls13-hybrid-pq 7/7, ssh-legacy 14/14, ssh-modern 10/10, http-plaintext 14/14

No differences from the labels.

## Classification (algorithm names, labelled independently of the catalog)

85 cases: tier 100%, threat 100%, HNDL 100%
