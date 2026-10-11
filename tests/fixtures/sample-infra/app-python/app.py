from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Cipher import AES

key = ec.generate_private_key(ec.SECP256R1())
digest = hashes.Hash(hashes.SHA256())
cipher = AES.new(b"0123456789abcdef", AES.MODE_GCM)

# CA pinned for the partner API (public certificate, pasted into the code)
PINNED_CA = """-----BEGIN CERTIFICATE-----
MIIBfTCCAQSgAwIBAgIUA1w6rv8MmXRv8jmS4k9zudf8xs4wCgYIKoZIzj0EAwMw
FjEUMBIGA1UEAwwLTGFiIFJvb3QgQ0EwHhcNMjYwMTAxMDAwMDAwWhcNNDEwMTAx
MDAwMDAwWjAWMRQwEgYDVQQDDAtMYWIgUm9vdCBDQTB2MBAGByqGSM49AgEGBSuB
BAAiA2IABHVH4DIV+kRmV1v09/ivVPIQWdF3cdx3NMVebjgnTbSLoL1QcJVSycmQ
0RF6NRZFC+x3ZjX8ILdUeh6Jwnup9DeFzK9WFuq+n5maaSP0jkrhKRCCq1Nd7BNR
N/fdLdGbf6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhkjOPQQDAwNnADBkAjAZ
BEBXXWL8c0dGpGWKZX1arwbgUII6m9MONPxv5qiq/orkq11YysRn4K2+EDHxaLsC
MCMNqumL2HVFLUjYwE5qsI5SEMglgjsNm0e0vWfzf+qqAij5pl0tBehkN0aHYs2P
mw==
-----END CERTIFICATE-----
"""
