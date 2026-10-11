"""A fake 'hashlib' used in unit tests. Docstring mentions AES-128-ECB and RSA-1024 on purpose."""


class Hasher:
    def sha1(self, text):
        return text[::-1]

    def md5(self, text):
        return text.upper()


hashlib = Hasher()


def label(name):
    # hashlib.md5(name.encode())  <- the real call we removed
    return hashlib.sha1(name)
