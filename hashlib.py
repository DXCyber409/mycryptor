from cryptography.hazmat.primitives import hashes

def md5(data):
    digest = hashes.Hash(hashes.MD5())
    digest.update(data)
    return digest.finalize()

def sha1(data):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(data)
    return digest.finalize()

def sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()

def sm3(data):
    digest = hashes.Hash(hashes.SM3())
    digest.update(data)
    return digest.finalize()
