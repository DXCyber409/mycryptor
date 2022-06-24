from cryptography.hazmat.primitives import hashes, hmac

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

def hmac_sha256(key, data):
    key = key if isinstance(key, bytes) else key.encode()
    h = hmac.HMAC(key=key, algorithm=hashes.SHA256())
    h.update(data)
    return h.finalize()

def hmac_sha1(key, data):
    key = key if isinstance(key, bytes) else key.encode()
    h = hmac.HMAC(key=key, algorithm=hashes.SHA1())
    h.update(data)
    return h.finalize()

def hmac_sm3(key, data):
    key = key if isinstance(key, bytes) else key.encode()
    h = hmac.HMAC(key=key, algorithm=hashes.SM3())
    h.update(data)
    return h.finalize()
