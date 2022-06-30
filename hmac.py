import os

from cryptography.hazmat.primitives import hashes, hmac

class HMac(object):
    @staticmethod
    def hmac_md5(key, data):
        key = key if isinstance(key, bytes) else key.encode()
        h = hmac.HMAC(key=key, algorithm=hashes.MD5())
        h.update(data)
        return h.finalize()

    @staticmethod
    def hmac_sha1(key, data):
        key = key if isinstance(key, bytes) else key.encode()
        h = hmac.HMAC(key=key, algorithm=hashes.SHA1())
        h.update(data)
        return h.finalize()

    @staticmethod
    def hmac_sha256(key, data):
        key = key if isinstance(key, bytes) else key.encode()
        h = hmac.HMAC(key=key, algorithm=hashes.SHA256())
        h.update(data)
        return h.finalize()

    @staticmethod
    def hmac_sha512(key, data):
        key = key if isinstance(key, bytes) else key.encode()
        h = hmac.HMAC(key=key, algorithm=hashes.SHA512())
        h.update(data)
        return h.finalize()

    @staticmethod
    def hmac_sm3(key, data):
        key = key if isinstance(key, bytes) else key.encode()
        h = hmac.HMAC(key=key, algorithm=hashes.SM3())
        h.update(data)
        return h.finalize()

if __name__ == '__main__':
    key = os.urandom(16)
    data = b"123456"
    hmac_data = HMac.hmac_sha256(key, data)
    print("key:", key.hex())
    print("hmac_data:", hmac_data.hex())
