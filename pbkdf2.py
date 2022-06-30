import os

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC as PBKDF2HMAC_CRYPTO

class PBKDF2HMAC(object):
    @staticmethod
    def pbkdf2sha256(key, salt, length=32, iterations=1000):
        kdf = PBKDF2HMAC_CRYPTO(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            iterations=iterations,
        )
        key_verify = kdf.derive(key)
        return key_verify
    # end pbkdf2sha256

    @staticmethod
    def pbkdf2sha256_verify(key_verify: bytes, key: bytes, salt: bytes, length=32, iterations=1000):
        try:
            kdf = PBKDF2HMAC_CRYPTO(
                algorithm=hashes.SHA256(),
                length=length,
                salt=salt,
                iterations=iterations,
            )
            kdf.verify(key, key_verify)
            return True
        except InvalidKey:
            return False
    # end pbkdf2sha256_verify

    @staticmethod
    def pbkdf2sm3(key: bytes, salt: bytes, length=32, iterations=1000):
        kdf = PBKDF2HMAC_CRYPTO(
            algorithm=hashes.SM3(),
            length=length,
            salt=salt,
            iterations=iterations,
        )
        key_verify = kdf.derive(key)
        return key_verify
    # end pbkdf2sm3

    @staticmethod
    def pbkdf2sm3_verify(key_verify: bytes, key: bytes, salt, length=32, iterations=1000):
        try:
            kdf = PBKDF2HMAC_CRYPTO(
                algorithm=hashes.SM3(),
                length=length,
                salt=salt,
                iterations=iterations,
            )
            kdf.verify(key, key_verify)
            return True
        except InvalidKey:
            return False
    # end pbkdf2sm3_verify

if __name__ == '__main__':
    salt = os.urandom(16)
    key = b"password"

    key_verify = PBKDF2HMAC.pbkdf2sha256(key, salt)
    print("pbkdf2sha256 key_verify:", key_verify.hex())
    verify_result = PBKDF2HMAC.pbkdf2sha256_verify(key_verify, key, salt)
    print("pbkdf2sha256 verify_result:", verify_result)

    key_verify = PBKDF2HMAC.pbkdf2sm3(key, salt)
    print("pbkdf2sm3 key_verify:", key_verify.hex())
    verify_result = PBKDF2HMAC.pbkdf2sm3_verify(key_verify, key, salt)
    print("pbkdf2sm3 verify_result:", verify_result)
