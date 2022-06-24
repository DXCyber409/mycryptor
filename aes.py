from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESCrypto(object):
    """AESCrypto."""

    def __init__(self, key, iv):
        if not isinstance(key, bytes):
            key = key.encode()

        if not isinstance(iv, bytes):
            iv = iv.encode()

        self.key = key
        self.iv = iv

    def cbc_encrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        if with_pkcs7padding:
            data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def cbc_decrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        data = cipher.decryptor().update(data)
        if with_pkcs7padding:
            data = self.pkcs7_unpadding(data).decode()
        return data

    def ecb_encrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        if with_pkcs7padding:
            data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def ecb_decrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        data = cipher.decryptor().update(data)
        if with_pkcs7padding:
            data = self.pkcs7_unpadding(data).decode()
        return data

    def cfb_encrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        if with_pkcs7padding:
            data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def cfb_decrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        data = cipher.decryptor().update(data)
        if with_pkcs7padding:
            data = self.pkcs7_unpadding(data).decode()
        return data

    def ctr_encrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv), backend=default_backend())
        if with_pkcs7padding:
            data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def ctr_decrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv), backend=default_backend())
        data = cipher.decryptor().update(data)
        if with_pkcs7padding:
            data = self.pkcs7_unpadding(data).decode()
        return data

    def ofb_encrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(self.iv), backend=default_backend())
        if with_pkcs7padding:
            data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def ofb_decrypt(self, data, with_pkcs7padding=True):
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(self.iv), backend=default_backend())
        data = cipher.decryptor().update(data)
        if with_pkcs7padding:
            data = self.pkcs7_unpadding(data).decode()
        return data

    def gcm_encrypt(self, data, associated_data, with_pkcs7padding=True):
        aesgcm = AESGCM(self.key)
        if with_pkcs7padding:
            data = self.pkcs7_padding(data)
        return aesgcm.encrypt(self.iv, data, associated_data)

    def gcm_decrypt(self, data, associated_data, with_pkcs7padding=True):
        aesgcm = AESGCM(self.key)
        data = aesgcm.decrypt(self.iv, data, associated_data)
        if with_pkcs7padding:
            data = self.pkcs7_unpadding(data).decode()
        return data

    @staticmethod
    def pkcs7_padding(data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data)
        unpadded_data = data + unpadder.finalize()
        return unpadded_data
