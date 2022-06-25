from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SM4Cryptor(object):

    def __init__(self, key, iv):
        if not isinstance(key, bytes):
            key = key.encode()

        if not isinstance(iv, bytes):
            iv = iv.encode()

        self.key = key
        self.iv = iv

    def cbc_encrypt(self, data):
        cipher = Cipher(algorithms.SM4(self.key), modes.CBC(self.iv), backend=default_backend())
        data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def cbc_decrypt(self, data):
        cipher = Cipher(algorithms.SM4(self.key), modes.CBC(self.iv), backend=default_backend())
        data = cipher.decryptor().update(data)
        return self.pkcs7_unpadding(data)

    def ecb_encrypt(self, data):
        cipher = Cipher(algorithms.SM4(self.key), modes.ECB(), backend=default_backend())
        data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def ecb_decrypt(self, data):
        cipher = Cipher(algorithms.SM4(self.key), modes.ECB(), backend=default_backend())
        data = cipher.decryptor().update(data)
        return self.pkcs7_unpadding(data).decode()

    def ctr_encrypt(self, data):
        cipher = Cipher(algorithms.SM4(self.key), modes.CTR(self.iv), backend=default_backend())
        return cipher.encryptor().update(data)

    def ctr_decrypt(self, data):
        cipher = Cipher(algorithms.SM4(self.key), modes.CTR(self.iv), backend=default_backend())
        return cipher.decryptor().update(data)

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
