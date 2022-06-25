from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class AESCryptor(object):

    def __init__(self, key, iv):
        if not isinstance(key, bytes):
            key = key.encode()

        if not isinstance(iv, bytes):
            iv = iv.encode()

        self.key = key
        self.iv = iv

    def ecb_encrypt(self, data):
        """
        ECB mode should have pkcs padding with default
        """
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def ecb_decrypt(self, data):
        """
        ECB mode should have pkcs padding with default
        """
        cipher = Cipher(algorithms.AES(self.key), modes.ECB(), backend=default_backend())
        data = cipher.decryptor().update(data)
        return self.pkcs7_unpadding(data).decode()

    def cbc_encrypt(self, data):
        """
        CBC mode should have pkcs padding with default
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        data = self.pkcs7_padding(data)
        return cipher.encryptor().update(data)

    def cbc_decrypt(self, data):
        """
        CBC mode should have pkcs padding with default
        """
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=default_backend())
        data = cipher.decryptor().update(data)
        return self.pkcs7_unpadding(data).decode()

    def cfb_encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        return cipher.encryptor().update(data)

    def cfb_decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=default_backend())
        return cipher.decryptor().update(data)

    def ofb_encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(self.iv), backend=default_backend())
        return cipher.encryptor().update(data)

    def ofb_decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.OFB(self.iv), backend=default_backend())
        return cipher.decryptor().update(data)

    def ctr_encrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv), backend=default_backend())
        return cipher.encryptor().update(data)

    def ctr_decrypt(self, data):
        cipher = Cipher(algorithms.AES(self.key), modes.CTR(self.iv), backend=default_backend())
        return cipher.decryptor().update(data)

    def gcm_encrypt(self, data, associated_data):
        """
        This GCM combines enc_data and tag, thus no independent tag value here
        """
        aesgcm = AESGCM(self.key)
        return aesgcm.encrypt(self.iv, data, associated_data)

    def gcm_decrypt(self, data, associated_data):
        """
        This GCM combines enc_data and tag, thus no independent tag value here
        """
        aesgcm = AESGCM(self.key)
        return aesgcm.decrypt(self.iv, data, associated_data)

    def gcm_encrypt_withtag(self, data, associated_data):
        """
        This GCM has standard return value with enc_data and tag verify
        """
        encryptor = Cipher(algorithms.AES(self.key), modes.GCM(self.iv), backend=default_backend()).encryptor()
        encryptor.authenticate_additional_data(associated_data)
        ciphertext = encryptor.update(data)
        encryptor.finalize()
        return ciphertext, encryptor.tag

    def gcm_decrypt_withtag(self, data, associated_data, tag):
        """
        This GCM has standard return value with enc_data and tag verify
        """
        decryptor = Cipher(algorithms.AES(self.key), modes.GCM(self.iv), backend=default_backend()).decryptor()
        decryptor.authenticate_additional_data(associated_data)
        plaintext = decryptor.update(data)
        decryptor.finalize_with_tag(tag)
        return plaintext

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
