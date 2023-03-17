import base64

from Crypto.Cipher import DES, DES3
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms


class DESedeCryptor(object):
    def __init__(self, key, iv):
        if key is not None and not isinstance(key, bytes):
            key = key.encode()

        if iv is not None and not isinstance(iv, bytes):
            iv = iv.encode()

        self.key = key  # des key need 16 or 24 bytes
        self.iv = iv[0:8] if iv else None  # des iv need 8 bytes

    def ecb_encrypt(self, data):
        des = DES3.new(self.key, mode=DES3.MODE_ECB)
        data = self.pkcs7_padding(data)
        return des.encrypt(data)

    def ecb_decrypt(self, data):
        des = DES3.new(self.key, mode=DES3.MODE_ECB)
        data = des.decrypt(data)
        return self.pkcs7_unpadding(data)

    def cbc_encrypt(self, data):
        des = DES3.new(self.key, mode=DES3.MODE_CBC, iv=self.iv)
        data = self.pkcs7_padding(data)
        return des.encrypt(data)

    def cbc_decrypt(self, data):
        des = DES3.new(self.key, mode=DES3.MODE_CBC, iv=self.iv)
        data = des.decrypt(data)
        return self.pkcs7_unpadding(data)

    @staticmethod
    def pkcs7_padding(data):
        des3_block_size = 64
        padder = padding.PKCS7(des3_block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        des3_block_size = 64
        unpadder = padding.PKCS7(des3_block_size).unpadder()
        data = unpadder.update(padded_data)
        unpadded_data = data + unpadder.finalize()
        return unpadded_data

# main
if __name__ == '__main__':
    key = b"123456789999999987654321"
    iv = b"0102030400000000000000000000000000000000"
    desede = DESedeCryptor(key, iv)

    data = "{'returnCode': 'APP00001', 't': '31', 'serviceTime': '20230317101810', 'returnMsg': '会话已失效', 'enc_flg': '2', 'returnWin': 'N'}".encode()
    print(base64.b64encode(desede.cbc_encrypt(data)).decode())
