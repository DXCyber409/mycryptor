import base64

from Crypto.Cipher import DES
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms


class DesCryptor(object):
    def __init__(self, key, iv):
        if key is not None and not isinstance(key, bytes):
            key = key.encode()

        if iv is not None and not isinstance(iv, bytes):
            iv = iv.encode()

        # des key and iv only 8bytes works
        self.key = key[0:8] if key else None
        self.iv = iv[0:8] if iv else None

    def ecb_encrypt(self, data):
        des = DES.new(self.key, mode=DES.MODE_ECB)
        data = self.pkcs7_padding(data)
        return des.encrypt(data)

    def ecb_decrypt(self, data):
        des = DES.new(self.key, mode=DES.MODE_ECB)
        data = des.decrypt(data)
        return self.pkcs7_unpadding(data)

    def cbc_encrypt(self, data):
        des = DES.new(self.key, mode=DES.MODE_CBC, iv=self.iv)
        data = self.pkcs7_padding(data)
        return des.encrypt(data)

    def cbc_decrypt(self, data):
        des = DES.new(self.key, mode=DES.MODE_CBC, iv=self.iv)
        data = des.decrypt(data)
        return self.pkcs7_unpadding(data)

    @staticmethod
    def pkcs7_padding(data):
        des_block_size = 64
        padder = padding.PKCS7(des_block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    @staticmethod
    def pkcs7_unpadding(padded_data):
        des_block_size = 64
        unpadder = padding.PKCS7(des_block_size).unpadder()
        data = unpadder.update(padded_data)
        unpadded_data = data + unpadder.finalize()
        return unpadded_data

# main
if __name__ == '__main__':
    key = b"00000000000000000000000000000000"
    iv = b"0102030400000000000000000000000000000000"
    des = DesCryptor(key, iv)

    data = "{'returnCode': 'APP00001', 't': '31', 'serviceTime': '20230317101810', 'returnMsg': '会话已失效', 'enc_flg': '2', 'returnWin': 'N'}".encode()
    print(base64.b64encode(des.cbc_encrypt(data)).decode())
