import base64
import binascii
from gmssl import sm2, func

class SM2(object):
    def __init__(self, private_key: str, public_key: str):
        """
        :param private_key: hex string 00B9AB0B828
        :param public_key: hex string B9C9A6E04E9
        """
        # 末尾asn1参数兼容Java
        self.sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key, asn1=True)
    # end __init__

    def encrypt(self, data) -> bytes:
        return self.sm2_crypt.encrypt(data)

    def decrypt(self, data) -> bytes:
        return self.sm2_crypt.decrypt(data)

    def sign_with_sm3(self, data) -> bytes:
        return binascii.a2b_hex(self.sm2_crypt.sign_with_sm3(data))

    def verify_with_sm3(self, data, sign_data) -> bool:
        return self.sm2_crypt.verify_with_sm3(sign_data.hex(), data)

if __name__ == '__main__':
    prikey = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    pubkey = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'

    data = b"test data"
    sm2 = SM2(private_key=prikey, public_key=pubkey)
    enc_data = sm2.encrypt(data)
    print("enc_data:", enc_data.hex())

    dec_data = sm2.decrypt(enc_data)
    print("dec_data:", dec_data)

    sign_data = sm2.sign_with_sm3(data)
    print("sign_data:", sign_data.hex())

    print("verify_result:", sm2.verify_with_sm3(data, sign_data))
