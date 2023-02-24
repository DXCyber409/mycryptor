from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers, RSAPrivateKey


class Rsa(object):

    def __init__(self, prikey: RSAPrivateKey, pubkey: RSAPublicKey):
        self.prikey = prikey
        self.pubkey = pubkey

    @staticmethod
    def generateKeyPair(key_size=2048, public_exponent=65537):
        private_key = rsa.generate_private_key(
            public_exponent=public_exponent,
            key_size=key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def makePublikey(e, n):
        """
        make public key from given big int e and n
        """
        return RSAPublicNumbers(e, n).public_key()

    @staticmethod
    def formatPubkeyPem(pubkey: str):
        """
        Convert one line pubkey str to standard PEM format.
        :param pubkey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgAtCPZkWiVylrtHVYp2up+o/sXwJisLoLOJhc\nhuF6/Z5lGLRRoWZJCAXU3vFJSF/VQw+UF2UPUo5Y5O12nhnxY6iInyOE4aeRGWrXowGwfokjK6sQ\nc6Mq4iJN5tIiJqxEH7mTSNd7VDwqYFm+0K/OQJ+Vb1emE56+C8r9cVHzAQIDAQAB
        :return:
        """
        HEADER = "-----BEGIN PUBLIC KEY-----\n"
        body = "\n".join([pubkey[i:i+64] for i in range(0, len(pubkey), 64)]) + "\n"
        FOOTER = "-----END PUBLIC KEY-----\n"
        return HEADER + body + FOOTER
    # end formatPubkeyPem

    @staticmethod
    def formatPrikeyPem(prikey: str):
        """
        Convert one line pubkey str to standard PEM format.
        :param prikey: MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgAtCPZkWiVylrtHVYp2up+o/sXwJisLoLOJhc\nhuF6/Z5lGLRRoWZJCAXU3vFJSF/VQw+UF2UPUo5Y5O12nhnxY6iInyOE4aeRGWrXowGwfokjK6sQ\nc6Mq4iJN5tIiJqxEH7mTSNd7VDwqYFm+0K/OQJ+Vb1emE56+C8r9cVHzAQIDAQAB
        :return:
        """
        HEADER = "-----BEGIN PRIVATE KEY-----\n"
        body = "\n".join([prikey[i:i + 64] for i in range(0, len(prikey), 64)]) + "\n"
        FOOTER = "-----END PRIVATE KEY-----\n"
        return HEADER + body + FOOTER
    # end formatPrikeyPem

    @staticmethod
    def loadPubkeyPem(pem: str):
        """
        load public key from standard PEM format.
        """
        public_key = serialization.load_pem_public_key(
            pem.encode(),
            backend=default_backend())
        return public_key

    @staticmethod
    def loadPubkeyDer(der: bytes):
        """
        load public key from standard DER format.
        """
        public_key = serialization.load_der_public_key(
            der,
            backend=default_backend())
        return public_key

    @staticmethod
    def loadPrikeyPem(pem: str, pwd: any):
        """
        load private key from standard PEM format
        """
        private_key = serialization.load_pem_private_key(
            pem.encode(),
            None if not pwd else pwd.encode(),
            backend=default_backend()
        )
        return private_key

    @staticmethod
    def loadPrikeyder(der: bytes, pwd: any):
        """
        load private key from standard DER format
        """
        private_key = serialization.load_der_private_key(
            der,
            None if not pwd else pwd.encode(),
            backend=default_backend()
        )
        return private_key

    def serialization_pubkey_pem(self):
        pubkey_pem = self.pubkey.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pubkey_pem.decode().strip()

    def serialization_prikey_pem(self, passwd=""):
        prikey_pem = self.prikey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passwd.encode()) if passwd else serialization.NoEncryption(),
        )
        return prikey_pem.decode().strip()

    def encrypt_pkcs_padding(self, data: bytes):
        """
        RSA encrypt with public key and legacy pkcs padding.
        """
        max_block_size = int(self.pubkey.key_size / 8) - 11
        ret = b''
        for i in range(0, len(data), max_block_size):
            ret += self.pubkey.encrypt(
                data[i:i + max_block_size],
                padding.PKCS1v15()
            )
        return ret

    def encrypt_oaep_padding(self, data: bytes):
        """
        RSA encrypt with public key and oaep padding
        """
        return self.pubkey.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    def sign_pkcs_padding(self, data: bytes):
        """
        Sign data with private key and legacy pkcs padding.
        """
        signature = self.prikey.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return signature

    def sign_pss_padding(self, data: bytes):
        """
        Sign data with private key and pss padding.
        """
        signature = self.prikey.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_pkcs_padding(self, data: bytes, signature: bytes):
        try:
            self.pubkey.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def verify_pss_padding(self, data: bytes, signature: bytes):
        try:
            self.pubkey.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def decrypt_pkcs_padding(self, data: bytes):
        """
        RSA decrypt with private key and pkcs padding.
        """
        max_block_size = int(self.pubkey.key_size / 8)
        if len(data) <= 0 or not len(data) % max_block_size == 0:
            raise Exception("RSA Decryption block error:" + str(len(data)))

        ret = b''
        for i in range(0, len(data), max_block_size):
            ret += self.prikey.decrypt(
                data[i:i + max_block_size],
                padding.PKCS1v15()
            )
        return ret

    def decrypt_oaep_padding(self, data: bytes):
        """
        RSA decrypt with private key and oaep padding.
        """
        return self.prikey.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
# end Rsa

if __name__ == '__main__':
    prikey, pubkey = Rsa.generateKeyPair()
    e = pubkey.public_numbers().e
    n = pubkey.public_numbers().n
    print("pubkey e:", e)
    print("pubkey n:", n)
    print()

    # Use e and n to reconstruct public key to encrypt, should be same as above public key.
    pubkey = Rsa.makePublikey(e, n)
    rsa = Rsa(prikey=None, pubkey=pubkey)
    print("pubkey pem:")
    print(rsa.serialization_pubkey_pem())
    enc_data = rsa.encrypt_pkcs_padding(b"test data")
    print("enc_data:", enc_data.hex())
    print()

    # use prikey to decrypt
    rsa = Rsa(prikey=prikey, pubkey=None)
    print("prikey pem:")
    print(rsa.serialization_prikey_pem())
    dec_data = rsa.decrypt_pkcs_padding(enc_data)
    print("dec_data:", dec_data)

    # format pubkey str
    pubkey_str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCgAtCPZkWiVylrtHVYp2up+o/sXwJisLoLOJhc\nhuF6/Z5lGLRRoWZJCAXU3vFJSF/VQw+UF2UPUo5Y5O12nhnxY6iInyOE4aeRGWrXowGwfokjK6sQ\nc6Mq4iJN5tIiJqxEH7mTSNd7VDwqYFm+0K/OQJ+Vb1emE56+C8r9cVHzAQIDAQAB".replace("\n", "")
    print("format pubkey pem:")
    print(Rsa.formatPubkeyPem(pubkey_str))

    # format prikey str
    prikey_str = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCnnzM+/SeM5M0GfHnPqtJrCSoW6A7F5L9C6FNxDFblMDuurX9fCpAZkrWfXZDQGP46ZVMiVLVp8uK3AO9AJcYelMFBpR1+nANTfwnjQoJHu4WEPzxXO9RbvLHeUAAr4lbsFw0swrogFXlodm4kfIqTa4xcLadjbY4SZBIw/EeAtXgKPnHAmQwoR5tMOsfrTXIi7vZzDtqZtGGWZ1kaktLkM5V+8perAkdIB3DXetDcVPPBJAQl8FdjPyxv4nK+zMIYzRBqI6Rce8MJHO9FmSNFroyTHsm9hYVMwuzpk5d1mnAO/4AOcLr9SuC8d9P+frivKvSBoZGsJgSiGIKCimudAgMBAAECggEABeNPpJa2CZZNU2Gk9piMlg6k2ny0JCRo7hKpifgdWZLnqTcNGUJXp+ZPKn8jGpZ+KVv18WfZDF4Ms60YXu3UwGT2R3YaQqBXmdqX5NJgCwW5L/3TOZKmXudt2zB+7Z378qk6DprPCw9Twsmv6A0ydBWlQQmoExP04IxcDTm79YmbuTzp6ddMYQeCXFO0ctSddLVVSigo0MlnztwmUvHLSJq1ZYmnszQPOu3JHrueoes+3DnzMHtbMGK/AmNfZmimA414l3NBE7XLSGtRdLwE59MKSxbEEke2nSCsB54YIxS7zEoBod7p7PQxUcOOTMz56PsRsCWzdBK3nBMwAlu52wKBgQDAjK6z2nCE8YENldlSWpbbttDLLEx1GIeSH6tCFtAncb1JIWSbhg5Bv1QglWd9n1d44Xc1ON6/nMNTtX7fF0C1MJAqGsj9sy2KAhhMnyfS8tTG/ovGwH2zFc5nluTxinoesVPCNQrmKw7Em9MfpQAL/HSPkDvvGOpBO0dNgOqKcwKBgQDe26QPN3LoQkAAMxCpnuymDN7/UfDoILp9acrFsKt5Yn9KM4ujnBp9YbKiBd0QhPX1YlhdtDTfjfetGu9ugTtZPgyrLIpe1+H3XIfk3c0e/4ZpQjJ39k+NPPPFw/AWWall/ePkf5Za2lbtZxroTkvIfvkbIomrfyBQs6Rj7e5drwKBgCw+Z0pWcDJsF95aR2SAAlgcKt/0nuDtMQGnmz+FZHEb1oW+UZLW++GpqBgQnIYmHgBdtnmZRr26tLtAYhW7DxhTP10daH+7M0SZ9KFulMUJHVFYXh/eTUPgR9xPtO23hxYUYw2mCIoY7LzKnXmQ/XDDorj2SH9JN1Kj3190tu/3AoGBAJCma8Rcrz7F0ZjPjF8sgln9PLjoTL++jo1cn3rVg1dUcV6OOnLFngQH59R2jdhtFOBjJwwbLb50/W/kbciCJS11su9gB6gr48WUz7fjp4IZRPsJNoza2SPJjkitNyaqp+NFeigUEFmEIqwRIkvqlhHbKIFOV6Fy8FyxXWBnTTKNAoGBAKlEJCxxmEzYSE8kS9KkqLwbAdMVs8E985o1K8VFFVWFAxD9DGE7giJB/nJqqu1CkXgXGOgsQ4Mwf0uXr/CdJDp8jGn1aqi1KNW8SlhNDsAaoybD3iZqKGSoT007tuvflnSzBZkJlD7vNyYP/Yag3T2y18YPASmqaGJ2S12qpIK+"
    print("format prikey pem:")
    print(Rsa.formatPrikeyPem(prikey_str))
