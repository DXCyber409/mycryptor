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

    def encrypt_pkcs_padding(self, data: bytes):
        """
        RSA encrypt with public key and legacy pkcs padding.
        """
        return self.pubkey.encrypt(
            data,
            padding.PKCS1v15()
        )

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
        return self.prikey.decrypt(
            data,
            padding.PKCS1v15()
        )

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

    # Use e and n to reconstruct public key to encrypt, should be same as above public key.
    pubkey = Rsa.makePublikey(e, n)
    rsa = Rsa(prikey=None, pubkey=pubkey)
    enc_data = rsa.encrypt_pkcs_padding(b"test data")
    print("enc_data:", enc_data.hex())

    # use prikey to decrypt
    rsa = Rsa(prikey=prikey, pubkey=None)
    dec_data = rsa.decrypt_pkcs_padding(enc_data)
    print("dec_data:", dec_data)
