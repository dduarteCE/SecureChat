import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class ReplayError(ValueError):
    """Raised when an encrypted message has an unexpected nonce sequence."""


class Actor:
    def __init__(self, direction_id):
        if direction_id not in (0, 1):
            raise ValueError("direction_id must be 0 (connect) or 1 (listen)")

        self.private_key, self.public_key = self.generate_private_public_keys()
        self.session_key = None
        self.aesgcm = None
        self.direction_id = direction_id
        self.send_counter = 0
        self.receive_counter = 0

    @staticmethod
    def generate_private_public_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def produce_and_encrypt_session_key(self, external_pub_key):
        self.session_key = secrets.token_bytes(32)
        encrypted = external_pub_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        self._set_aesgcm()
        return encrypted

    def get_existing_session_key(self, encrypted_key):
        self.session_key = self.private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        self._set_aesgcm()
        return self.session_key

    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @staticmethod
    def load_public_key(pem_text):
        if not isinstance(pem_text, str):
            raise ValueError("public key must be PEM text")

        public_key = serialization.load_pem_public_key(pem_text.encode("ascii"))
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("public key must be an RSA key")
        if public_key.key_size < 2048:
            raise ValueError("RSA public key must be at least 2048 bits")
        return public_key

    def generate_nonce(self):
        if self.send_counter >= 2**64:
            raise RuntimeError("message counter exhausted; establish a new session")
        nonce = (
            self.direction_id.to_bytes(4, "big")
            + self.send_counter.to_bytes(8, "big")
        )
        self.send_counter += 1
        return nonce

    def _set_aesgcm(self):
        if self.session_key is None:
            raise RuntimeError("session key has not been established")
        self.aesgcm = AESGCM(self.session_key)

    def encrypt_message_aesgcm(self, nonce, plain_text):
        if self.aesgcm is None:
            raise RuntimeError("secure session has not been established")
        return self.aesgcm.encrypt(nonce, plain_text, None)

    def decrypt_message_aesgcm(self, nonce, encrypted_message):
        if self.aesgcm is None:
            raise RuntimeError("secure session has not been established")
        if len(nonce) != 12:
            raise ValueError("AES-GCM nonce must be 12 bytes")

        direction_id = int.from_bytes(nonce[:4], "big")
        message_counter = int.from_bytes(nonce[4:], "big")
        expected_direction_id = 1 - self.direction_id
        if direction_id != expected_direction_id:
            raise ReplayError("message nonce has an unexpected sender direction")
        if message_counter != self.receive_counter:
            raise ReplayError("message was replayed or arrived out of order")

        try:
            plaintext = self.aesgcm.decrypt(nonce, encrypted_message, None)
        except InvalidTag:
            # This ordered TCP record consumed the sender's nonce counter even
            # though its contents failed authentication.
            self.receive_counter += 1
            return None
        self.receive_counter += 1
        return plaintext
