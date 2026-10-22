from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import secrets


class Actor:

    def __init__(self, direction_id):
        self.private_key, self.public_key = self.generate_private_public_keys()
        self.session_key = None
        self.aesgcm = None
        
        self.direction_id = direction_id
        self.send_counter = 0

    def generate_private_public_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()
        
        return private_key, public_key
    
    def produce_and_encrypt_session_key(self, external_pub_key):
        self.session_key = secrets.token_bytes(32)
        self.set_aesgcm()
        encrypted = external_pub_key.encrypt(
            self.session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
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
        self.set_aesgcm()
        return self.session_key
    
    def get_public_key(self):
        return self.public_key

    def export_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

    @staticmethod
    def load_public_key(pem_text):
        return serialization.load_pem_public_key(pem_text.encode("ascii"))

    def generate_nonce(self):
        nonce = (
            self.direction_id.to_bytes(4, "big")
            + self.send_counter.to_bytes(8, "big")
        )
        self.send_counter += 1
        return nonce
    
    def set_aesgcm(self):
        self.aesgcm = AESGCM(self.session_key)
        
    def encrypt_message_aesgcm(self, nonce, plain_text):
        return self.aesgcm.encrypt(nonce, plain_text, None)
    
    def decrypt_message_aesgcm(self, nonce, encrypted_message):
        try:
            return self.aesgcm.decrypt(nonce, encrypted_message, None)
        except InvalidTag:
            print("Message rejected: authentication failed.")
            return None
