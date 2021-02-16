import hmac
from base64 import b64encode, b64decode
from hashlib import sha512
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

from nacl.public import PrivateKey, PublicKey, Box

import pritunl_wireguard_client.utils.random as utils


def pritunl_auth(sync_token: str, sync_secret: bytes, method: str, *args):
    '''Authentication helper for pritunl API'''
    timestamp = str(int(time.time()))
    auth_nonce = utils.rand_str(32)
    
    auth_content = [
        sync_token,
        timestamp,
        auth_nonce,
        method.upper()
    ]
    for arg in args:
        auth_content.append(arg)
    auth_str = '&'.join(auth_content)

    sig = hmac.digest(sync_secret, auth_str.encode(), sha512)
    sig = b64encode(sig).decode('ascii')

    headers = {
        'Auth-Token': sync_token,
        'Auth-Timestamp': timestamp,
        'Auth-Nonce': auth_nonce,
        'Auth-Signature': sig,
    }
    return headers


def verify_signature(sync_secret: bytes, signature: str, *data):
    sig = b64decode(signature)
    compare_data = '&'.join(data).encode('ascii')
    digest = hmac.digest(sync_secret, compare_data, sha512)
    return hmac.compare_digest(digest, sig)


def pritunl_sign(private_key, *args):
    '''RSA sign content provided in args'''
    data = '&'.join(args).encode()
    data_hash = sha512(data).digest()
    
    user_privkey = serialization.load_pem_private_key(
        private_key.encode(),
        password=None
    )

    rsa_sig = user_privkey.sign(
        data_hash,
        padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
        ),
        Prehashed(hashes.SHA512())
    )
    sig64 = b64encode(rsa_sig).decode('ascii')
    return sig64


class ClientBox:
    '''NaCl box helper'''
    def __init__(self, server_box_pubkey, is_base64=False):
        if is_base64:
            server_box_pubkey = base64.b64decode(server_box_pubkey)
        assert(len(server_box_pubkey) == 32)

        sender_private_key = PrivateKey.generate()
        sender_public_key = sender_private_key.public_key
        server_public_key = PublicKey(server_box_pubkey)

        self.box = Box(sender_private_key, server_public_key)
        self._public_key = sender_public_key

    def public_key(self):
        return bytes(self._public_key)

    def public_key_base64(self):
        return b64encode(self.public_key()).decode('ascii')

    def encrypt(self, plaintext):
        encrypted = self.box.encrypt(plaintext.encode('utf-8'))
        return encrypted.ciphertext, encrypted.nonce

    def encrypt_base64(self, plaintext):
        ciphertext, nonce = self.encrypt(plaintext)
        ciphertext64 = b64encode(ciphertext).decode('ascii')
        nonce64 = b64encode(nonce).decode('ascii')
        return ciphertext64, nonce64
        
    def decrypt(self, ciphertext, nonce=None):
        return self.box.decrypt(ciphertext, nonce).decode('utf-8')

    def decrypt_base64(self, plaintext64, nonce64=None):
        plaintext = b64decode(plaintext64)
        nonce = b64decode(nonce64) if nonce64 else None
        return self.decrypt(plaintext, nonce)
