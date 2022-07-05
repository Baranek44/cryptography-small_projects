import os

from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import CBC
from cryptography.hazmat.primitives.hashes import SHA256


def hybrid_encrypt(plain_text, public_key):
    # Pad the plain_text
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plain_text = pkcs7_padder.update(plain_text) + pkcs7_padder.finalize()

    # Generate new random AES-256 key
    key = os.urandom(256 // 8)

    # Generate new random 128-bit IV
    iv = os.urandom(128 // 8)

    # AES CBC cipher
    aes_cbc_cipher = Cipher(AES(key), CBC(iv))

    # Encrypt padded plain_text
    cipher_text = aes_cbc_cipher.encryptor().update(padded_plain_text)

    # Encrypt AES key
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    cipher_key = public_key.encrypt(key, oaep_padding)

    return {'iv': iv, 'cipher_text': cipher_text}, cipher_key


def hybrid_decrypt(cipher_text, cipher_key, private_key):

    # Decrypt AES key
    oaep_padding = asymmetric_padding.OAEP(mgf=asymmetric_padding.MGF1(algorithm=SHA256()), algorithm=SHA256(), label=None)
    recovered_key = private_key.decrypt(cipher_key, oaep_padding)

    # Decrypt padded plaintext
    aes_cbc_cipher = Cipher(AES(recovered_key), CBC(cipher_text['iv']))
    recovered_padded_plain_text = aes_cbc_cipher.decryptor().update(cipher_text['cipher_text'])

    # Remove padding
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    recovered_plain_text = pkcs7_unpadder.update(recovered_padded_plain_text) + pkcs7_unpadder.finalize()

    return recovered_plain_text


if __name__ == '__main__':

    # Recipient's private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Public key to make available to senders
    public_key = private_key.public_key()

    # Plain_text to hybrid encrypt
    plain_text = b'Lorem ipsum dolor sit amet, consectetur adipiscing elit'

    # Hybrid encrypt plaintext
    cipher_text, cipher_key = hybrid_encrypt(plain_text, public_key)

    # Hybrid decrypt plaintext
    recovered_plain_text = hybrid_decrypt(cipher_text, cipher_key, private_key)
    
    assert (recovered_plain_text == plain_text)
