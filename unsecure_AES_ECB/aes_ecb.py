import os

# Cipher objects combine an algorithm such as AES with a mode like CBC or CTR
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB
from cryptography.hazmat.primitives import padding

if __name__ == '__main__':
    # plain-text to be kept confidential

    plain_text = b'Cryptography'
    print(f"Plain text: {plain_text}")

    # Create a 256-bit AES key
    key = os.urandom(256 // 8)

    # Create AES ECB cipher
    aes_ecb_cipher = Cipher(AES(key), ECB())

    # Encrypt cipher_text
    cipher_text = aes_ecb_cipher.encryptor().update(plain_text)
    print(f"Cipher text: {cipher_text}")

    # Decrypt from cipher_text to recovered_plaintext
    recovered_plaintext = aes_ecb_cipher.decryptor().update(cipher_text)
    print(f"Recovered plaintext: {recovered_plaintext}")

    # Lining up the plain_text
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_plaintext = pkcs7_padder.update(plain_text) + pkcs7_padder.finalize()
    print(f"Padded plaintext: {padded_plaintext}")

    # Encrypt padded plain_text
    cipher_text = aes_ecb_cipher.encryptor().update(padded_plaintext)
    print(f"Ciphertext: {cipher_text}")

    # Decrypt to padded plain_text
    recovered_plaintext_with_padding = aes_ecb_cipher.decryptor().update(cipher_text)
    print(f"Recovered plaintext with padding: {recovered_plaintext_with_padding}")

    # Remove padding
    pkcs7_unpadder = padding.PKCS7(AES.block_size).unpadder()
    recovered_plaintext = pkcs7_unpadder.update(recovered_plaintext_with_padding) + pkcs7_unpadder.finalize()
    assert (recovered_plaintext == plain_text)

    # Encrypt mandelbrot.ppn

    # Read the image into memory
    with open("firstImageOfABlackHole.ppm", "rb") as image:
        image_file = image.read()
        image_bytes = bytearray(image_file)

    # Keep ppm header
    header_size = 20
    image_header = image_bytes[:header_size]
    image_body = image_bytes[header_size:]

    # Pad the image body
    pkcs7_padder = padding.PKCS7(AES.block_size).padder()
    padded_image_body = pkcs7_padder.update(image_body) + pkcs7_padder.finalize()

    # Encrypt the image body
    encrypted_image_body = aes_ecb_cipher.encryptor().update(padded_image_body)

    # Assemble encrypted image
    encrypted_image = image_header + encrypted_image_body[:len(image_body)]

    # Create and save the full encrypted image in ppm
    with open("firstImageOfABlackHole_aes_ecb_encrypted.ppm", "wb") as image_encrypted:
        image_encrypted.write(encrypted_image)