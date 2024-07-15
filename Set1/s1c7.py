# Matasano Crypto Challenges
# Set 1, Challenge 7 - AES ECB Mode
#
import base64
import binascii

from Crypto.Cipher import AES

def load_base64_data( filename: str ) -> bytes:
    with open( filename, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    # Ensure the key is 16 bytes for AES-128
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"

    # Create an AES cipher object with the key and ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted = cipher.decrypt(ciphertext)
    
    # Return the decrypted data
    return decrypted

if __name__ == '__main__':
    ciphertext = load_data('s1c7.dat')
    key = bytes('YELLOW SUBMARINE',"utf-8")
    plaintext = decrypt_aes_ecb(ciphertext,key)
    print('data: ',plaintext.decode("utf-8", "ignore"))