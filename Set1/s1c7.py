# Matasano Crypto Challenges
# Set 1, Challenge 7 - AES ECB Mode
#
import base64
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_unpad
from Crypto.Cipher import AES

def load_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

def decrypt_aes_ecb(ciphertext: bytes, key: bytes) -> bytes:
    # Ensure the key is 16 bytes for AES-128
    assert len(key) == 16, "Key must be 16 bytes long for AES-128"

    # Create an AES cipher object with the key and ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted = cipher.decrypt(ciphertext)
    
    # Unpad data
    return pkcs7_unpad( decrypted )

def run_challenge_7():
    print('')
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 7 - AES ECB Mode')
    print('---------------------------------')
    print('')

    ciphertext = load_data('s1c7.dat')
    key = bytes('YELLOW SUBMARINE',"utf-8")
    plaintext = decrypt_aes_ecb(ciphertext,key)
    print('data: ',plaintext.decode("utf-8"))
    return plaintext

if __name__ == '__main__':
    run_challenge_7()