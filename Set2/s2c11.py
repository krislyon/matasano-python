# Matasano Crypto Challenges
# Set 2, Challenge 11 - ECB/CBC detection Oracle
#
import sys
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_pad, encrypt_aes_manual_cbc, encrypt_aes_ecb, detect_ecb

def encrypt_with_random_key( plaintext:bytes ) -> bytes:
    data = bytearray()
    data.extend( random.randbytes( random.randrange(5,10)))
    data.extend( plaintext )
    data.extend( random.randbytes( random.randrange(5,10)))
    data = pkcs7_pad(data)

    key = random.randbytes(16)
    iv = random.randbytes(16)

    if( random.randint(1,2) == 1 ):
        print('Encrypting with CBC.')
        ct = encrypt_aes_manual_cbc( data, key, iv )
    else:
        print('Encrypting with ECB.')
        ct = encrypt_aes_ecb( data, key )

    return ct


print('Matasano Crypto Challenges')
print('Set 2, Challenge 11 - ECB/CBC detection Oracle')
print('----------------------------------------------')

ciphertext = encrypt_with_random_key( bytes('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','utf-8') )
if detect_ecb( ciphertext ):
    print('ECB Detected.')
else:
    print('CBC assumed.')

ciphertext = encrypt_with_random_key( bytes('abababababababababababababababababababababababababababababababababababababababababababababababab','utf-8') )
if detect_ecb( ciphertext ):
    print('ECB Detected.')
else:
    print('CBC assumed.')

ciphertext = encrypt_with_random_key( bytes('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd','utf-8') )
if detect_ecb( ciphertext ):
    print('ECB Detected.')
else:
    print('CBC assumed.')

ciphertext = encrypt_with_random_key( bytes('abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh','utf-8') )
if detect_ecb( ciphertext ):
    print('ECB Detected.')
else:
    print('CBC assumed.')

ciphertext = encrypt_with_random_key( bytes('abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop','utf-8') )
if detect_ecb( ciphertext ):
    print('ECB Detected.')
else:
    print('CBC assumed.')



