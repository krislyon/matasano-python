# Matasano Crypto Challenges
# Set 2, Challenge 10 - Implement CBC mode
#
import sys
import base64
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_unpad, decrypt_aes_manual_cbc
from text_utils import hexdump

def load_base64_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        data = base64.b64decode( file.read() )
        return data


print('Matasano Crypto Challenges')
print('Set 2, Challenge 10 - Implement CBC mode')
print('------------------------------------------')

key = bytes("YELLOW SUBMARINE", "utf-8")
iv = bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","utf-8")
ciphertext = load_base64_data('s2c10.dat')

print('\nCiphertext:')
for line in hexdump( ciphertext ):
    print(line)

padded_plaintext = decrypt_aes_manual_cbc( ciphertext, key, iv )

print('\nPadded-Plaintext:')
for line in hexdump( padded_plaintext ):
    print(line)

print('\nResult:')
result = pkcs7_unpad( padded_plaintext )
print( result.decode("utf-8") )


print( base64.b64encode( result ) )
   