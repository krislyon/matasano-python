# Matasano Crypto Challenges
# Set 4, Challenge 25 - Break "random access read/write" AES CTR
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
import random
import time
import itertools
import base64
import os
from stream_utils import encrypt_aes_ctr, decrypt_aes_ctr, AesCtrKeystreamGenerator
from xor_utils import buffer_xor
from text_utils import hex_space

aeskey = random.randbytes(16)
nonce = bytes.fromhex("0000000000000000")

def load_base64_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

def edit_aes_ctr( ciphertext:bytes, key:bytes, offset:int, plaintext:bytes, nonce:bytes ) -> bytes:       
    ctr = AesCtrKeystreamGenerator( key, nonce )
    itertools.islice( ctr, offset )  
    ciphertext_patch = buffer_xor( plaintext, ctr )
    end_idx  = offset + len(plaintext)
    ct = bytearray(ciphertext)
    ct[offset:end_idx] = ciphertext_patch
    return bytes(ct)

print('Matasano Crypto Challenges')
print('Set 4, Challenge 25 - Break "random access read/write" AES CTR')
print('--------------------------------------------------------------')

pt = load_base64_data('s4c25.dat')
ct = encrypt_aes_ctr(pt,aeskey,nonce)

### Recover the keysteam
recovery_pt = bytes([0xff for i in range(len(ct))])
new_ct = edit_aes_ctr( ct, aeskey, 0, recovery_pt, nonce )
recovered_keystream = buffer_xor( new_ct, recovery_pt )

#### Recover the data
recovered_plaintext = buffer_xor( ct, recovered_keystream )
print( recovered_plaintext.decode('utf-8') )









