# Matasano Crypto Challenges
# Set 3, Challenge 20 - Break fixed-nonce CTR statistically
#
import sys
import base64
import random
import itertools
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from stream_utils import encrypt_aes_ctr, AesCtrKeystreamGenerator
from xor_utils import recover_xor_key, transpose_data_blocks

def load_base64_data( filename: str ) -> bytes:
    with open( filename, 'r') as file:
        data = [base64.b64decode(line) for line in file.readlines()]
        return data

aeskey = random.randbytes(16)


print('Matasano Crypto Challenges')
print('Set 3, Challenge 20 - Break fixed-nonce CTR statistically')
print('---------------------------------------------------------')

plaintexts = load_base64_data("s3c19.dat")
ciphertexts = [encrypt_aes_ctr( pt, aeskey, bytes.fromhex("0000000000000000")) for pt in plaintexts]

## Determine the min-length ciphertext
min_ct_len = 1000
for ct in ciphertexts:
    if len(ct) < min_ct_len:
        min_ct_len = len(ct)
print('min_ct_len: ' + str(min_ct_len))


# Trim ciphertexts to min_ct_len, and append them together.
ciphertext = bytearray()
for ct in ciphertexts:
    ciphertext.extend(ct[0:min_ct_len])

blocks = transpose_data_blocks( ciphertext, min_ct_len )
recovered_key_stream = recover_xor_key( blocks )

## Compare against actual.
key_stream_gen = AesCtrKeystreamGenerator(aeskey,bytes.fromhex("0000000000000000"))
actual_key_stream = list(itertools.islice(key_stream_gen, min_ct_len))

sum = 0  
for v in [ (1 if a == r else 0) for a,r in zip(actual_key_stream,recovered_key_stream) ]:
    sum += v



print( "Recovered:\t" + recovered_key_stream.hex() )
print( "Actual:\t\t" + bytes(bytearray(actual_key_stream )).hex() )
print( "Match Rate:\t" + str(sum/(min_ct_len)))






