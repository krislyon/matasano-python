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
        mode = 0
    else:
        print('Encrypting with ECB.')
        ct = encrypt_aes_ecb( data, key )
        mode = 1

    return (ct, mode)

def run_challenge_11():

    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 11 - ECB/CBC detection Oracle')
    print('----------------------------------------------')

    plaintexts = [b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                b'abababababababababababababababababababababababababababababababababababababababababababababababab',
                b'abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd',
                b'abcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefghabcdefgh',
                b'abcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnopabcdefghijklmnop']

    results = []
    for pt in plaintexts:
        (ct,mode) = encrypt_with_random_key( pt )
        if detect_ecb( ct ):
            detected = 1
            print('ECB Detected.')
        else:
            detected = 0
            print('CBC assumed.')
        results.append( (mode,detected) )
    return results

if __name__ == '__main__':
    run_challenge_11()