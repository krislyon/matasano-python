# Matasano Crypto Challenges
# Set 3, Challenge 24 - Create the MT19937 stream cipher and break it
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
import random
import time
from stream_utils import encrypt_mt19937_stream, decrypt_mt19937_stream


def bruteforce_mt19937_seed(ct,known_bytes):
    for seed_guess in range(0xFFFF):
        pt = decrypt_mt19937_stream(ct, seed_guess)
        if( pt.find( known_bytes ) != -1 ):
            return seed_guess

def checkPRTTimeSeed(ct):
    for timeseed in range( int(time.time()) - 2000, int(time.time()) + 2000 ):
        ct_check = encrypt_mt19937_stream(bytes('PASSWORD_RESET_TOKEN','utf-8'), timeseed )
        if ct_check == ct:
            return True

    return False

def run_challenge_24():
    print('Matasano Crypto Challenges')
    print('Set 3, Challenge 24 - Create the MT19937 stream cipher and break it')
    print('-------------------------------------------------------------------')


    randseed16 = random.randint(0,0x0000ffff)
    pt = "No more countin' dollars, we'll be countin' stars. Yeah, we'll be countin' stars"
    print('P1 - MT19937 Stream Cipher - Encrypt/Decrypt Verification:')
    print('Plaintext: ' + bytes(pt,'utf-8').hex() )
    ct = encrypt_mt19937_stream( bytes(pt,'utf-8'), randseed16 )
    print('Encrypted: ' + ct.hex() )
    dc = decrypt_mt19937_stream( ct, randseed16 )
    print('Decrypted: ' + dc.hex() )
    print( dc.decode('utf-8'))

    print()
    print('P2 - Recover seed using known plaintext and 16bit key in stream cipher mode.')
    print('Searching...')
    known_text = bytes('AAAAAAAAAAAAAA','utf-8')
    sample_pt = bytearray(random.randbytes( random.randint(0,64) ))
    sample_pt.extend( known_text )
    sample_ct = encrypt_mt19937_stream( sample_pt, randseed16 )

    recovered_seed = bruteforce_mt19937_seed( sample_ct, known_text )

    print('Random Seed: ' + randseed16.to_bytes(2).hex() )
    print('Recovered Seed: ' + recovered_seed.to_bytes(2).hex() )

    print('Plaintext: ' + sample_pt.hex() )
    print('Recovered: ' + decrypt_mt19937_stream( sample_ct, recovered_seed ).hex() )
    print()

    print()
    print('P3 - Generate Password Reset Token')
    prt = encrypt_mt19937_stream( bytes('PASSWORD_RESET_TOKEN','utf-8'), int(time.time()) )
    print('Password Token: ' + prt.hex() )
    print('Check for timeseeded mt19937 based generation: ' + str(checkPRTTimeSeed( prt )))
    return ( randseed16.to_bytes(2).hex(), recovered_seed.to_bytes(2).hex() )

if __name__ == '__main__':
    run_challenge_24()
