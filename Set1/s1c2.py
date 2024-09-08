# Matasano Crypto Challenges
# Set 1, Challenge 2 - Fixed XOR
#
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
#
# 686974207468652062756c6c277320657965
# ... should produce:
#
# 746865206b696420646f6e277420706c6179
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import buffer_xor

expected = '746865206b696420646f6e277420706c6179'
indata =   '1c0111001f010100061a024b53535009181c'
xorkey =   '686974207468652062756c6c277320657965'

def run_challenge_2():
    print('')
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 2 - Fixed XOR')
    print('------------------------------')

    result = buffer_xor( bytes.fromhex(indata), bytes.fromhex(xorkey) )

    print('Input Data:  ' + indata )
    print('Key Data:    ' + xorkey )
    print('XOR Result:  ' + str(result.hex()) )
    print('Expected:    ' + expected )

    return result.hex()

if __name__ == '__main__':
    run_challenge_2()
