# Matasano Crypto Challenges
# Set 1, Challenge 3 - Single-byte XOR cipher
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import buffer_xor, create_xor_key
from text_utils import ascii_range_score
from scored_data import ScoredData

def run_challenge_3():
    print('')
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 3 - Single-byte XOR cipher')
    print('-------------------------------------------')

    hex_data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    xor_enc_data = bytes.fromhex( hex_data )
    sd = ScoredData()

    for i in range(256):
        key_guess = create_xor_key( i, len(xor_enc_data) )
        result = buffer_xor( xor_enc_data, key_guess )
        score = ascii_range_score( result )
        sd.add( score, ( key_guess, result ) )

    result = sd.max()
    maxScore = result[0]
    maxKey = result[1][0]
    maxResult = result[1][1]

    # Display results.
    print(  "ascii-score: " + str( maxScore ) + ", key: " + str(maxKey) + ", '" + maxResult.decode('utf-8') + "'" )

    return maxKey

if __name__ == '__main__':
    run_challenge_3()
