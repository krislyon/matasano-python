# Matasano Crypto Challenges
# Set 2, Challenge 9 - Implement PKCS#7 Padding
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_pad

def run_challenge_9():
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 9 - Implement PKCS#7 Padding')
    print('------------------------------------------')
    results = {}
    for i in range(16):
        postfix = 'a' * i
        results[i] = pkcs7_pad( bytes(f"YELLOW SUBMARINE{postfix}","utf-8") ).hex()
        print( results[i] )

    return results

if __name__ == '__main__':
    run_challenge_9()