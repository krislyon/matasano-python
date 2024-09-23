# Matasano Crypto Challenges
# Set 3, Challenge 21 - Implement the MT19937 Mersenne Twister RNG
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
import mt19937 as mt

def load_test_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        return [ int(line) for line in file.readlines()]
        
def run_challenge_21():
    print('Matasano Crypto Challenges')
    print('Set 3, Challenge 21 - Implement the MT19937 Mersenne Twister RNG')
    print('----------------------------------------------------------------')

    expected_outputs = load_test_data('s3c21.dat')
    rng = mt.MT19937(1131464071)
    for i, expected in enumerate(expected_outputs):
        generated = rng.rand32()
        assert generated == expected, f"Output {i+1}: Expected {expected}, got {generated}"

    print("Test vector validated successfully.")