# Matasano Crypto Challenges
# Set 1, Challenge 5 - Implement repeating-key XOR
#
import math
import os
import sys
sys.path.append('../utils')
from xor_utils import buffer_xor, RepeatingKeyGenerator
from text_utils import ascii_range_score

def load_data( filename ):
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        # Read all lines into a list
        lines = file.read()
        return lines

def run_challenge_5():
    print()
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 5 - Implement repeating-key XOR')
    print('------------------------------------------------')

    filedata = load_data( 's1c5.dat')
    xor_enc_data = bytes( filedata, "utf-8" )        
    keybuf = RepeatingKeyGenerator( bytes("ICE","utf-8") )
    result = buffer_xor( xor_enc_data, keybuf )

    print( str( result.hex() ) )
    return result.hex()

