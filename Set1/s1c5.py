# Matasano Crypto Challenges
# Set 1, Challenge 5 - Implement repeating-key XOR
#
import os
import sys
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import buffer_xor, RepeatingKeyGenerator

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

