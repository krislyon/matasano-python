# Matasano Crypto Challenges
# Set 1, Challenge 4 - Detect single-character XOR
#
import sys
import os
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import buffer_xor, create_xor_key
from text_utils import ascii_range_score

hex_data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
xor_enc_data = bytes.fromhex( hex_data )

def load_data( filename ):
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        # Read all lines into a list
        lines = file.readlines()
        return lines

def run_challenge_4():
    print()
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 4 - Detect single-character XOR')
    print('------------------------------------------------')
    filedata = load_data( "s1c4.dat" )
    max_score = 0
    max_key = 0
    max_result = ""

    for line in filedata:    
        xor_enc_data = bytes.fromhex(line)
        for i in range(256):
            key_guess = create_xor_key( i, len(xor_enc_data) )
            result = buffer_xor( xor_enc_data, key_guess )

            score = ascii_range_score( result )
            if( score > max_score ):
                max_score = score
                max_key = i
                max_result = result

    # Display results
    print(  "ascii-score: " + str( max_score ) + ", key: " + str(max_key) + ", '" + max_result.decode('utf-8') + "'" )
    return max_key

if __name__ == '__main__':
    run_challenge_4()
