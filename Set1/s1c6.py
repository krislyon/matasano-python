# Matasano Crypto Challenges
# Set 1, Challenge 6 - Break repeating-key XOR
#
import base64
import os
import sys
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import calculate_xor_keysize, transpose_data_blocks, recover_xor_key, buffer_xor, RepeatingKeyGenerator

def load_data( filename ):
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

def run_challenge_6():
    print()
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 6 - Break repeating-key XOR')
    print('------------------------------------------------')
    print('')

    # Load Data
    ciphertext = load_data('s1c6.dat')

    # Calculate the keysize used to encyrpt the data
    (keySize,candiates) = calculate_xor_keysize( ciphertext=ciphertext, debug=False )
    print("Keysize Guess: " + str(keySize) )

    # Transpose the blocks and find the key for each block.
    transposed_blocks = transpose_data_blocks( ciphertext, keySize )
    recovered_key = recover_xor_key( transposed_blocks )        
    print('Recovered Key: ' + str(recovered_key))

    # Decrypt cipher text with recovered key
    key = RepeatingKeyGenerator( bytes(recovered_key) )
    result = buffer_xor( ciphertext, key )

    print('\nResult:')
    print( result.decode('utf-8'))

    return recovered_key

if __name__ == "__main__":
    run_challenge_6()




