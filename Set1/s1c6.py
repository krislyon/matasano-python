# Matasano Crypto Challenges
# Set 1, Challenge 6 - Break repeating-key XOR
#
import base64
import sys
sys.path.append('../utils')

from xor_utils import *

def load_data( filename ):
    with open( filename, 'r') as file:
        data = base64.b64decode( file.read() )
        return data

if __name__ == '__main__':

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
    recovered_key = recovery_xor_key( transposed_blocks )        
    print('Recovered Key: ' + str(recovered_key))

    # Decrypt cipher text with recovered key
    key = RepeatingKeyGenerator( bytes(recovered_key) )
    result = buffer_xor( ciphertext, key )

    print('\nResult:')
    print( result.decode('utf-8'))





