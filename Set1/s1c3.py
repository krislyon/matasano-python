# Matasano Crypto Challenges
# Set 1, Challenge 3 - Single-byte XOR cipher
#
import sys
sys.path.append('../utils')
from xor_utils import buffer_xor, create_xor_key
from text_utils import ascii_range_score

hex_data = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
xor_enc_data = bytes.fromhex( hex_data )


if __name__ == '__main__':
    max_score = 0
    max_key = 0
    max_result = ""
    
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 3 - Single-byte XOR cipher')
    print('-------------------------------------------')

    for i in range(256):
        key_guess = create_xor_key( len(xor_enc_data), i )
        result = buffer_xor( xor_enc_data, key_guess )

        score = ascii_range_score( result )
        if( score > max_score ):
            max_score = score
            max_key = i
            max_result = result

    # Display results.
    print(  "ascii-score: " + str( max_score ) + ", key: " + str(max_key) + ", '" + max_result.decode('utf-8') + "'" )

