# Matasano Crypto Challenges
# Set 1, Challenge 5 - Implement repeating-key XOR
#
import math

def create_repeating_xor_key(key,length):
    keyString = key * math.ceil( length / len(key) )
    return bytes( keyString, "utf-8" )

def fixed_xor( buf1, buf2 ):
    return bytes([b1 ^ b2 for b1, b2 in zip( buf1, buf2)])

def load_data( filename ):
    with open( filename, 'r') as file:
        # Read all lines into a list
        lines = file.read()
        return lines


if __name__ == '__main__':

    filedata = load_data('s1c5.dat')
    xor_enc_data = bytes( filedata, "utf-8" )        
    keybuf = create_repeating_xor_key( "ICE", len(xor_enc_data) )
    result = fixed_xor( xor_enc_data, keybuf )
    
    # Display results
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 5 - Implement repeating-key XOR')
    print('------------------------------------------')
    print( str( result.hex() ) )

    if( result.hex() == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f" ):
        print("Data Matched.")
    else:
        print("Match Failed.")

