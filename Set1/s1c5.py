# Matasano Crypto Challenges
# Set 1, Challenge 5 - Implement repeating-key XOR
#
import math
import sys
sys.path.append('../utils')
from xor_utils import buffer_xor, RepeatingKeyGenerator
from text_utils import ascii_range_score

def load_data( filename ):
    with open( filename, 'r') as file:
        # Read all lines into a list
        lines = file.read()
        return lines


print('Matasano Crypto Challenges')
print('Set 1, Challenge 5 - Implement repeating-key XOR')
print('------------------------------------------------')
expected  = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
filedata = load_data('s1c5.dat')
xor_enc_data = bytes( filedata, "utf-8" )        
keybuf = RepeatingKeyGenerator( bytes("ICE","utf-8") )
result = buffer_xor( xor_enc_data, keybuf )

print( str( result.hex() ) )
if( result.hex() == expected ):
    print("Data Matched.")
else:
    print("Match Failed.")

