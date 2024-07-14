# Matasano Crypto Challenges
# Set 1, Challenge 1 - Convert hex to base64
#
import base64

print('Matasano Crypto Challenges')
print('Set 1, Challenge 1 - Convert hex to base64')
print('------------------------------------------')

hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
byte_string = bytes.fromhex(hex_string)
base64EncodedStr = base64.b64encode( byte_string ).decode('utf-8')
expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

print('Expected:   ' + expected )
print('Calculated: ' + base64EncodedStr )
if base64EncodedStr == expected:
    print("Match")
else:
    print("No Match")

