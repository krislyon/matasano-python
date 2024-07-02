# Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.
#
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

import base64
hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
byte_string = bytes.fromhex(hex_string)
base64EncodedStr = base64.b64encode( byte_string )
print(base64EncodedStr)
