# S1C2.py - Fixed XOR
# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
#
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
#
# 686974207468652062756c6c277320657965
# ... should produce:
#
# 746865206b696420646f6e277420706c6179

def fixed_xor( buf1, buf2 ):
    return bytes([b1 ^ b2 for b1, b2 in zip(bytes.fromhex(buf1), bytes.fromhex(buf2))])

if __name__ == '__main__':
    result = fixed_xor( '1c0111001f010100061a024b53535009181c', '686974207468652062756c6c277320657965' )
    print( result.hex() )