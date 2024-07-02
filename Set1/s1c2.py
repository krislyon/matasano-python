# Matasano Crypto Challenges
# Set 1, Challenge 2 - Fixed XOR
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

    expected = '746865206b696420646f6e277420706c6179'
    indata =  '1c0111001f010100061a024b53535009181c'
    xorkey =  '686974207468652062756c6c277320657965'
    result = fixed_xor( indata, xorkey )

    # Display results
    print('Matasano Crypto Challenges')
    print('Set 1, Challenge 2 - Fixed XOR')
    print('------------------------------')

    print('Input Data:  ' + indata )
    print('Key Data:    ' + xorkey )
    print('XOR Result:  ' + str(result.hex()) )
    print('Expected:    ' + expected )

    if result.hex() == expected:
        print("Match")
    else:
        print("No Match")
