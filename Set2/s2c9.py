# Matasano Crypto Challenges
# Set 2, Challenge 9 - Implement PKCS#7 Padding
#
print('Matasano Crypto Challenges')
print('Set 2, Challenge 9 - Implement PKCS#7 Padding')
print('------------------------------------------')

def pkcs7_pad( plaintext:bytes, blocksize:int=16 ) -> bytes:
    data = bytearray(plaintext)
    ptlen = len(plaintext) % blocksize
    pad_byte = blocksize - ptlen
    for i in range(pad_byte):
        data.append(pad_byte)
    return bytes(data)


if __name__ == '__main__':
    print( pkcs7_pad( bytes("YELLOW SUBMARINE","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaa","utf-8") ).hex() )

    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaa","utf-8") ).hex() )

    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaa","utf-8") ).hex() )

    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaaaaaa","utf-8") ).hex() )

    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaaaaaaa","utf-8") ).hex() )
    print( pkcs7_pad( bytes("YELLOW SUBMARINEaaaaaaaaaaaaaaaaa","utf-8") ).hex() )