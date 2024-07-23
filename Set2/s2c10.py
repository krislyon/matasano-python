# Matasano Crypto Challenges
# Set 2, Challenge 10 - Implement CBC mode
#
from Crypto.Cipher import AES
import sys
import base64
sys.path.append('../utils')
from block_utils import pkcs7_pad, pkcs7_unpad, split_blocks, decrypt_aes_manual_cbc
from text_utils import hexdump

def load_base64_data( filename: str ) -> bytes:
    with open( filename, 'r') as file:
        data = base64.b64decode( file.read() )
        return data


if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 10 - Implement CBC mode')
    print('------------------------------------------')

    key = bytes("YELLOW SUBMARINE", "utf-8")
    iv = bytes("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00","utf-8")
    ciphertext = load_base64_data('s2c10.dat')

    print('\nCiphertext:')
    for line in hexdump( ciphertext ):
        print(line)

    padded_plaintext = decrypt_aes_manual_cbc( ciphertext, key, iv )

    print('\nPadded-Plaintext:')
    for line in hexdump( padded_plaintext ):
        print(line)

    print('\nResult:')
    result = pkcs7_unpad( padded_plaintext )
    print( result.decode("utf-8") )


    print( base64.b64encode( result ) )
   