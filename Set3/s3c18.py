# Matasano Crypto Challenges
# Set 3, Challenge 17 - The CBC Padding Oracle
#
import sys
import base64
import random
sys.path.append('../utils')
from xor_utils import buffer_xor
from block_utils import encrypt_aes_ecb


def AesCtrGenerator( key, nonce:bytes ):
    assert len(nonce)==8, "Nonce must be 64 bit value."
    ctr_counter = 0
    keybytes = bytes(16)
    key_idx = 16
    pt = bytearray()

    while True:
        key_idx = key_idx+1
        
        if(key_idx > 15):
            pt = bytearray()
            pt.extend(nonce)
            pt.extend(ctr_counter.to_bytes(8,"little"))
            keybytes = encrypt_aes_ecb( pt, key )
            ctr_counter += 1
            key_idx = 0       
        
        yield keybytes[key_idx]



if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 3, Challenge 17 - The CBC Padding Oracle')
    print('--------------------------------------------')

    ciphertext = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")    
    ctr = AesCtrGenerator( bytes("YELLOW SUBMARINE","utf-8" ), bytes.fromhex("0000000000000000") )
    result = buffer_xor( ciphertext, ctr )

    print(result.decode("utf-8"))


