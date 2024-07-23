# Matasano Crypto Challenges
# Set 4, Challenge 26 - CTR BitFlipping Attack
#
import sys
import base64
import random
from typing import Dict,Callable
sys.path.append('../utils')
from stream_utils import encrypt_aes_ctr, decrypt_aes_ctr, AesCtrKeystreamGenerator
from xor_utils import buffer_xor
from text_utils import hexdump

aeskey = random.randbytes(16)
nonce = bytes.fromhex("0000000000000000")


def create_token( attacker_input:str ):
    prefix  = "comment1=cooking%20MCs;userdata="
    postfix = ";comment2=\x20like\x20a\x20pound\x20of\x20bacon"
    pt = bytes(prefix + attacker_input + postfix,"utf-8")
    ct = encrypt_aes_ctr( pt, aeskey, nonce )
    return ct


def is_admin( token:bytes ):
    pt = encrypt_aes_ctr( token, aeskey, nonce )
    print("Token: " + str(pt,'utf-8'))
    if bytes(";admin=true","utf-8") in pt:
        return True
    else:
        return False
       
if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 16 - CBC BitFlipping Attacks')
    print('------------------------------------------')


    userdata_idx = 32
    attack_input_1 = "FFFFFFFFFFFFFFF"
    attack_input_2 = bytes("ABCD;admin=true",'utf-8')
    token = create_token( attack_input_1 )

    keystream = buffer_xor(token[32:47], bytes(attack_input_1,'utf-8') )
    patch = buffer_xor( keystream, attack_input_2  )

    modified_token = bytearray(token)
    modified_token[32:47] = patch

    print("Admin: " + str(is_admin( bytes(modified_token) )))
