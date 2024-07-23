# Matasano Crypto Challenges
# Set 4, Challenge 27 - Recover the key from CBC with IV = Key
#
import sys
import base64
import random
from typing import Dict,Callable
sys.path.append('../utils')
from block_utils import pkcs7_pad, pkcs7_unpad, encrypt_aes_manual_cbc, decrypt_aes_manual_cbc
from text_utils import hexdump, in_simple_alpha_range
from xor_utils import buffer_xor

aeskey = random.randbytes(16)
iv = aeskey

def sender_encrypt_data( message:str ):
    pt = pkcs7_pad( bytes( message,"utf-8") )
    ct = encrypt_aes_manual_cbc( pt, aeskey, iv )
    return ct


def receiver_decrypt_data( token:bytes ):
    pt = decrypt_aes_manual_cbc( token, aeskey, iv )
    # pt = pkcs7_unpad( pt )
    
    # ASCII Check
    for c in bytearray(pt):
        if( in_simple_alpha_range(c) == False ):
            print("Error, illegal byte detected: ")
            print(pt.hex())
            break
    return pt


print('Matasano Crypto Challenges')
print('Set 4, Challenge 27 - Recover the key from CBC with IV = Key')
print('------------------------------------------------------------')

msg = "How much wood can a woodchuck chuck!"

ct = sender_encrypt_data(msg)
blockcount = len(ct)/16 
print('Blockcount: ' + str(blockcount))

zero_block = bytes.fromhex('00000000000000000000000000000000')
modified_ct = bytearray()
modified_ct.extend( ct[0:16] )
modified_ct.extend( zero_block )
modified_ct.extend( ct[0:16] )

print( modified_ct.hex() )
mod_pt = receiver_decrypt_data( modified_ct )
print("Received Message: " + str(mod_pt) )

recovered_key = buffer_xor( mod_pt[0:16], mod_pt[32:48])  

print('Key:\t\t' + aeskey.hex() )
print('Recovered Key\t' + recovered_key.hex() ) 

print('Recovered Msg: ' + decrypt_aes_manual_cbc( ct, recovered_key, recovered_key ).decode('utf-8') )



