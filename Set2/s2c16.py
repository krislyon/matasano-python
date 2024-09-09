# Matasano Crypto Challenges
# Set 2, Challenge 16 - CBC BitFlipping Attacks
#
import sys
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_pad, pkcs7_unpad, encrypt_aes_manual_cbc, decrypt_aes_manual_cbc

aeskey = random.randbytes(16)
iv = random.randbytes(16)

def create_token( attacker_input:str ):
    prefix  = "comment1=cooking%20MCs;userdata="
    postfix = ";comment2=\x20like\x20a\x20pound\x20of\x20bacon"
    pt = pkcs7_pad( bytes(prefix + attacker_input + postfix,"utf-8") )
    ct = encrypt_aes_manual_cbc( pt, aeskey, iv )
    return ct


def is_admin( token:bytes ):
    pt = decrypt_aes_manual_cbc( token, aeskey, iv )
    pt = pkcs7_unpad( pt )
    if bytes(";admin=true","utf-8") in pt:
        return True
    else:
        return False
       

print('Matasano Crypto Challenges')
print('Set 2, Challenge 16 - CBC BitFlipping Attacks')
print('------------------------------------------')


attack_input = "XXXXXXXXXXXXXXXXXXXXX\x3aadmin\x3ctrue"
token = create_token( attack_input )
    
modified_token = bytearray(token)
modified_token[37] = modified_token[37] ^ 0x3a      
modified_token[37] = modified_token[37] ^ 0x3b      
modified_token[43] = modified_token[43] ^ 0x3c      
modified_token[43] = modified_token[43] ^ 0x3d      

print("Admin: " + str(is_admin( bytes(modified_token) )))
