# Matasano Crypto Challenges
# Set 2, Challenge 13 - ECB Cut and Paste
#
import sys
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from typing import Dict
from block_utils import pkcs7_pad, pkcs7_unpad, encrypt_aes_ecb, decrypt_aes_ecb

aeskey = random.randbytes(16)

def kv_string_parse( kvstring:str ) -> Dict[str,str]:
    kv_dict = {}
    pairs = kvstring.split('&')
    for pair in pairs:
        kv = pair.split('=')
        kv_dict[kv[0]] = kv[1]
    return kv_dict

def kv_string_encode( kv_dict:Dict[str,str] ) -> str:
    result = ""
    for key in kv_dict.keys():
        result += key + "=" + kv_dict[key]
        result += '&'
    return result[0:-1]


def profile_for( email:str ) -> str:
    assert email.find('&') == -1, "Email contains illegal characters. ($)"
    assert email.find('=') == -1, "Email contains illegal characters. (=)"
    user_profile = {}
    user_profile['email'] = email
    user_profile['uid'] = str(10)
    user_profile['role'] = 'user'
    return kv_string_encode( user_profile )

def oracle( email:str ):
    profile_string = profile_for(email)
    ct = encrypt_aes_ecb( pkcs7_pad(bytes(profile_string,'utf-8')), aeskey )
    return ct

def run_challenge_13():
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 13 - ECB Cut and Paste')
    print('------------------------------------------')

    # Arts and Crafts time: Cut and paste the blocks...
    # Part1: email=xxxxxxxxxx xxx&uid=10&role= user                  // keep block 1 & 2
    p1ciphertext = oracle('hakr@home.com')
    block1 = p1ciphertext[0:16]
    block2 = p1ciphertext[16:32]

    # Part2: email=xxxxxxxxxx adminPPPPPPPPPPP &uid=10&role=use r    // keep block 2.
    p2ciphertext = oracle( 'aaaaaaaaaaadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b' )
    block3 = p2ciphertext[16:32]

    crafted_ciphertext = bytearray()
    crafted_ciphertext.extend( block1 )
    crafted_ciphertext.extend( block2 )
    crafted_ciphertext.extend( block3 )

    ######
    pt = pkcs7_unpad( decrypt_aes_ecb( crafted_ciphertext, aeskey ))
    result_dict = kv_string_parse(pt.decode('utf-8'))
    print( result_dict )
    return result_dict

if __name__ == '__main__':
    run_challenge_13()