# Matasano Crypto Challenges
# Set 4, Challenge 26 - CTR BitFlipping Attack
#
import sys
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from stream_utils import encrypt_aes_ctr
from xor_utils import buffer_xor, detect_diff_start

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

def run_challenge_26():       
    print('Matasano Crypto Challenges')
    print('Set 4, Challenge 26 - CTR BitFlipping Attacks')
    print('---------------------------------------------')

    # determine userdata_idx in ciphertext
    userdata_idx = 0
    ct_a = create_token( "A" )
    ct_b = create_token( "B" )
    userdata_idx = detect_diff_start( ct_a, ct_b )
    print("userdata_idx: " + str(userdata_idx))

    attack_input_1 = "FFFFFFFFFFFFFFF"
    attack_input_2 = bytes("ABCD;admin=true",'utf-8')
    token = create_token( attack_input_1 )

    keystream = buffer_xor(token[userdata_idx:userdata_idx + len(attack_input_1)], bytes(attack_input_1,'utf-8') )
    patch = buffer_xor( keystream, attack_input_2  )

    modified_token = bytearray(token)
    modified_token[userdata_idx:userdata_idx + len(attack_input_1)] = patch

    admin_status = is_admin( bytes(modified_token) )
    print(f"Admin: {admin_status}")
    return admin_status

if __name__ == '__main__':
    run_challenge_26()