# Matasano Crypto Challenges
# Set 4, Challenge 29 - Implement a SHA-1 keyed MAC
#
import sys
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from sha1_utils import sha1_keyed_mac, sha1_hash_set_state, sha1_generate_padding, sha1_keyed_mac_validate, sha1_recover_state

def get_random_word(file_path):
    # Open and read the file
    with open(file_path, 'r') as file:
        words = file.readlines()
    
    # Strip any extra whitespace and select a random word
    words = [word.strip() for word in words]
    return random.choice(words)


def forge_keyed_mac( orig_message, orig_keyed_mac, keylen_guess ):
    addition = ";admin=true"
    (a,b,c,d,e) = sha1_recover_state( orig_keyed_mac )

    # Create required glue padding to add between original message and forged addition.
    glue_padding = sha1_generate_padding( len(orig_message) + keylen_guess )   

    # Create our forged addition: glue + forgery
    forged_addition_bytes = bytes(addition,"utf-8")
    forced_length = keylen_guess + len(orig_message) + len(glue_padding) + len(forged_addition_bytes)

    forged_keyed_mac = sha1_hash_set_state( forged_addition_bytes, a, b, c, d, e, forced_length )
    forged_message_ba = bytearray(orig_message)
    forged_message_ba.extend( glue_padding )
    forged_message_ba.extend( forged_addition_bytes )

    return ( bytes(forged_message_ba), forged_keyed_mac )

def run_challenge_29( mac_key=False ):
    print('Matasano Crypto Challenges')
    print('Set 4, Challenge 29 - Break a SHA-1 keyed MAC using length extension')
    print('-------------------------------------------------')

    # Specify the path to the words file
    file_path = '/usr/share/dict/words'
    original_message_bytes = bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon","utf-8")

    if( mac_key ):
        mac_key_bytes = bytes(mac_key,'utf-8')
    else:
        mac_key_bytes = bytes(get_random_word(file_path),"utf-8")

    original_mac = sha1_keyed_mac( original_message_bytes, mac_key_bytes )
    original_validation = sha1_keyed_mac_validate( original_message_bytes, mac_key_bytes, original_mac )
    print(f"Random Key:\t\t\t{mac_key_bytes.decode("utf-8")}")
    print(f"Original Message:\t\t{original_message_bytes.decode("utf-8")}")
    print(f"Original Message MAC:\t\t{original_mac.hex()}" )
    print(f"Validate Original MAC:\t\t{ "***** SUCCESS *****" if original_validation else "Validation Failed." }")

    for keylen in range(0,20):
        (forged_message_bytes,forged_mac) = forge_keyed_mac( original_message_bytes, original_mac, keylen )
        forged_validation = sha1_keyed_mac_validate( forged_message_bytes, mac_key_bytes, forged_mac )

        print(f"\n\n---- Trying MAC Key Length: {keylen} ----")
        print(f"Forged Message:\t\t\t{forged_message_bytes}")
        print(f"Forged Message MAC:\t\t{forged_mac.hex()}" )
        print(f"Validate Forged MAC:\t\t{ "***** SUCCESS *****" if forged_validation else "Validation Failed." }")
        
        if forged_validation:
            return True

    return False 

if __name__ == '__main__':
    run_challenge_29()