# Matasano Crypto Challenges
# Set 4, Challenge 29 - Implement a SHA-1 keyed MAC
#
import sys
import random
sys.path.append('../utils')
from sha1_utils import hmac_sha1, hash_sha1_set_state, generate_sha1_padding, validate_hmac, recover_sha1_state, hash_sha1

def get_random_word(file_path):
    # Open and read the file
    with open(file_path, 'r') as file:
        words = file.readlines()
    
    # Strip any extra whitespace and select a random word
    words = [word.strip() for word in words]
    return random.choice(words)


def forge_hmac( orig_message, orig_hmac, keylen_guess ):

    addition = ";admin=true"
    (a,b,c,d,e) = recover_sha1_state( orig_hmac )

    # Create required glue padding to add between original message and forged addition.
    glue_padding = generate_sha1_padding( len(orig_message) + keylen_guess )   

    # Create our forged addition: glue + forgery
    forged_addition_bytes = bytes(addition,"utf-8")
    forced_length = keylen_guess + len(orig_message) + len(glue_padding) + len(forged_addition_bytes)

    forged_hmac = hash_sha1_set_state( forged_addition_bytes, a, b, c, d, e, forced_length )
    forged_message_ba = bytearray(orig_message)
    forged_message_ba.extend( glue_padding )
    forged_message_ba.extend( forged_addition_bytes )

    return ( bytes(forged_message_ba), forged_hmac )


print('Matasano Crypto Challenges')
print('Set 4, Challenge 29 - Break a SHA-1 keyed MAC using length extension')
print('-------------------------------------------------')

# Specify the path to the words file
file_path = '/usr/share/dict/words'
original_message_bytes = bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon","utf-8")

hmac_key_bytes = bytes(get_random_word(file_path),"utf-8")

original_hmac = hmac_sha1( original_message_bytes, hmac_key_bytes )
original_validation = validate_hmac( original_message_bytes, hmac_key_bytes, original_hmac )
print(f"Random Key:\t\t\t{hmac_key_bytes.decode("utf-8")}")
print(f"Original Message:\t\t{original_message_bytes.decode("utf-8")}")
print(f"Original Message HMAC:\t\t{original_hmac.hex()}" )
print(f"Validate Original HMAC:\t\t{ "***** SUCCESS *****" if original_validation else "Validation Failed." }")

for keylen in range(0,20):

    (forged_message_bytes,forged_hmac) = forge_hmac( original_message_bytes, original_hmac, keylen )
    forged_validation = validate_hmac( forged_message_bytes, hmac_key_bytes, forged_hmac )

    print(f"\n\n---- Trying HMAC Key Length: {keylen} ----")
    print(f"Forged Message:\t\t\t{forged_message_bytes}")
    print(f"Forged Message HMAC:\t\t{forged_hmac.hex()}" )
    print(f"Validate Forged HMAC:\t\t{ "***** SUCCESS *****" if forged_validation else "Validation Failed." }")
    
    if forged_validation:
        break