# Matasano Crypto Challenges
# Set 5, Challenge 33 - Implement Diffie-Hellman
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from dh_utils import *

def sample_key_exchg_simple(p:int,g:int,debug=False):
    print(f'p: {p}, g: {g}')
    print()
    print('--Alice---------------------------------------------------------------')
    (alice_pub,alice_priv) = dhs_create_key_exchg_data(p,g, debug=debug )
    print(f'Alice creates public key:\t{hex(alice_pub)}')
    print()
    print(f'Alice creates private key:\t{hex(alice_priv)}')

    print()
    print('--Bob-----------------------------------------------------------------')
    (bob_pub,bob_priv) = dhs_create_key_exchg_data(p,g, debug=debug)
    print(f'Bob creates public key:\t\t{hex(bob_pub)}')
    print()    
    print(f'Bob creates private key:\t{hex(bob_priv)}')

    print()
    print('--Alice and Bob exchange public data----------------------------------')
    print(f'Alice sends Bob:\t\t{hex(alice_pub)}')
    print()
    print(f'Bob sends Alice:\t\t{hex(bob_pub)}')

    print()
    print('--Alice---------------------------------------------------------------')
    alice_secret = dhs_create_shared_secret(alice_priv, bob_pub, p, debug=debug)
    print(f'Alice creates session material:\t{hex(alice_secret)}')

    print()
    print('--Bob-----------------------------------------------------------------')
    bob_secret = dhs_create_shared_secret(bob_priv, alice_pub, p, debug=debug)
    print(f'Bob creates session material:\t{hex(bob_secret)}')

def sample_key_exchg(p:bytes, g:bytes, debug=False ):
    print(f'p: {p.hex()}, g: {g.hex()}')
    print()
    print('--Alice---------------------------------------------------------------')
    (alice_pub,alice_priv) = dh_create_key_exchg_data(p,g, debug=debug )
    print(f'Alice creates public key:\t{alice_pub.hex()}')
    print()
    print(f'Alice creates private key:\t{alice_priv.hex()}')

    print()
    print('--Bob-----------------------------------------------------------------')
    (bob_pub,bob_priv) = dh_create_key_exchg_data(p,g, debug=debug)
    print(f'Bob creates public key:\t\t{bob_pub.hex()}')
    print()    
    print(f'Bob creates private key:\t{bob_priv.hex()}')

    print()
    print('--Alice and Bob exchange public data----------------------------------')
    print(f'Alice sends Bob:\t\t{alice_pub.hex()}')
    print()
    print(f'Bob sends Alice:\t\t{bob_pub.hex()}')

    print()
    print('--Alice---------------------------------------------------------------')
    alice_secret = dh_create_shared_secret(alice_priv, bob_pub, p, debug=debug)
    print(f'Alice creates session material:\t{alice_secret.hex()}')

    print()
    print('--Bob-----------------------------------------------------------------')
    bob_secret = dh_create_shared_secret(bob_priv, alice_pub, p, debug=debug)
    print(f'Bob creates session material:\t{bob_secret.hex()}')

print()
print('Matasano Crypto Challenges')
print('Set 5, Challenge 33 - Implement Diffie Hellman')
print('--------------------------------------------------------------------------')

sample_key_exchg_simple(37,5)

print()
print('**************************************************************************')
print()

p = bytes.fromhex( NIST_P )
g = bytes.fromhex( NIST_G )
sample_key_exchg( p, g )