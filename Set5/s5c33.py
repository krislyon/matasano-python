# Matasano Crypto Challenges
# Set 5, Challenge 33 - Implement Diffie-Hellman
#
import random
import math

NIST_P =    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" + \
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" + \
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" + \
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" + \
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" + \
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" + \
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" + \
            "fffffffffffff"

NIST_G =    "2"

def dhs_create_key_exchg_data(p,g,debug=False):
    rand = random.randint(0,0xFFFFFFFF)
    priv = rand % p 
    pub = (g**priv) % p

    if( debug ):
        print(f'\nrand:\t\t\t{hex(rand)}')
        print(f'\na (private):\t\t{hex(priv)}')
        print(f'\nA (public):\t\t{hex(pub)}')    

    return (pub,priv)

def dhs_create_shared_secret(priv,pub,p,debug=False):
    s = (pub**priv) % p
    if( debug ):
        print(f's (private): {s}')
    return s

def dh_create_key_exchg_data(p, g, rand_size=3096, debug=False, debug_set_rand=False):

    # Set or generate random bits.
    if( debug_set_rand ):
        rand = debug_set_rand
    else:
        rand = random.getrandbits( rand_size )

    # Calcuate our public and private key exchange data
    priv = rand % p
    pub = pow(g,priv,p)

    if( debug ):
        print(f'\nrand:\t\t\t{hex(rand)}')
        print(f'\na (private):\t\t{hex(priv)}')
        print(f'\nA (public):\t\t{hex(pub)}')

    return( pub, priv )

def dh_create_shared_secret(priv,pub,p,debug=False):
    s = pow( pub, priv, p )

    if( debug ):
        print(f's (private): {s}')

    return s

def sample_key_exchg_simple(p,g,debug=False):
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

def sample_key_exchg(p, g, debug=False ):
    print(f'p: {p}, g: {g}')
    print()
    print('--Alice---------------------------------------------------------------')
    (alice_pub,alice_priv) = dh_create_key_exchg_data(p,g, debug=debug )
    print(f'Alice creates public key:\t{hex(alice_pub)}')
    print()
    print(f'Alice creates private key:\t{hex(alice_priv)}')

    print()
    print('--Bob-----------------------------------------------------------------')
    (bob_pub,bob_priv) = dh_create_key_exchg_data(p,g, debug=debug)
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
    alice_secret = dh_create_shared_secret(alice_priv, bob_pub, p, debug=debug)
    print(f'Alice creates session material:\t{hex(alice_secret)}')

    print()
    print('--Bob-----------------------------------------------------------------')
    bob_secret = dh_create_shared_secret(bob_priv, alice_pub, p, debug=debug)
    print(f'Bob creates session material:\t{hex(bob_secret)}')

print()
print('Matasano Crypto Challenges')
print('Set 5, Challenge 33 - Implement Diffie Hellman')
print('--------------------------------------------------------------------------')

sample_key_exchg_simple(37,5)

print()
print('**************************************************************************')
print()

p = int( NIST_P, 16 )
g = int( NIST_G, 16 )
sample_key_exchg( p, g )