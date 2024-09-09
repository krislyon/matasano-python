import random

NIST_P =    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024" + \
            "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd" + \
            "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec" + \
            "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f" + \
            "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361" + \
            "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552" + \
            "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff" + \
            "fffffffffffff"

NIST_G =    "02"

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

def dh_create_key_exchg_data(p:bytes, g:bytes, rand_size:bytes=3096, debug:bool=False, debug_set_rand=False, int_size:int=192 ):

    p_int = int.from_bytes( p, 'little', signed=False )
    g_int = int.from_bytes( g, 'little', signed=False )  

    # Set or generate random bits.
    if( debug_set_rand ):
        rand = debug_set_rand
    else:
        rand = random.getrandbits( rand_size )

    # Calcuate our public and private key exchange data
    priv_int = rand % p_int
    pub_int = pow(g_int,priv_int,p_int)

    pub = pub_int.to_bytes( int_size, 'little', signed=False )
    priv = priv_int.to_bytes( int_size, 'little', signed=False )

    if( debug ):
        print(f'\nrand:\t\t\t{hex(rand)}')
        print(f'\na (private):\t\t{priv.hex()}')
        print(f'\nA (public):\t\t{pub.hex()}')

    return( pub, priv )

def dh_create_shared_secret( priv:bytes, pub:bytes, p:bytes, debug=False, int_size:int=192 ):

    priv_int = int.from_bytes( priv, 'little', signed=False )
    pub_int = int.from_bytes( pub, 'little', signed=False )
    p_int = int.from_bytes( p, 'little', signed=False )

    s_int = pow( pub_int, priv_int, p_int )
    s = s_int.to_bytes( int_size, 'little', signed=False )

    if( debug ):
        print(f's (private): {s_int.hex()}')

    return s
