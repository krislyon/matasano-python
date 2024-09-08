# Matasano Crypto Challenges
# Set 5, Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
import argparse
import dh_utils
import sha1_utils
import block_utils
import random
import requests
import json


SERVER_ADDRESS = 'http://127.0.0.1'
SERVER_PORT = '5001'
URL_KEY_EXCHG = "/key-exchange"
URL_MESSAGE = "/secure-message"


def derive_key( shared_secret:bytes ):
    return sha1_utils.sha1_hash( shared_secret )[0:16]

def decrypt_msg( ct:bytes, key:bytes, iv:bytes ):
    padded = block_utils.decrypt_aes_manual_cbc( ct, key, iv )
    pt = block_utils.pkcs7_unpad( padded )
    return pt 

def encrypt_msg( pt:bytes, key:bytes, iv:bytes ):
    padded = block_utils.pkcs7_pad(pt)
    ct = block_utils.encrypt_aes_manual_cbc( padded, key, iv )
    return ct

def request_key_exchange( p:bytes, g:bytes ):
    (client_pub, client_priv) = dh_utils.dh_create_key_exchg_data( p, g )

    payload = {"p": p.hex(), "g": g.hex(), "A": client_pub.hex()  }
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_KEY_EXCHG
    response = requests.get( request_url, params=payload )
    jdict = response.json()

    session_id = bytes.fromhex( jdict['session-id'] )
    B = bytes.fromhex( jdict['B'] )
    iv = bytes.fromhex( jdict['session-iv'] )

    shared_secret = dh_utils.dh_create_shared_secret( client_priv, B, p )
    key = derive_key( shared_secret )

    return ( session_id, key, iv )

def request_secret_message( session_id:bytes, ciphertext:bytes ):
    payload = { "session-id":session_id.hex(), "message-data":ciphertext.hex() }
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_MESSAGE
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    return bytes.fromhex( jdict['message-data'] )

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 5, Challenge 34 (Server) - MITM key-fixing attack on Diffie Hellman')
    print('----------------------------------------------------------------------------')
    print()

    p = bytes.fromhex(dh_utils.NIST_P)
    g = bytes.fromhex(dh_utils.NIST_G)

    ( session_id, key, iv ) = request_key_exchange( p, g )

    print(f'session-id:\t{session_id.hex()}')
    print(f'key:\t\t{key.hex()}')
    print(f'iv:\t\t{iv.hex()}')

    pt = 'I get my kicks on channel six'
    print(f'SEND({session_id.hex()}): {pt}')    
    ct = encrypt_msg( bytes(pt,'utf-8'), key, iv )
    resp_ct = request_secret_message( session_id, ct )
    pt = decrypt_msg( resp_ct, key, iv )
    print(f'RECV({session_id.hex()}): {pt.decode('utf-8')}')

    pt = 'The light it burns my eyes and I feel so dirty'
    print(f'SEND({session_id.hex()}): {pt}')    
    ct = encrypt_msg( bytes(pt,'utf-8'), key, iv )
    resp_ct = request_secret_message( session_id, ct )
    pt = decrypt_msg( resp_ct, key, iv )
    print(f'RECV({session_id.hex()}): {pt.decode('utf-8')}')

    pt = 'Here comes Christ on crutches'
    print(f'SEND({session_id.hex()}): {pt}')    
    ct = encrypt_msg( bytes(pt,'utf-8'), key, iv )
    resp_ct = request_secret_message( session_id, ct )
    pt = decrypt_msg( resp_ct, key, iv )
    print(f'RECV({session_id.hex()}): {pt.decode('utf-8')}')
