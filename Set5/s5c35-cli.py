# Matasano Crypto Challenges
# Set 5, Challenge 34 - Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection
#
import sys
sys.path.append('../utils')
import argparse
import dh_utils
import sha1_utils
import block_utils
import random
import requests
import json


SERVER_ADDRESS = 'http://127.0.0.1'
SERVER_PORT = '5000'

URL_KEY_PARAM = "/set-params"
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


def request_key_exchange_set_params( p:bytes, g:bytes ):
    (client_pub, client_priv) = dh_utils.dh_create_key_exchg_data( p, g )

    payload = {"p": p.hex(), "g": g.hex() }
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_KEY_PARAM
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    session_id_hex = jdict['session-id']

    print(jdict)

    if( jdict['result'] == 'ACK'):
        return ( True, bytes.fromhex(session_id_hex) )
    else:
        return ( False, bytes.fromhex(session_id_hex) )

def request_key_exchange( session_id:bytes, p:bytes, g:bytes ):
    (client_pub, client_priv) = dh_utils.dh_create_key_exchg_data( p, g )

    payload = { "A": client_pub.hex(), 'session-id': session_id.hex() }
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_KEY_EXCHG
    response = requests.get( request_url, params=payload )
    jdict = response.json()

    B = bytes.fromhex( jdict['B'] )
    iv = bytes.fromhex( jdict['session-iv'] )

    shared_secret = dh_utils.dh_create_shared_secret( client_priv, B, p )
    key = derive_key( shared_secret )

    return ( key, iv )

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

    ( result, session_id ) = request_key_exchange_set_params( p, g )
    ( key, iv ) = request_key_exchange( session_id, p, g )

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
