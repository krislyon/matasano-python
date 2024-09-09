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
from flask import Flask, jsonify, request

parser = argparse.ArgumentParser( "Set-5, Challenge-34 Server", description="Server for matasano challenges" )
args = parser.parse_args()
app = Flask(__name__)
sessions = {}

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

@app.route('/set-params', methods=['GET'])
def handleSetParams():
    debug = False
    dh_p = bytes.fromhex( request.args.get('p') )
    dh_g = bytes.fromhex( request.args.get('g') )

    if( dh_p is None ):
        api_error = {'error':50001, 'message':'Missing set parameter: p'}
        return (jsonify(api_error), 500)

    if( dh_g is None ):
        api_error = {'error':50002, 'message':'Missing set parameter: g'}
        return (jsonify(api_error), 500)

    session_id_hex = random.randbytes(16).hex()
    if( debug ):
        print(f'Created session: {session_id_hex()}\n')

    print(f'session-id:\t{session_id_hex}')
    sessions[session_id_hex] = ( session_id_hex, dh_p, dh_g )

    return (jsonify({'result':'ACK','session-id':session_id_hex, 'p': dh_p.hex(), 'g': dh_g.hex() }), 200)

@app.route('/key-exchange', methods=['GET'])
def handleKeyExchange():
    debug = False   
    dh_A = bytes.fromhex( request.args.get('A') )

    if( dh_A is None ):
        api_error = {'error':50003, 'message':'Missing key exhchange parameter: A'}
        return (jsonify(api_error), 500)

    session_id_hex = request.args.get('session-id')
    ( _, dh_p, dh_g ) = sessions[session_id_hex]

    session_iv = random.randbytes(16)
    if( debug ):
        print(f'Created IV: {session_iv.hex()}\n')

    (srv_pub, srv_priv) = dh_utils.dh_create_key_exchg_data( dh_p, dh_g )
    if( debug ):
        print(f'Server created keypair: {srv_pub.hex()}\n\n{srv_priv.hex()}\n')

    shared_secret = dh_utils.dh_create_shared_secret( srv_priv, dh_A , dh_p )
    if( debug ):
        print(f'Server created shared secret: {shared_secret.hex()}\n')

    session_key = derive_key( shared_secret )
    if( debug ):
        print(f'Server created session key: {session_key.hex()}\n')

    print(f'session-id:\t{session_id_hex}')
    print(f'session-key:\t\t{session_key.hex()}')
    print(f'session-iv:\t\t{session_iv.hex()}')

    sessions[session_id_hex] = ( session_id_hex, dh_p, dh_g, session_key, session_iv, srv_pub, srv_priv )
    return (jsonify({'session-id': session_id_hex, 'session-iv': session_iv.hex(), 'B': srv_pub.hex() }), 200)

@app.route('/secure-message', methods=['GET'])
def handleSecureMessage():

    session_id_hex = request.args.get('session-id')
    ct = bytes.fromhex( request.args.get('message-data') )

    if( session_id_hex is None ):
        api_error = {'error':50004, 'message':'Missing session identifier'}
        return (jsonify(api_error), 500)

    if( ct is None ):
        api_error = {'error':50005, 'message':'Missing message data'}
        return (jsonify(api_error), 500)

    session = sessions.get(session_id_hex)
        
    if( session is None ):
        api_error = {'error':50006, 'message':'Session not found.'}
        return (jsonify(api_error), 500)

    session_key = session[3]
    session_iv = session[4]

    pt = decrypt_msg( ct, session_key, session_iv )
    msg_txt = pt.decode('utf-8')
    print('')
    print(f'RECV({session_id_hex}): {msg_txt}')

    pt = bytes(msg_txt[::-1],'utf-8')
    ct = encrypt_msg( pt, session_key, session_iv )
    print(f'SEND({session_id_hex}): {pt}')

    print('')
    return (jsonify({ 'session-id': session_id_hex, 'message-data': ct.hex(), 'session-iv': session_iv.hex() }), 200)
 

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 5, Challenge 34 (Server) - MITM key-fixing attack on Diffie Hellman')
    print('----------------------------------------------------------------------------')
    print()
    app.run()
