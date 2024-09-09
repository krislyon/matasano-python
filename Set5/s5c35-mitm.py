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
import sha1_utils
import block_utils
import requests
from flask import Flask, jsonify, request

parser = argparse.ArgumentParser( "Set-5, Challenge-34 MitM Proxy", description="Server for matasano challenges" )
parser.add_argument('-m', '--mitm', action='store', help='Set mitm mode, 0:no attack, 1: g=1 (default), 2: g=p, 3: g=(p-1)', default=1)
args = parser.parse_args()
app = Flask(__name__)

sessions = {}
SERVER_ADDRESS = 'http://127.0.0.1'
SERVER_PORT = '5000'
URL_SET_PARAMS = "/set-params"
URL_KEY_EXCHG  = "/key-exchange"
URL_MESSAGE    = "/secure-message"

# MITM_MODE
#
# 0 - Don't Attack
# 1 - Attack G = 1
# 2 - Attack G = p
# 3 - Attack G = (p-1)
#

print(args)
MITM_MODE = int(args.mitm)

def forwardSetParams(payload):
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_SET_PARAMS
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    return (jdict, response.status_code)

def forwardKeyExchange(payload):
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_KEY_EXCHG
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    return (jdict, response.status_code)

def forwardSecureMessage(payload):
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_MESSAGE
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    return (jdict, response.status_code)

def derive_key():
    if( MITM_MODE == 0 or MITM_MODE == 2):
        s_val = 0
        shared_secret = s_val.to_bytes( 192, 'little', signed=False )
    elif( MITM_MODE == 1 ):
        s_val = 1
        shared_secret = s_val.to_bytes( 192, 'little', signed=False )
    elif( MITM_MODE == 3 ):
        s_val = 1
        shared_secret = s_val.to_bytes( 192, 'little', signed=False )
        # Note we might adjust this later to (p-1)

    return sha1_utils.sha1_hash( shared_secret )[0:16]

def decrypt_msg( ct:bytes, key:bytes, iv:bytes ):
    padded = block_utils.decrypt_aes_manual_cbc( ct, key, iv )
    pt = block_utils.pkcs7_unpad( padded, validate=True )
    return pt 

@app.route('/set-params', methods=['GET'])
def handleSetParams():
    dh_p = bytes.fromhex( request.args.get('p') )
    dh_g = bytes.fromhex( request.args.get('g') )

    # manipulate_client_message
    if( MITM_MODE == 0 ):
        client_payload = {"p": dh_p.hex(), "g": dh_g.hex()  }
    elif( MITM_MODE == 1 ):
        g_int = 1
        client_payload = {"p": dh_p.hex(), "g": g_int.to_bytes(192,'little',signed=False).hex() }
    elif( MITM_MODE == 2 ):
        client_payload = {"p": dh_p.hex(), "g": dh_p.hex() }
    elif( MITM_MODE == 3 ):
        int_p_minus_one = ( int.from_bytes( dh_p, byteorder='little', signed=False ) - 1 )
        client_payload = {"p": dh_p.hex(), "g": int_p_minus_one.to_bytes(192,'little',signed=False).hex() }

    (server_payload,response_code) = forwardSetParams( client_payload )

    # manipulate_server_message
    session_id_hex = server_payload['session-id']
    sessions[ session_id_hex ] = ( session_id_hex, dh_p, dh_g )

    return (jsonify(server_payload), response_code )

@app.route('/key-exchange', methods=['GET'])
def handleKeyExchange():
    session_id_hex = request.args.get('session-id')
    dh_p = sessions[session_id_hex][1]    
    client_pub = bytes.fromhex( request.args.get('A') )

    # manipulate_client_message
    client_payload = {"session-id": session_id_hex, "A": client_pub.hex()  }

    (server_payload,response_code) = forwardKeyExchange( client_payload )

    # pull data from server_message to session
    session_iv = bytes.fromhex(server_payload['session-iv'])
    serv_pub = bytes.fromhex(server_payload['B'])

    # manipulate_server_message
    sessions[session_id_hex] = ( session_id_hex, derive_key(), session_iv, client_pub, serv_pub, dh_p )

    return (jsonify(server_payload), response_code )

@app.route('/secure-message', methods=['GET'])
def handleSecureMessage():
    session_id_hex = request.args.get('session-id') 
    session = sessions[session_id_hex]
    session_key = session[1]
    session_iv =  session[2]
    dh_p = session[5]

    # Decrypt and print client message    
    ct = bytes.fromhex( request.args.get('message-data') )

    if( MITM_MODE == 3):
        try:    
            client_pt = decrypt_msg(ct, session_key, session_iv )

        except Exception:
            int_p_minus_one = ( int.from_bytes( dh_p, 'little', signed=False ) - 1 )
            shared_secret = int_p_minus_one.to_bytes( 192, 'little', signed=False )
            session_key = sha1_utils.sha1_hash( shared_secret )[0:16]

    try:    
        client_pt = decrypt_msg(ct, session_key, session_iv )
        try:
            client_pt = client_pt.decode('utf-8')
            print(f'CLI --> SERV ({session_id_hex}):\t{client_pt}')
        except Exception:
            print(f'CLI --> SERV ({session_id_hex}):\t ***** UTF-8 Decode Failed *****')
    except Exception:
        print(f'CLI --> SERV ({session_id_hex}):\t ***** Decrypt Failed, Incorrect PKCS7 Padding *****')

    client_payload = { 'session-id': session_id_hex, 'message-data': ct.hex() }
    (server_payload, response_code) = forwardSecureMessage( client_payload )

    # Decrypt and print server message
    ct = bytes.fromhex( server_payload['message-data'] )

    try:
        server_pt = decrypt_msg(ct, session_key, session_iv )
        try:
            server_pt = server_pt.decode('utf-8')
            print(f'SERV --> CLI ({session_id_hex}):\t{server_pt}')
        except Exception:
            print(f'SERV --> CLI ({session_id_hex}):\t ***** UTF-8 Decode Failed *****')  
    except Exception:
        print(f'SERV --> CLI ({session_id_hex}):\t ***** Decrypt Failed, Incorrect PKCS7 Padding *****')

    return (jsonify(server_payload), response_code )
 

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 5, Challenge 34 (Server) - MITM key-fixing attack on Diffie Hellman')
    print('----------------------------------------------------------------------------')
    if( MITM_MODE == 0 ):
        print('MITM Server: Not executing attack.')
    elif( MITM_MODE == 1 ):
        print('MITM Server: Executing g=1 attack.')
    elif( MITM_MODE == 2 ):
        print('MITM Server: Executing g=p attack.')
    elif( MITM_MODE == 3 ):
        print('MITM Server: Executing g=(p-1) attack.')
    print()
    app.run(port=5001 )
