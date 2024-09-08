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
from flask import Flask, jsonify, request

parser = argparse.ArgumentParser( "Set-5, Challenge-34 MitM Proxy", description="Server for matasano challenges" )
args = parser.parse_args()
app = Flask(__name__)

sessions = {}
SERVER_ADDRESS = 'http://127.0.0.1'
SERVER_PORT = '5000'
URL_KEY_EXCHG = "/key-exchange"
URL_MESSAGE = "/secure-message"



def forwardSecureMessage(payload):
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_MESSAGE
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    return (jdict, response.status_code)

def forwardKeyExchange(payload):
    request_url = SERVER_ADDRESS + ':' + SERVER_PORT + URL_KEY_EXCHG
    response = requests.get( request_url, params=payload )
    jdict = response.json()
    return (jdict, response.status_code)

def derive_key():
    # with the parameter injection of 'p', the value of the shared secret is reduced to 0.
    # we need to use the appropriate byte length 192 and use this as the secret.
    zero_val = 0
    shared_secret = zero_val.to_bytes( 192, 'little', signed=False )
    return sha1_utils.sha1_hash( shared_secret )[0:16]

def decrypt_msg( ct:bytes, key:bytes, iv:bytes ):
    padded = block_utils.decrypt_aes_manual_cbc( ct, key, iv )
    pt = block_utils.pkcs7_unpad( padded )
    return pt 


@app.route('/key-exchange', methods=['GET'])
def handleKeyExchange():
    debug = False
    dh_p = bytes.fromhex( request.args.get('p') )
    dh_g = bytes.fromhex( request.args.get('g') )
    dh_A = bytes.fromhex( request.args.get('A') )

    # manipulate_client_message
    client_payload = {"p": dh_p.hex(), "g": dh_g.hex(), "A": dh_p.hex()  }

    (server_payload,response_code) = forwardKeyExchange( client_payload )
    # manipulate_server_message
    server_payload['B'] = dh_p.hex()   

    sessions[ server_payload['session-id'] ] = ( derive_key(), bytes.fromhex(server_payload['session-iv']) )

    return (jsonify(server_payload), response_code )


@app.route('/secure-message', methods=['GET'])
def handleSecureMessage():
    session_id = request.args.get('session-id') 
    session = sessions[session_id]
    session_key = session[0]
    session_iv =  session[1]

    # Decrypt and print client message    
    ct = bytes.fromhex( request.args.get('message-data') )
    client_pt = decrypt_msg(ct, session_key, session_iv ).decode('utf-8')
    print(f'CLI --> SERV ({session_id}):\t{client_pt}')

    client_payload = { 'session-id': session_id, 'message-data': ct.hex() }
    (server_payload, response_code) = forwardSecureMessage( client_payload )

    # Decrypt and print server message
    ct = bytes.fromhex( server_payload['message-data'] )
    server_pt = decrypt_msg(ct, session_key, session_iv ).decode('utf-8')
    print(f'SERV --> CLI ({session_id}):\t{server_pt}')


    return (jsonify(server_payload), response_code )
 

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 5, Challenge 34 (Server) - MITM key-fixing attack on Diffie Hellman')
    print('----------------------------------------------------------------------------')
    print()
    app.run(port=5001 )
