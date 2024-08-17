# Matasano Crypto Challenges
# Set 4, Challenge 29 - Implement a SHA-1 keyed MAC
#
import sys
import random
import time
import argparse
from flask import Flask, jsonify, request
sys.path.append('../utils')
from sha1_utils import sha1_hmac

file_path = '/usr/share/dict/words'

parser = argparse.ArgumentParser( "Set-4, Challenge-32 API Server", description="Server for matasano challenges" )
parser.add_argument('-s', '--secret', action='store', help='Force secret to specified word.')
parser.add_argument('-t', '--timeout', action='store', help='Set insecure compare timeout.', default=0.005 )
args = parser.parse_args()
timeout = float(args.timeout)
apiVersion = 2


def get_random_word(file_path):
    print(args)
    if( args.secret != None ):
        return args.secret
    else:
        # Open and read the file
        with open(file_path, 'r') as file:
            words = file.readlines()
        
        # Strip any extra whitespace and select a random word
        words = [word.strip() for word in words]
        return random.choice(words)

def insecure_compare( calcuated, expected, compare_timeout ):
    for i in range( len(expected) ):
        if calcuated[i] != expected[i]:
            return False
        else:
            time.sleep(compare_timeout)
    return True

hmac_key_bytes = bytes(get_random_word(file_path),"utf-8")
app = Flask(__name__)

@app.route('/hmac', methods=['GET'])
def hmac():
    data = request.args.get('data')

    if( data == None ):
        return (jsonify({'result': 500, 'apiVersion': apiVersion }), 500)

    sig = sha1_hmac( bytes(data,'utf-8'), hmac_key_bytes )
    return ( jsonify({'result': 200, 'signature': sig.hex(), 'apiVersion': apiVersion }), 200 )

@app.route('/validate', methods=['GET'])
def validate():
    data = request.args.get('data')
    if( data == None ):
        return (jsonify({'result': 500, 'apiVersion': apiVersion }), 500)

    sig = request.args.get('signature')
    if( data == None ):
        return (jsonify({'result': 500, 'apiVersion': apiVersion }), 500)

    calculated = sha1_hmac( bytes(data,'utf-8'), hmac_key_bytes )
    
    if( insecure_compare( calculated, bytes.fromhex(sig), timeout ) ):
        return (jsonify({'result': 200, 'apiVersion': apiVersion }), 200)
    else:
        return (jsonify({'result': 500, 'apiVersion': apiVersion }), 500)

if __name__ == '__main__':
    print('Matasano Crypto Challenges')
    print('Set 4, Challenge 31 (Server) - Break a HMAC-SHA1 with artificial timing leak')
    print('----------------------------------------------------------------------------')
    print(f'API Verion: {apiVersion}')
    print(f'Comparison Timeout: {timeout}')
    print(f"Secret: '{hmac_key_bytes.decode('utf-8')}'")
    print()
    app.run()


