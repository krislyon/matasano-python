# Matasano Crypto Challenges
# Set 4, Challenge 29 - Implement a SHA-1 keyed MAC
#
import sys
import random
import time
from flask import Flask, jsonify, request
sys.path.append('../utils')
from sha1_utils import sha1_hmac

file_path = '/usr/share/dict/words'

def get_random_word(file_path):
    # Open and read the file
    with open(file_path, 'r') as file:
        words = file.readlines()
    
    # Strip any extra whitespace and select a random word
    words = [word.strip() for word in words]
    return random.choice(words)

def insecure_compare( calcuated, expected, timeout ):
    for i in range( len(expected) ):
        if calcuated[i] != expected[i]:
            return False
        else:
            time.sleep(timeout)
    return True

print('Matasano Crypto Challenges')
print('Set 4, Challenge 31 (Server) - Break a HMAC-SHA1 with artificial timing leak')
print('----------------------------------------------------------------------------')
timeout = 0.05
apiVersion = 1
print(f'Comparison Timeout: {timeout}')
print(f'API Verion: {apiVersion}')
print()

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
    app.run()

