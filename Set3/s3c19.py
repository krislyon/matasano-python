# Matasano Crypto Challenges
# Set 3, Challenge 19 - Break fixed-nonce CTR mode using substitutions
#
import sys
import base64
import random
import itertools
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from stream_utils import encrypt_aes_ctr, AesCtrKeystreamGenerator
from text_utils import in_ascii_alpha_range
from freq_utils import digraph_dict


def load_base64_data( filename: str ) -> bytes:
    module_dir = os.path.dirname(os.path.abspath(__file__)) 
    filepath = os.path.join( module_dir, filename )
    with open( filepath, 'r') as file:
        data = [base64.b64decode(line) for line in file.readlines()]
        return data

aeskey = random.randbytes(16)

def single_byte_recovery(texts,count,max_length):
    result = {}

    for target_byte_idx in range(max_length):
        kbGuess = {}
        for byte_guess in range(256):
            for ct in texts:

                if len(ct) > target_byte_idx:
                    key = int(byte_guess).to_bytes().hex()
                    if kbGuess.get(key) is None:
                        kbGuess[key] = {}
                        (kbGuess[key])['asc'] = 0
                        (kbGuess[key])['cnt'] = 0
                        (kbGuess[key])['val'] = byte_guess

                    (kbGuess[key])['cnt'] += 1
                    pt = ct[target_byte_idx] ^ byte_guess
                    if( in_ascii_alpha_range(pt) ):
                        (kbGuess[key])['asc'] += 1
                    
        def stat_comparator(x):
            return int( (x['asc'] * 1000 ) / x['cnt'] )

        sorted_guess_list = sorted( kbGuess.values(), key=lambda stat: stat_comparator(stat), reverse=True )
        #print( str(target_byte_idx) + " : " + str(sorted_guess_list[0:count]) )
        result[target_byte_idx] = sorted_guess_list[0:count]
    return result

def perform_digraph_enhancement( sb_result, texts, max_length ):
    result = {}
    guess_count = len(sb_result[0])

    for target_byte_idx in range(max_length-1):
        max_score = 0
        for i in range(guess_count):
            for j in range(guess_count):
                score = 0
                count = 0
                byte_a_guess = 0
                byte_b_guess = 0

                for ct in ciphertexts:
                    if( len(ct) > target_byte_idx+1 ):
                        byte_a_guess = sb_result[target_byte_idx][i]['val']
                        byte_b_guess = sb_result[target_byte_idx+1][j]['val']
                        ptA = ct[target_byte_idx] ^ byte_a_guess
                        ptB = ct[target_byte_idx+1] ^ byte_b_guess
                        digraph_key = str(ptA.to_bytes(),"utf-8") + str(ptB.to_bytes(),"utf-8")
                        freq = digraph_dict.get(digraph_key)
                        if( freq is not None ):
                            score += freq
                            count += 1

                if score > max_score:
                    max_score = score
                    result[target_byte_idx]   = byte_a_guess
                    result[target_byte_idx+1] = byte_b_guess  


    return [result[k] for k in sorted( result.keys() )]



print('Matasano Crypto Challenges')
print('Set 3, Challenge 19 - Break fixed-nonce CTR mode using substitutions')
print('--------------------------------------------------------------------')

plaintexts = load_base64_data("s3c19.dat")
ciphertexts = [encrypt_aes_ctr( pt, aeskey, bytes.fromhex("0000000000000000")) for pt in plaintexts]

## Determine the max-length ciphertext
max_ct_len = 0
for ct in ciphertexts:
    if len(ct) > max_ct_len:
        max_ct_len = len(ct)
print('max_ct_len: ' + str(max_ct_len))

## Recover the keystream via stat analysis
sb_result = single_byte_recovery( ciphertexts, 5, max_ct_len )
recovered_key_stream = perform_digraph_enhancement( sb_result, ciphertexts, max_ct_len )

## Compare against actual.
key_stream_gen = AesCtrKeystreamGenerator(aeskey,bytes.fromhex("0000000000000000"))
actual_key_stream = list(itertools.islice(key_stream_gen,38))

sum = 0  
for v in [ (1 if a == r else 0) for a,r in zip(actual_key_stream,recovered_key_stream) ]:
    sum += v

print( "Recovered:\t" + str(recovered_key_stream) )
print( "Actual:\t\t" + str(actual_key_stream ) )
print( "Match Rate:\t" + str(sum/(max_ct_len-1)))


