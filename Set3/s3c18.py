# Matasano Crypto Challenges
# Set 3, Challenge 18 - Implement CTR, the stream cipher mode
#
import sys
import base64
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from xor_utils import buffer_xor
from block_utils import encrypt_aes_ecb
from stream_utils import decrypt_aes_ctr





print('Matasano Crypto Challenges')
print('Set 3, Challenge 18 - Implement CTR, the stream cipher mode')
print('-----------------------------------------------------------')


ciphertext = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")    
result = decrypt_aes_ctr( ciphertext, bytes("YELLOW SUBMARINE","utf-8"), bytes.fromhex("0000000000000000") )
print(result.decode("utf-8"))


