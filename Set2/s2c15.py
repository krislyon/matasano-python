# Matasano Crypto Challenges
# Set 2, Challenge 15 - PKCS#7 Padding Validation
#
import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from block_utils import pkcs7_unpad

def run_challenge_15():
    print('Matasano Crypto Challenges')
    print('Set 2, Challenge 15 - PKCS#7 Padding Validation')
    print('-----------------------------------------------')


    try:
        print( pkcs7_unpad( bytes("AAAABBBBCCCCDDD\x01","utf-8"), True ))
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("ICE ICE BABY","utf-8"), True )) 
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("ICE ICE BABY\x04\x04\x04\x04","utf-8"), True )) 
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("ICE ICE BABY\x05\x05\x05\x05","utf-8"), True ))
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("ICE ICE BABY\x01\x02\x03\x04","utf-8"), True ))
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("AAAABBBBCCCCDD\x02\x02","utf-8"), True ))
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("AAAABBBBCCCCD\x03\x03\x03","utf-8"), True ))
    except Exception as e:
        print(e)

    try:
        print( pkcs7_unpad( bytes("AAAABBBBCCCCDDDD\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10","utf-8"), True ))
    except Exception as e:
        print(e)

if __name__ == '__main__':
    run_challenge_15()
