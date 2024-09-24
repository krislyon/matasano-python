# Matasano Crypto Challenges
# Set 4, Challenge 28 - Implement a SHA-1 keyed MAC
#
import sys
import random
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR ) 
from sha1_utils import sha1_keyed_mac


def run_challenge_28( set_mac_key=False ):    
    print('Matasano Crypto Challenges')
    print('Set 4, Challenge 28 - Implement a SHA-1 keyed MAC')
    print('-------------------------------------------------')

    if set_mac_key:
        mac_key = set_mac_key
    else:
        mac_key = random.randbytes(16)

    message = "I've become so numb, I can't feel you there\nBecome so tired, so much more aware\nI'm becoming this, all I want to do\nIs be more like me and be less like you"
    mac = sha1_keyed_mac( bytes(message,'utf-8'), mac_key )

    print( "Message:")
    print( message )
    print( "MAC: " + mac.hex() )

    return mac.hex()

if __name__ == '__main__':
    run_challenge_28()