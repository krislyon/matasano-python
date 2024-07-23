# Matasano Crypto Challenges
# Set 4, Challenge 28 - Implement a SHA-1 keyed MAC
#
import sys
import random
sys.path.append('../utils')
from sha1_utils import hmac_sha1



print('Matasano Crypto Challenges')
print('Set 4, Challenge 28 - Implement a SHA-1 keyed MAC')
print('-------------------------------------------------')

hmackey = random.randbytes(16)

message = "I've become so numb, I can't feel you there\nBecome so tired, so much more aware\nI'm becoming this, all I want to do\nIs be more like me and be less like you"
hmac = hmac_sha1( bytes(message,'utf-8'), hmackey )

print( "Message:")
print( message )
print( "HMAC: " + hmac.hex() )