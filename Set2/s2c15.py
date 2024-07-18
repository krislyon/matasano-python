import sys
import base64
import random
sys.path.append('../utils')
from block_utils import pkcs7_unpad

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



