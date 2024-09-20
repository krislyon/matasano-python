import sys
import os
import pytest
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
SET2_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../Set2') )
if( SET2_DIR not in sys.path ):
    sys.path.append( SET2_DIR )
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from s2c9 import run_challenge_9
from s2c10 import run_challenge_10
from s2c11 import run_challenge_11
from s2c12 import run_challenge_12
from s2c13 import run_challenge_13
from s2c14 import run_challenge_14
from block_utils import pkcs7_unpad
from s2c16 import run_challenge_16

def test___set2___challenge_9():
    expected = ["59454c4c4f57205355424d4152494e4510101010101010101010101010101010", 
                "59454c4c4f57205355424d4152494e45610f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", 
                "59454c4c4f57205355424d4152494e4561610e0e0e0e0e0e0e0e0e0e0e0e0e0e",
                "59454c4c4f57205355424d4152494e456161610d0d0d0d0d0d0d0d0d0d0d0d0d",
                "59454c4c4f57205355424d4152494e45616161610c0c0c0c0c0c0c0c0c0c0c0c",
                "59454c4c4f57205355424d4152494e4561616161610b0b0b0b0b0b0b0b0b0b0b",
                "59454c4c4f57205355424d4152494e456161616161610a0a0a0a0a0a0a0a0a0a",
                "59454c4c4f57205355424d4152494e4561616161616161090909090909090909",
                "59454c4c4f57205355424d4152494e4561616161616161610808080808080808",
                "59454c4c4f57205355424d4152494e4561616161616161616107070707070707",
                "59454c4c4f57205355424d4152494e4561616161616161616161060606060606",
                "59454c4c4f57205355424d4152494e4561616161616161616161610505050505",
                "59454c4c4f57205355424d4152494e4561616161616161616161616104040404",
                "59454c4c4f57205355424d4152494e4561616161616161616161616161030303",
                "59454c4c4f57205355424d4152494e4561616161616161616161616161610202",
                "59454c4c4f57205355424d4152494e4561616161616161616161616161616101"]

    result = run_challenge_9()
    for i in range(16):
        assert expected[i] == result[i]

def test___set2___challenge_10():
    result = run_challenge_10()
    assert result.endswith('Play that funky music \x0A')

def test___set2___challenge_11():
    results = run_challenge_11()
    for result in results:
        assert result[0] == result[1]

def test___set2___challenge_12():
    result = run_challenge_12()
    assert result.endswith('Did you stop? No, I just drove by\x0A')

def test___set2___challenge_13():
    result = run_challenge_13()
    assert result.get("role",False)
    role = result.get("role")
    assert role == 'admin'

def test___set2___challenge_14():
    result = run_challenge_14()
    print( bytes( result, 'utf-8'))
    assert result.endswith('Did you stop? No, I just drove by\x0A')

def test___set2___challenge_15():
    # Correctly padded, should not raise an exception
    pkcs7_unpad( bytes("AAAABBBBCCCCDDD\x01","utf-8"), True )
    pkcs7_unpad( bytes("ICE ICE BABY\x04\x04\x04\x04","utf-8"), True )
    pkcs7_unpad( bytes("AAAABBBBCCCCDD\x02\x02","utf-8"), True )
    pkcs7_unpad( bytes("AAAABBBBCCCCD\x03\x03\x03","utf-8"), True )
    pkcs7_unpad( bytes("AAAABBBBCCCCDDDD\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10","utf-8"), True )

    # Incorrectly padded, should raise an exception
    with pytest.raises(Exception):
        pkcs7_unpad( bytes("ICE ICE BABY\x05\x05\x05\x05","utf-8"), True )
   
    with pytest.raises(Exception):
        pkcs7_unpad( bytes("ICE ICE BABY\x01\x02\x03\x04","utf-8"), True )
    
    with pytest.raises(Exception):
        pkcs7_unpad( bytes("ICE ICE BABY","utf-8"), True )
    

def test___set2___challenge_16():
    result = run_challenge_16()
    assert bytes(";admin=true","utf-8") in result
