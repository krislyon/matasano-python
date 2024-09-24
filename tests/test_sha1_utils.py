import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from sha1_utils import sha1_run_test_vector, sha1_keyed_mac, sha1_keyed_mac_validate, sha1_recover_state, sha1_generate_padding

def test___sha1_test_vector_1():
    sha1_run_test_vector( b"", "da39a3ee5e6b4b0d3255bfef95601890afd80709" )

def test___sha1_test_vector_2():
    sha1_run_test_vector( b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq","84983e441c3bd26ebaae4aa1f95129e5e54670f1" )

def test___sha1_test_vector_3():
    sha1_run_test_vector( b"abc","a9993e364706816aba3e25717850c26c9cd0d89d" )

def test___sha1_keyed_mac():
    msg = "I'm comin back down tonight, cuz im hypnotized by the light"
    key = "purplediscomachine"
    kmac = sha1_keyed_mac( bytes(msg,'utf-8'), bytes(key,'utf-8') )
    assert kmac.hex() == '1f776c49621bc11d264ab7a8ae5311fd398b89be'

def test___sha1_keyed_mac_validate():
    msg = bytes("I'm comin back down tonight, cuz im hypnotized by the light", 'utf-8')
    key = bytes("purplediscomachine",'utf-8')
    kmac = bytes.fromhex('1f776c49621bc11d264ab7a8ae5311fd398b89be')
    assert sha1_keyed_mac_validate( msg, key, kmac )

def test___sha1_recover_state():
    (a,b,c,d,e) = sha1_recover_state(bytes.fromhex('1f776c49 621bc11d 264ab7a8 ae5311fd 398b89be') )
    print(a,b,c,d,e)
    assert a == 0x1f776c49
    assert b == 0x621bc11d
    assert c == 0x264ab7a8
    assert d == 0xae5311fd
    assert e == 0x398b89be

def test__sha1_generate_padding():
    padA = sha1_generate_padding( 55 )
    padB = sha1_generate_padding( 56 )
    padC = sha1_generate_padding( 57 )
    assert padA.hex() == '8000000000000001b8'
    assert padB.hex() == '8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c0'
    assert padC.hex() == '80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c8'
