import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from md4_utils import md4_run_test_vector, md4_keyed_mac, md4_keyed_mac_validate, md4_recover_state, md4_generate_padding

def test___md4_test_vector_1():
    md4_run_test_vector( b"", "31d6cfe0d16ae931b73c59d7e0c089c0" )

def test___md4_test_vector_2():
    md4_run_test_vector( b"a","bde52cb31de33e46245e05fbdbd6fb24" )

def test___md4_test_vector_3():
    md4_run_test_vector( b"abc","a448017aaf21d8525fc10ae87aa6729d" )

def test___md4_test_vector_4():
    md4_run_test_vector( b"message digest","d9130a8164549fe818874806e1c7014b" )

def test___md4_test_vector_5():
    md4_run_test_vector( b"abcdefghijklmnopqrstuvwxyz","d79e1c308aa5bbcdeea8ed63df412da9" )

def test___md4_keyed_mac():
    msg = "I'm comin back down tonight, cuz im hypnotized by the light"
    key = "purplediscomachine"
    kmac = md4_keyed_mac( bytes(msg,'utf-8'), bytes(key,'utf-8') )
    assert kmac.hex() == '2529982c055eef071a97dae340e24194'

def test___md4_keyed_mac_validate():
    msg = bytes("I'm comin back down tonight, cuz im hypnotized by the light", 'utf-8')
    key = bytes("purplediscomachine",'utf-8')
    kmac = bytes.fromhex('2529982c055eef071a97dae340e24194')
    assert md4_keyed_mac_validate( msg, key, kmac )

def test___md4_recover_state():
    (a,b,c,d) = md4_recover_state(bytes.fromhex('2529982c055eef071a97dae340e24194') )
    assert a == 0x2c982925
    assert b == 0x07ef5e05
    assert c == 0xe3da971a
    assert d == 0x9441e240

def test__md4_generate_padding():
    padA = md4_generate_padding( 55 )
    padB = md4_generate_padding( 56 )
    padC = md4_generate_padding( 57 )
    assert padA.hex() == '80b801000000000000'
    assert padB.hex() == '80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c001000000000000'
    assert padC.hex() == '800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c801000000000000'
