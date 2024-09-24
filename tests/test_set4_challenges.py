import sys
import os

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
SET4_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../Set4') )
if( SET4_DIR not in sys.path ):
    sys.path.append( SET4_DIR )
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
 
from s4c25 import run_challenge_25
from s4c26 import run_challenge_26
from s4c27 import run_challenge_27
from s4c28 import run_challenge_28
from s4c29 import run_challenge_29
from s4c30 import run_challenge_30

def test___set4___challenge_25():
    result = run_challenge_25()
    print(bytes(result,'utf-8'))
    assert result.endswith('Play that funky music \n')

def test___set4___challenge_26():
    admin_status = run_challenge_26()
    assert admin_status

def test___set4___challenge_27():
    (expected,recovered) = run_challenge_27()
    assert expected == recovered

def test___set4___challenge_28():
    result = run_challenge_28( bytes('ABCDEF1234567890', 'utf-8') )
    assert result == 'f7aa88e9118bb5ef54694c7d1f8720dd7872958e'

def test___set4___challenge_29():
    result = run_challenge_29("abbaisgreat")
    assert result

def test___set4___challenge_30():
    result = run_challenge_30("abbaisgreat")
    assert result
    
#def test___set4___challenge_31():
#def test___set4___challenge_32():
