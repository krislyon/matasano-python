import sys
import os

MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
SET5_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../Set5') )
if( SET5_DIR not in sys.path ):
    sys.path.append( SET5_DIR )
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
 
from s5c33 import run_challenge_33
    
def test___set5___challenge_33():
    run_challenge_33()

#def test___set5___challenge_34():
#def test___set5___challenge_35():
