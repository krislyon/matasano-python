import sys
import os
import pytest
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
SET3_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../Set3') )
if( SET3_DIR not in sys.path ):
    sys.path.append( SET3_DIR )
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
 
from s3c17 import run_challenge_17
from s3c18 import run_challenge_18
from s3c19 import run_challenge_19
from s3c20 import run_challenge_20
from s3c21 import run_challenge_21
from s3c22 import run_challenge_22
from s3c23 import run_challenge_23
from s3c24 import run_challenge_24

def test___set3___challenge_17():
    expected = [
        "000000Now that the party is jumping",
        "000001With the bass kicked in and the Vega's are pumpin'",
        "000002Quick to the point, to the point, no faking",
        "000003Cooking MC's like a pound of bacon",
        "000004Burning 'em, if you ain't quick and nimble",
        "000005I go crazy when I hear a cymbal",
        "000006And a high hat with a souped up tempo",
        "000007I'm on a roll, it's time to go solo",
        "000008ollin' in my five point oh",
        "000009ith my rag-top down so my hair can blow"
    ]
    results  = run_challenge_17()
    for res, exp in zip( results, expected ):
        assert res == exp

def test___set3___challenge_18():
    result = run_challenge_18()
    assert result == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

def test___set3___challenge_19():
    run_challenge_19()

def test___set3___challenge_20():
    run_challenge_20()

def test___set3___challenge_21():
    run_challenge_21()

@pytest.mark.slow
def test___set3___challenge_22():
    run_challenge_22(40)

def test___set3___challenge_23():
    (orig,cloned) = run_challenge_23()
    for a,b in zip( orig, cloned ):
        assert a == b

@pytest.mark.slow
def test___set3___challenge_24():
    (expected, result) = run_challenge_24()
    assert result == expected