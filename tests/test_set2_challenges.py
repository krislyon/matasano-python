import sys
import os
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
SET2_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../Set2') )
if( SET2_DIR not in sys.path ):
    sys.path.append( SET2_DIR )
from s2c9 import run_challenge_9
from s2c10 import run_challenge_10
from s2c11 import run_challenge_11
from s2c12 import run_challenge_12

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
 