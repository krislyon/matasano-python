import sys
sys.path.append('../Set1')
from s1c1 import run_challenge_1
from s1c2 import run_challenge_2
from s1c3 import run_challenge_3
from s1c4 import run_challenge_4
from s1c5 import run_challenge_5
from s1c6 import run_challenge_6
from s1c7 import run_challenge_7
from s1c8 import run_challenge_8


def test___set1___challenge_1():
    result = run_challenge_1()
    expected = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert result == expected

def test___set1___challenge_2():
    result = run_challenge_2()
    expected = '746865206b696420646f6e277420706c6179'
    assert result == expected

def test___set1___challenge_3():
    result = run_challenge_3()
    expected = b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
    assert result == expected

def test___set1___challenge_4():
    result = run_challenge_4( path_prefix="../Set1/" )
    expected = 53
    assert result == expected

def test___set1___challenge_5():
    result = run_challenge_5( path_prefix="../Set1/" )
    expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    assert result == expected

def test___set1___challenge_6():
    result = run_challenge_6( path_prefix="../Set1/" )
    expected = b'Terminator X: Bring the noise'
    assert result == expected

def test___set1___challenge_7():
    result = run_challenge_7(path_prefix="../Set1/")
    assert result.endswith(b'Play that funky music \x0A')

def test___set1___challenge_8():
    result = run_challenge_8(path_prefix="../Set1/")
    assert result.endswith("4040deb0ab51b29933f2c123c58386b06fba186a")
