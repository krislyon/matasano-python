import sys
sys.path.append('../utils')
from scored_data import *

def test___ScoredData___max():
    sd = ScoredData()
    sd.add( 1, "one" )
    sd.add( 5, "five" )
    sd.add( 2, "two" )
    sd.add( 4, "four" )
    sd.add( 3, "three" )

    result = sd.max()
    assert 5 == result[0], 'Scored data ::max returned the wrong score.'
    assert "five" == result[1], 'Scored data ::max returned the wrong data score.'

def test___ScoredData___re_sort():
    sd = ScoredData()
    sd.add( 1, "one" )
    sd.add( 2, "two" )
    sd.max()  # force a sort
    sd.add( 4, "four" )
    sd.add( 5, "five" )
    sd.add( 3, "three" )

    result = sd.max()
    assert 5 == result[0], 'Scored data ::max returned the wrong score.'
    assert "five" == result[1], 'Scored data ::max returned the wrong data score.'

def test___ScoredData___all():
    sd = ScoredData()
    sd.add( 1, "one" )
    sd.add( 5, "five" )
    sd.add( 2, "two" )
    sd.add( 4, "four" )
    sd.add( 3, "three" )

    result = sd.all()
    
    scores = [5,4,3,2,1]
    values = ["five","four","three","two","one"]
    for i,v in enumerate( result ):
        assert  v[0] == scores[i], f'Scored data ::all returned the wrong data score.'
        assert  v[1] == values[i], f'Scored data ::all returned the wrong data value.'