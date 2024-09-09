import os
import sys
MODULE_DIR = os.path.dirname(os.path.abspath(__file__))
UTILS_DIR  = os.path.abspath( os.path.join( MODULE_DIR, '../utils') )
if( UTILS_DIR not in sys.path ):
    sys.path.append( UTILS_DIR )
from scored_data import ScoredData

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
        assert  v[0] == scores[i], 'Scored data ::all returned the wrong data score.'
        assert  v[1] == values[i], 'Scored data ::all returned the wrong data value.'