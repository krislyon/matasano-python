from unittest import *
import sys
sys.path.append('../utils')
from scored_data import *

class Test_max( TestCase ):
    def runTest(self):
        sd = ScoredData()
        sd.add( 1, "one" )
        sd.add( 5, "five" )
        sd.add( 2, "two" )
        sd.add( 4, "four" )
        sd.add( 3, "three" )

        result = sd.max()
        self.assertEqual( 5, result[0], 'Scored data ::max returned the wrong score.')
        self.assertEqual( "five", result[1], 'Scored data ::max returned the wrong data score.')

class Test_resort( TestCase ):
    def runTest(self):
        sd = ScoredData()
        sd.add( 1, "one" )
        sd.add( 2, "two" )
        sd.max()  # force a sort
        sd.add( 4, "four" )
        sd.add( 5, "five" )
        sd.add( 3, "three" )

        result = sd.max()
        self.assertEqual( 5, result[0], 'Scored data ::max returned the wrong score.')
        self.assertEqual( "five", result[1], 'Scored data ::max returned the wrong data score.')

class Test_all( TestCase ):
    def runTest(self):
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
            self.assertEqual( v[0], scores[i], f'Scored data ::all returned the wrong data score.')
            self.assertEqual( v[1], values[i], f'Scored data ::all returned the wrong data value.')

class Suite_ScoredData( TestSuite ):
    def __init__(self):
        super().__init__()
        self.addTest( Test_max() )
        self.addTest( Test_all() )
        self.addTest( Test_resort() )


if __name__ == '__main__':
    test_runner = TextTestRunner()
    test_runner.run( Suite_ScoredData() )