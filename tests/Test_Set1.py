from unittest import *
import sys
sys.path.append('../Set1')
from s1c1 import run_challenge_1
from s1c2 import run_challenge_2
from s1c3 import run_challenge_3
from s1c4 import run_challenge_4
from s1c5 import run_challenge_5
from s1c6 import run_challenge_6



class Test_Challenge1( TestCase ):
    def runTest(self):
        result = run_challenge_1()
        self.assertEqual( True, result, 'Challenge 1 Failed.')

class Test_Challenge2( TestCase ):
    def runTest(self):
        result = run_challenge_2()
        self.assertEqual( True, result, 'Challenge 2 Failed.')
 
class Test_Challenge3( TestCase ):
    def runTest(self):
        result = run_challenge_3()
        self.assertEqual( True, result, 'Challenge 3 Failed.')

class Test_Challenge4( TestCase ):
    def runTest(self):
        result = run_challenge_4( path_prefix="../Set1/" )
        self.assertEqual( True, result, 'Challenge 4 Failed.')

class Test_Challenge5( TestCase ):
    def runTest(self):
        result = run_challenge_5( path_prefix="../Set1/" )
        self.assertEqual( True, result, 'Challenge 5 Failed.')

class Test_Challenge6( TestCase ):
    def runTest(self):
        result = run_challenge_6( path_prefix="../Set1/" )
        self.assertEqual( True, result, 'Challenge 6 Failed.')

class Test_Challenge7( TestCase ):
    def runTest(self):
        result = run_challenge_7()
        self.assertEqual( True, result, 'Challenge 7 Failed.')

class Test_Challenge8( TestCase ):
    def runTest(self):
        result = run_challenge_8()
        self.assertEqual( True, result, 'Challenge 8 Failed.')


class Suite_Set1( TestSuite ):
    def __init__(self):
        super().__init__()
        self.addTest( Test_Challenge1() )
        self.addTest( Test_Challenge2() )
        self.addTest( Test_Challenge3() )
        self.addTest( Test_Challenge4() )
        self.addTest( Test_Challenge5() )
        self.addTest( Test_Challenge6() )
        # self.addTest( Test_Challenge7() )
        # self.addTest( Test_Challenge8() )



if __name__ == '__main__':
    test_runner = TextTestRunner()
    test_runner.run( Suite_Set1() )