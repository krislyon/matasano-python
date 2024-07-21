
class MT19937:
    
    def __init__( self, seed:int=19650218 ):
        self.CONST_A = 0x9908b0df
        self.CONST_B = 0x9d2c5680
        self.CONST_C = 0xefc60000
        self.CONST_F = 0x6c078965

        self.state_idx = 624
        self.state = [0] * 624
        self.state[0] = seed
        
        for i in range(1,624):
            self.state[i] = ( self.CONST_F * (self.state[i-1] ^ (self.state[i-1] >> 30)) + i) & 0xffffffff

    def rand32(self):
        if self.state_idx >= 624:
            self.twist()
        
        y = self.state[self.state_idx]
        y ^= (y >> 11)
        y ^= (y << 7) & self.CONST_B
        y ^= (y << 15) & self.CONST_C
        y ^= (y >> 18)

        self.state_idx += 1
        return y & 0xffffffff
    
    def loadstate( self, idx, new_state ):
        self.state_idx = idx
        for j in range(len(new_state)):
            self.state[j] = new_state[j]

    def twist(self):
        for i in range(624):
            y = (self.state[i] & 0x80000000) + (self.state[(i+1) % 624] & 0x7fffffff)
            self.state[i] = self.state[(i + 397) % 624] ^ (y >> 1)
            if y % 2 != 0:
                self.state[i] ^= self.CONST_A
        self.state_idx = 0

def MT19937Generator(seed):
    rng = MT19937(seed)
    idx = 0
    bytestream = bytearray( rng.rand32().to_bytes(4) )

    while True:
        
        if( idx >= 4 ):
            bytestream = bytearray( rng.rand32().to_bytes(4) )

        yield bytestream[idx]
        idx += 1
             

def untemper1(y):
    yt3 = (y & 0xFFE00000)
    yt2 = (y & 0x001FF800) ^ ((y & 0xFFC00000) >> 11 )
    yt1 = (((yt3 | yt2) >> 11) & 0x000007FF) ^ (y & 0x000007FF)
    return yt3 | yt2 | yt1

def untemper2(y):
    for i in range(7):
        y = y ^ ((y << 7) & 0x9d2c5680)
    return y

def untemper3(y):
    for i in range(15):
        y = y ^ ((y << 15) & 0xefc60000)
    return y

def untemper4(y):
    return (y^(y>>18))

def untemper(y):
    return untemper1(untemper2(untemper3(untemper4(y))))



