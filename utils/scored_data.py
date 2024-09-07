class ScoredData:

    def __init__( self, retain_data=False, score_start=0 ):
        self.retain_data = retain_data
        self.data = []
        self.sorted = False

    def __sort_data( self ):
        self.data = sorted( self.data, key=lambda element: element[0], reverse=True )
        self.sorted = True

    def add( self, score, data ):
        self.data.append( (score, data) )    
        self.sorted = False

    def max( self ):
        if( self.sorted == False ):
            self.__sort_data()
        return self.data[0]

    def all( self ):
        if( self.sorted == False ):
            self.__sort_data()
        return self.data

    