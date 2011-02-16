class Enum(object):
    """
    A nice class to handle Enums gracefullly.
    """
    def __init__(self, **pairs):
        #Generate reverse dict
        self._reverse = dict([(b, a) for a, b in pairs.iteritems()])

        #Generate attributes
        for key, value in pairs.iteritems():
            setattr(self, key, value)

    def __getitem__(self, index):
        return self._reverse[index]

    def __iter__(self):
        return self._reverse.itervalues()

    def parse(self, value):
        #If value is enum name convert to value
        if isinstance(value, str):
            if hasattr(self, value):
                return getattr(self, value)
            #If value is a number assume parsing meant converting the value to int
            #if you can think of a more generic way feel free to change
            if value.isdigit():
                value = int(value)

        #If not check if value is a value of the enum
        if value in self._reverse:
            return value

        #Enum doesn't know this value
        raise ValueError("Value '%s' is not in the Enum." % value)

if __name__ == "__main__":
    eColors = Enum(
                Red = 1,
                Blue = 2
              )
    print eColors.Red, eColors.Blue, eColors[1]
