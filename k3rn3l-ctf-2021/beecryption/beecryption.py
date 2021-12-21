#!/usr/bin/env python3
import os

class BeeHive:
    """ Surrounding their beehive, the bees can feast on six flower fields with six flowers each. """
    def __init__(self, key):
        """ Initialise the bee colony. """
        self.fields = self.plant_flowers(key)
        self.nectar = None
        self.collect()
        
    def plant_flowers(self, key):
        """ Plant flowers around the beehive. """
        try:
            if type(key) != bytes:
                key = bytes.fromhex(key)
            return [FlowerField(key[i:i+6]) for i in range(0,36,6)]
        except:
            raise ValueError('Invalid Key!')

    def collect(self):
        """ Collect nectar from the closest flowers. """
        A,B,C,D,E,F = [i.flowers for i in self.fields]
        self.nectar = [A[2] ^ B[4], B[3] ^ C[5], C[4] ^ D[0], D[5] ^ E[1], E[0] ^ F[2], F[1] ^ A[3]]

    def cross_breed(self):
        """ Cross-breed the outermost bordering flowers. """
        def swap_petals(F1: FlowerField, F2: FlowerField, i1, i2):
            """ Swap the petals of two flowers. """
            F1.flowers[i1], F2.flowers[i2] = F2.flowers[i2], F1.flowers[i1]

        A, B, C, D, E, F = self.fields
        swap_petals(A,B,1,5)
        swap_petals(B,C,2,0)
        swap_petals(C,D,3,1)
        swap_petals(D,E,4,2)
        swap_petals(E,F,5,3)
        swap_petals(F,A,0,4)
        
    def pollinate(self):
        """ Have the bees pollinate their flower fields (in order). """
        bees = self.nectar[:]

        for i in range(6):
            bees = [self.fields[i].flowers[k] ^ bees[k] for k in range(6)]
            self.fields[i].flowers = bees

    def stream(self, n=1):
        """ Produce the honey... I mean keystream! """
        buf = []
        # Go through n rounds
        for _ in range(n):
            # Go through 6 sub-rounds
            for field in self.fields:
                field.rotate()
                self.cross_breed()
                self.collect()
                self.pollinate()
            # Collect nectar
            self.collect()
            buf += self.nectar
        return buf

    def encrypt(self, msg):
        """ Beecrypt your message! """
        beeline = self.stream(n = -(-len(msg)//6))
        cip = bytes(beeline[i] ^ msg[i] for i in range(len(msg)))
        return cip

class FlowerField:
    """ A nice field perfectly suited for a total of six flowers. """
    def __init__(self, flowers):
        """ Initialise the flower field. """
        self.flowers = [i for i in flowers]

    def rotate(self):
        """ Crop-rotation is important! """
        self.flowers = [self.flowers[-1]] + self.flowers[:-1]
        
some_text = b'Bees make honey, but they also made the Bee Movie... flag{_REDACTED_}'

flag = BeeHive(os.urandom(36).hex()).encrypt(some_text).hex()

print(flag)
# b8961e85e54e357cf1bb18550e9d397cb6e522e386a837a970c71e02a353eddb9117713e60aa8f764e4525f86898e379fce195437ec59202a5b715334b3295b9f9c9280b2de048183f1a9581860b852167102c1c4ec2897b59e360b5ba37d90b60f23b2ad47c04782a6be3bf
