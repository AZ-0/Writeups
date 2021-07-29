#!/usr/bin/python3
from gmpy2 import popcount

def rev(flag): # step 3
    b = flag >> l - 1
    flag = flag << 1 & 2**l - 1 # step 2
    return flag | b ^ popcount(flag & T) & 1 # step 1

T = 136085
l = 420
flag = 2535320453775772016257932121117911974157173123778528757795027065121941155726429313911545470529920091870489045401698656195217643

for _ in range(421337):
    flag = rev(flag)

print(flag.to_bytes((l+7)//8, 'little'))