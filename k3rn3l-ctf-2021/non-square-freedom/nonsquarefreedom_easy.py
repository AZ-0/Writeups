#!/usr/bin/env python3
from Crypto.Util.number import getPrime

# Local imports
with open('flag.txt','rb') as f:
    FLAG = f.read()
    f.close()

# Key gen
P = getPrime(64)
Q = getPrime(256)
R = getPrime(256)
N = P**8 * Q * R
E = 0x10001

def pad_easy(m):
    m <<= 64
    m += (-m % P)
    return m

# Pad FLAG
M = pad_easy(int.from_bytes(FLAG,'big'))
print('M < N    :', M < N)
print('M < P**8 :', M < (P**8))
print('M < Q*R  :', M < (Q*R))

# Encrypt FLAG
C = pow(M, E, N)
print('\nn =', N)
print('e =', E)
print('c =', C)

# Hint
F = P**7 * (P-1) * (Q-1) * (R-1)
D = pow(E, -1, F)
print('\nD(C) =', pow(C,D,N))

#----------------------------------------------------
#                       Output
#----------------------------------------------------
# M < N    : True
# M < P**8 : True
# M < Q*R  : True
n = 68410735253478047532669195609897926895002715632943461448660159313126496660033080937734557748701577020593482441014012783126085444004682764336220752851098517881202476417639649807333810261708210761333918442034275018088771547499619393557995773550772279857842207065696251926349053195423917250334982174308578108707
e = 65537
c = 4776006201999857533937746330553026200220638488579394063956998522022062232921285860886801454955588545654394710104334517021340109545003304904641820637316671869512340501549190724859489875329025743780939742424765825407663239591228764211985406490810832049380427145964590612241379808722737688823830921988891019862
M = 58324527381741086207181449678831242444903897671571344216578285287377618832939516678686212825798172668450906644065483369735063383237979049248667084304630968896854046853486000780081390375682767386163384705607552367796490630893227401487357088304270489873369870382871693215188248166759293149916320915248800905458
