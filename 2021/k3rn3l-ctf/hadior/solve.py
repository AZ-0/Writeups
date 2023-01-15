from base64 import urlsafe_b64encode, urlsafe_b64decode
from hadior import HADIOR
import json

def bake():
    data = json.dumps({'user' : 'whatever', 'admin' : True}).encode()
    db64 = urlsafe_b64encode(data)[:(len(data)*8+5)//6]
    tb64 = urlsafe_b64encode(int(0).to_bytes(4, 'big'))[:-2]
    cb64 = db64 + b'.' + tb64

    print(f'{db64 = }')
    print(f'{tb64 = }')
    print(f'{cb64 = }')
    r, s = 1, 0

    return cb64.decode() + '.' + hadior.tokenify([r, s])

hadior = HADIOR(64)

print('cookie =', cookie := bake())
data, t, r, s = cookie.split('.')

r = int.from_bytes(urlsafe_b64decode(r + '==='), 'big')
s = int.from_bytes(urlsafe_b64decode(s + '==='), 'big')

print('cheesed =', hadior.verify((data + '.' + t).encode(), r, s))