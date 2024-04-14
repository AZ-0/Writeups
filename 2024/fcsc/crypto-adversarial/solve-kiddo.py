from collections import defaultdict

n = 32317006071311007300714876688669951960444102669715484116646415746394635540935921521724498858714153019942728273207389351392489359055364847068112159175081645180751388138858639873796530441238955101568733568176426113140426646976937052525918530731769533330028543775101205176486450544323218351858348091394877603920443607214945787590258064663918917740728042628406529049644873974905470262922605695823668958842546472908325174694333334844222696779786423580284135591089906934014814106737656354549850191740172203279085863986305338341130808123659535483768004216490879857791785965848808238698345641038729244197829259714168491081729
e = 65537
c = 0x00bae65fbca88fea74202821d1773fa90e1a6e3532b3e60f1516ad8e04c84c1c42b733206d5b10bfeada9facd35adc426234b31183398adc4d0e842a3a2d09756f9e0bcdfdfe5b553dab4b21ea602eba4dc7db589f69360e1a598048ea0b719e7ab3ca25dec80acdaec582140877da1ce4c912425c43b1e19757309c2383b3b48ebbfcdac5bddfa167bbf1f7a31ec2a7758a52579956600306ca0dab86d5b37d3a7dfc9429a757f978905c01e46bd6d7c32f314a5916107545ad1cb17d76962b4ac11bbb6020a3ff0175d72081cc47cfd486ff05ed8799e2dd0991ce7b4f4ba2f2eae9dbddecc43e9d7a3899f6b493a839d5be7f9fe856fbe238e10047a7ad2945

N = [*map(int, f'{n:b}'[::-1])]
indices = [idx for idx in range(len(N)) if N[idx] == 1]
B = n.bit_length()
L = len(indices)


def one_factor_contrib(p: list[int], q: list[int], idx: int, f: dict[int,int]):
    p.append(idx)
    _f = f.copy()
    possible = True

    for jdx in q:
        kdx = idx+jdx
        while _f[kdx] == 1:
            del _f[kdx]
            kdx += 1
        _f[kdx] = 1

        if kdx > B or ((not N[kdx]) and (not N[kdx+1]) and (not N[kdx+2])): # SPARSENESS ASSUMPTION: Only look 2 bits ahead
            possible = False

    return possible, _f


def two_factor_contrib(p: list[int], q: list[int], idx: int, f: dict[int,int]):
    p.append(idx)
    _f = f.copy()

    for jdx in q:
        kdx = idx+jdx
        while _f[kdx]:
            del _f[kdx]
            kdx += 1
        _f[kdx] = 1

    q.append(idx)
    for jdx in p: # Don't multiply new contribution *again*
        kdx = idx+jdx
        while _f[kdx]:
            del _f[kdx]
            kdx += 1
        _f[kdx] = 1
    
    return not any(
        bit and (not N[kdx]) and (not N[kdx+1]) and (not N[kdx+2]) # SPARSENESS ASSUMPTION: Only look 2 bits ahead
        for kdx, bit in _f.items()
    ), _f


def backtrack(p: list[int] = [0], q: list[int] = [0], i: int = 1, f = defaultdict(lambda:0)):
    """
    Bruteforce a factorisation of n, assuming it is sparse
    - p: list of indices (representing the bits of p) 
    - q: list of indices (representing the bits of q)
    - i: index of current index
    - f: partial factorisation of n, according to what we know
    """
    print('-'*((L-i)//2), '>', i)

    # goal: explain idx
    idx = indices[i]

    if idx >= B//2: # log p + log q = log n
        _p = sum(1<<j for j in p)
        _q = sum(1<<j for j in q)
        if n % _q == 0:
            _p, _q = _q, _p
        if n % _p == 0:
            print('p =', _p)
            print('q =', _q := n//_p)
            if _p>1 and _q>1:
                print('DING DING DING!!!')
                return True, (_p,_q)
    
    if i>2 and indices[i-1] > B//2: # security
        return False, None

    print('Before contrib')

    # Already explained
    if f[idx]:
        check, _ = ret = backtrack(p, q, i+1, f)
        if check: return ret
        twocontrib = True  # Need 2 contributions (1 + 2 = 0b11)
    else:
        twocontrib = False

    print('After contrib:', twocontrib)

    if twocontrib:
        # Two factor contributions
        possible, _f = two_factor_contrib(p, q, idx, f)
        if possible:
            check, _ = ret = backtrack(p, q, i+1, _f)
            if check: return ret    
        p.pop()
        q.pop()
    else:
        # Two factor contribution at previous index
        possible, _f = two_factor_contrib(p, q, idx-1, f)
        if possible:
            check, _ = ret = backtrack(p, q, i+1, _f)
            if check: return ret    
        p.pop()
        q.pop()

    # Contribution of p
    possible, _f = one_factor_contrib(p, q, idx, f)
    cleanq = False
    if possible and twocontrib:
        possible, _f = one_factor_contrib(q, p, idx, _f)
        cleanq = True
    if possible:
        check, _ = ret = backtrack(p, q, i+1, _f)
        if check: return ret
    p.pop()
    if cleanq:
        q.pop()

    # Contribution of q
    possible, _f = one_factor_contrib(q, p, idx, f)
    cleanp = False
    if possible and twocontrib:
        possible, _f = one_factor_contrib(p, q, idx, _f)
        cleanp = True
    if possible:
        check, _ = ret = backtrack(p, q, i+1, _f)
        if check: return ret
    q.pop()
    if cleanp:
        p.pop()

    # Partially explained by previous contribution
    oldidx = idx
    while f[idx-1] and (not N[idx-1]):
        idx -= 1

    if idx == oldidx: # No previous contribution
        return False, None

    # Contribution of p
    possible, _f = one_factor_contrib(p, q, idx, f)
    cleanq = False
    if twocontrib:
        possible, _f = one_factor_contrib(q, p, oldidx, _f)
        cleanq = True
    if possible:
        check, _ = ret = backtrack(p, q, i+1, _f)
        if check: return ret
    p.pop()
    if cleanq:
        q.pop()

    # Contribution of q
    possible, _f = one_factor_contrib(q, p, idx, f)
    cleanp = False
    if twocontrib:
        possible, _f = one_factor_contrib(p, q, oldidx, _f)
        cleanp = True
    if possible:
        check, _ = ret = backtrack(p, q, i+1, _f)
        if check: return ret
    q.pop()
    if cleanp:
        p.pop()

    return False, None


check, ret = backtrack()
if check:
    p, q = ret
    d = pow(e, -1, (p-1)*(q-1))
    m = pow(c, d, n)
    print('d =', d)
    print('m =', m)
    print('flag:', m.to_bytes(m.bit_length()//8+1, 'big'))
else:
    print('Done :c')