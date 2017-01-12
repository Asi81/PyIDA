

def lcs(a, b):
    lengths = [[0 for j in range(len(b) + 1)] for i in range(len(a) + 1)]
    # row 0 and column 0 are initialized to 0 already
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            if x == y:
                lengths[i + 1][j + 1] = lengths[i][j] + 1
            else:
                lengths[i + 1][j + 1] = max(lengths[i + 1][j], lengths[i][j + 1])
    # read the substring out from the matrix
    result = []
    x, y = len(a), len(b)
    while x != 0 and y != 0:
        if lengths[x][y] == lengths[x - 1][y]:
            x -= 1
        elif lengths[x][y] == lengths[x][y - 1]:
            y -= 1
        else:
            assert a[x - 1] == b[y - 1]
            result.insert(0,a[x - 1])
            x -= 1
            y -= 1
    return result



def insertion(seqv, lcs_seqv):
    insert = {}
    i,j = 0,0
    while i < len(seqv):
        if seqv[i] == lcs_seqv[j]:
            j+=1
        else:
            l = insert.get(j,[])
            l.append(seqv[i])
            insert[j] = l
        i+=1
    return insert


def create_text(lcs_seqv,a_insert,b_insert):

    ret = []
    d = {}

    ab = set(a_insert.keys()) | set(b_insert.keys())
    for i in list(ab):
        a = a_insert.get(i,[])
        b = b_insert.get(i,[])
        while len(a) < len(b):
            a.append("")
        if a:
            d[i] = a
    for i in range(len(lcs_seqv)):
        for l in d.get(i,[]):
            ret.append("+" + l)
        ret.append("=" + lcs_seqv[i])
    return "\n".join(ret)

