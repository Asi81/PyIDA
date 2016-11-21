import idc


### c declaration stuff
def function(ea):
    '''returns the C function declaration at given address'''
    result = idc.GetType(ea)
    if result is None:
        raise ValueError('function %x does not have a declaration'% ea)
    return result

def arguments(ea):
    '''returns an array of all the function's C arguments'''
    decl = function(ea)
    args = decl[ decl.index('(')+1: decl.rindex(')') ]
    result = [ x.strip() for x in args.split(',')]
    return result

def size(decl_str):
    '''returns the size of a c declaration'''
    if not decl_str.endswith(';'):
        decl_str = decl_str + ';'
    result = idc.ParseType(decl_str, 0)
    if result is None:
        raise TypeError('Unable to parse C declaration %s' % repr(decl_str))
    _,typ,_ = result
    return idc.SizeOf(typ)

def demangle(fn):
    '''demangle's a symbol to a human-decipherable string'''
    result = idc.Demangle(fn, idc.GetLongPrm(idc.INF_LONG_DN))
    return fn if result is None else result

