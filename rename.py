import re



_operator_substitude = [

    ["[]","subscript"],
    ["<<","leftshift"],
    [">>","rightshift"],
    ["->","dereference"],
    ["()","function_call"],
    ["++","increment"],
    ["--","decrement"],
    ["*","multiply"],
    ["+","add"],
    ["-","substract"],
    ["<","less_than"],
    [">","greater_than"],
    ["<=","less_or_equal"],
    ["=>","greater_or_equal"],
    ["==","equal"],
    ["!=","not_equal"],
]

_o2n = dict(_operator_substitude)
_n2o = {y:x for x, y in _operator_substitude}

_op_regex = re.compile(r"\boperator\b(.*?)\(")
_op_regex2 = re.compile(r"\boperator\b(.*?)$")

_op_name_regex = re.compile(r"\boperator_(\w*?)\(")
_op_name_regex2 = re.compile(r"\boperator_(\w*?)$")


def get_regex(reg_lst,txt):
    for r in reg_lst:
        m = r.search(txt)
        if m:
            return m
    return None


def op_regex(txt):
    return get_regex([_op_regex,_op_regex2],txt)


def op_name_regex(txt):
    return get_regex([_op_name_regex, _op_name_regex2], txt)

def is_operator(op_name):
    return op_name in _o2n.keys()

def _is_operator_name(op_name):
    return op_name in _n2o.keys()

def opr2name(operator):
    return _o2n.get(operator, None)

def name2opr(name):
    return _n2o.get(name, None)

def is_operator_func(func_name):
    m = op_regex(func_name)
    if not m:
        return False
    return is_operator(m.group(1))

def is_removed_operator_func(func_name):
    m = op_name_regex(func_name)
    if not m:
        return False
    return _is_operator_name(m.group(1))


def remove_operator_symbols(func_name):
    if not is_operator_func(func_name):
        return func_name
    m = op_regex(func_name)
    new_name = func_name[:m.start(1)]+ "_" + opr2name(m.group(1)) + func_name[m.end(1):]
    return new_name

def getback_operator_symbols(func_name):
    if not is_removed_operator_func(func_name):
        return func_name
    m = op_name_regex(func_name)
    new_name = func_name[:m.start(1)-1]+ name2opr(m.group(1)) + func_name[m.end(1):]
    return new_name
