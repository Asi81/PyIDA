import re

pointer_size = 4

def raise_error(s):
    print s
    raise BaseException()


def sizeof(typ):
    if (typ.endswith("*")):
        return pointer_size

    builtin = {}
    builtin['int'] = 4
    builtin['unsigned int'] = 4
    builtin['short'] = 2
    builtin['unsigned short'] = 2
    builtin['char'] = 1
    builtin['unsigned char'] = 1
    builtin['__int64'] = 8
    builtin['pvoid'] = pointer_size
    builtin['pdword'] = pointer_size

    if typ not in builtin.keys():
        raise_error("Unknown type %s" % typ)
    return builtin[typ]


def remove_comments(cl):
    cl = re.sub(r'/\*[\w\W]*?\*/', "", cl)  # remove /**/ comments
    cl = re.sub(r'//.*', '', cl)  # remove // comments
    return cl


class StructField(object):
    def __init__(self):
        self.typ = ""
        self.name = ""
        self.fun_args = ""
        self.arr_list = []
        self.strong_ast = ""
        self.weak_ast = ""
        self.orig_str = ""
        self.sign = ""

    def type_string(self):
        arrstr = "".join("[%s]" % i for i in self.arr_list)
        full_type = "%s %s %s %s %s %s" % (self.sign, self.typ, self.weak_ast, self.strong_ast, self.fun_args, arrstr)
        while full_type.count("  "):
            full_type = full_type.replace("  ", " ")

        return full_type

    def parse(self, item):

        """

        :type item: str
        """
        self.orig_str = item

        # get base typ
        if re.match(r'\s*(struct)|(union)', item):
            raise_error("Nested structs is not supported")

        # get sign prefix
        m = re.match(r'\s*(un)*signed', item)
        if m:
            self.sign = m.group(0).strip()
            item = item[m.end(0):]

        # get typ
        m = re.match(r'\s*([A-Za-z_]\w*)', item)
        if not m:
            raise_error("bad string %s" % item)
        self.typ = m.group(1)
        item = item[m.end(0):]

        # get strong and weak pointers
        m = re.match(r'([\s\*]*)\(([\*\s]+)([A-Za-z_]\w*)\s*\)', item)
        if m:
            self.weak_ast = m.group(1).count('*') * '*'
            self.strong_ast = "(" + m.group(2).count('*') * '*' + ")"
            self.var_name = m.group(3)
        else:
            m = re.match(r'([\*\s]*)([A-Za-z_]\w*)', item)
            if not m:
                raise_error("var name not found")
            self.weak_ast = m.group(1).count('*') * '*'
            self.strong_ast = ''
            self.var_name = m.group(2)
        item = item[m.end(0):]

        # get func args
        m = re.match(r'\s*(\(.*\))', item)
        if m:
            self.fun_args = m.group(1)
            item = item[m.end(0):]

        else:
            # get array definition
            while True:
                m = re.match(r'\s*\[\s*([0-9A-Fa-fx]*)\s*\]', item)
                if not m:
                    break
                try:
                    self.arr_list.append(int(m.group(1), 0))
                except:
                    raise_error("bad num %s" % m.group(1))
                item = item[m.end(0):]

        if re.search('[^\s]', item):
            raise_error("Unusual ending: " + item)

    def single_size(self):
        if self.strong_ast or self.weak_ast:
            return pointer_size
        return sizeof(self.typ)

    def size(self):
        if self.strong_ast:
            return pointer_size
        s = 1
        for a in self.arr_list:
            s *= a
        return s * self.single_size()

    def divisible_size(self):
        return self.size() / (self.arr_list[0] if self.arr_list else 1)

    def __len__(self):
        if self.strong_ast:
            return 1

        if self.arr_list:
            return self.arr_list[0]
        return 1


class HeaderStruct(object):
    def __init__(self, align):
        self.fields = []
        self.struct_name = ''
        self.align = align

    def parse(self, struct):

        """

        :type struct: str
        """

        struct = remove_comments(struct)
        m = re.match(r'\s*struct\s*([a-zA-Z_]\w*)\s*\{([\s\S]*?)\}', struct)
        if not m:
            raise_error("bad declaration")

        self.struct_name = m.group(1)
        body = m.group(2)

        items = [i for i in body.split(";") if re.search(r'\S', i)]
        for item in items:
            f = StructField()
            f.parse(item)
            self.fields.append(f)
            print f.type_string(), "\titem = ", item.replace("\n", "")

    def field_offset(self, index):
        """

        :type index: int
        """
        off = 0
        for f in self.fields[:index]:
            al = min(self.align, f.single_size())
            off = (off + al - 1) // al * al + f.size()
        return off

    def size(self):
        a = max([f.single_size() for f in self.fields])
        a = min(self.align, a)
        return (self.field_offset(len(self.fields)) + a - 1) / a * a

    def fields(self):
        return [f.name for f in self.fields]

    def insert_var(self, field_name, new_var_str, arr_index = 0):

        """

        :param field_name: str
        :param new_var_str: str
        :param arr_index: int

        """
        f = self.fields[self.fields().index(field_name)]

        nf = StructField()
        nf.parse(new_var_str)

        if nf.size() % f.divisible_size():
            raise_error("New size = %s  should be divisible of %s" % (nf.size(),f.divisible_size()))

        if nf.size() > f.size():
            raise_error("New field size(%s) is bigger than old field size(%d)" % (nf.size(), f.size()))

        if f.arr_list:

            repl_count = nf.size / f.divisible_size()
            if arr_index:
                pre_f = f
                pre_f.arr_list[0] = arr_index



        pass

    def __len__(self):
        return len(self.fields)


s = """struct CLafFlash
{
	char buf0[2]; // comment 1    0
	char /*comment 2*/ buf2[0x10]; //   2
	char buf3[0x5]    /*comment 3*/; //  18
	int * ptr;                 //24
	signed int ( * parr)[2][3];    //32
	unsigned char (/*comment 2*/ **buf5)[10];   //40
	int *arr[5];                                //48
	void (*pfunc)(int a1);                          //88
	void* (*super_ptr) (int a1,int a2, int a3);     //96

}; //104

"""

e = """struct CLafFlash
{
    short m;
    char n;
    __int64 nv;
    char t;

};

"""
hs = HeaderStruct(16)
hs.parse(s)

print "struct field count %s" % len(hs)

print "struct size ", hs.size()

