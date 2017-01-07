import re
import idaapi
import copy



class Key(object):
    def __init__(self, pred): self.pred = pred
    def __eq__(self, other): return self.pred(other)

pointer_size = 8

def raise_error(error_text):
    print error_text
    raise BaseException(error_text)


def sizeof(typ):
    if typ.endswith("*"):
        return pointer_size

    builtin = {'int': 4, 'unsigned int': 4, 'short': 2, 'unsigned short': 2, 'char': 1, 'unsigned char': 1,
               '__int64': 8, 'pvoid': pointer_size, 'pdword': pointer_size}

    if typ not in builtin.keys():
        raise_error("Unknown type %s" % typ)
    return builtin[typ]


def remove_comments(cl):
    cl = re.sub(r'/\*[\w\W]*?\*/', "", cl)  # remove /**/ comments
    cl = re.sub(r'//.*', '', cl)  # remove // comments
    return cl


class StructField(object):
    def __init__(self,item = None):
        self.typ = ""
        self.fun_args = ""
        self.arr_list = []
        self.strong_ast = ""
        self.weak_ast = ""
        self.orig_str = ""
        self.sign = ""
        self.name = ""
        if item:
            self.parse(item)


    def array_shape(self):
        return copy.copy(self.arr_list)

    def set_array_shape(self,shape):
        self.arr_list = copy.copy(shape)

    def type_string(self):
        arrstr = "".join("[%s]" % i for i in self.arr_list)
        full_type = "%s %s %s %s %s %s" % (self.sign, self.typ, self.weak_ast, self.strong_ast, self.fun_args, arrstr)
        full_type = re.sub(' +',' ',full_type).strip()
        return full_type

    def __str__(self):
        arrstr = "".join("[%s]" % i for i in self.arr_list)

        show_name = self.name
        if self.strong_ast:
            show_name = self.strong_ast.replace(")", " %s)" % self.name  )
        definition = "%s %s %s %s %s %s" % (self.sign, self.typ, self.weak_ast, show_name, self.fun_args, arrstr)
        definition = re.sub(' +',' ',definition).strip()
        return definition


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
            self.name = m.group(3)
        else:
            m = re.match(r'([\*\s]*)([A-Za-z_]\w*)', item)
            if not m:
                raise_error("var name not found")
            self.weak_ast = m.group(1).count('*') * '*'
            self.strong_ast = ''
            self.name = m.group(2)
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
        result = 1
        for a in self.arr_list:
            result *= a
        return result * self.single_size()

    def divisible_size(self):
        if self.arr_list:
            return self.size() / self.arr_list[0]
        return self.size()

    def divisible_count(self):
        return self.size() / self.divisible_size()



class HeaderStruct(object):
    def __init__(self, align):
        self.fields = []
        self.struct_name = ''
        self.align = align


    def __str__(self):

        s = """struct %s
{
%s;
};
        """ % (self.struct_name,  ";\n".join( "\t" + str(s) for s in self.fields ))
        return s

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

    def split_var(self, field_name, new_var_str, arr_index = 0):

        """

        :param field_name: str
        :param new_var_str: str
        :param arr_index: int

        """
        try:
            i = self.fields.index(Key(lambda x: x.name == field_name))
        except:
            raise_error("field %s not found" % field_name)

        of = self.fields[i]
        nf = StructField(new_var_str)

        if nf.size() % of.divisible_size():
            raise_error("New size = %s  should be divisible of %s" % (nf.size(),of.divisible_size()))

        if nf.size() > of.size():
            raise_error("New field size(%s) is bigger than old field size(%d)" % (nf.size(), of.size()))

        end_index = arr_index + nf.size() / of.divisible_size()
        if end_index > of.divisible_count():
            raise_error("Array index is out of bounds")


        self.fields.pop(i)

        if arr_index:
            pre_f = copy.deepcopy(of)
            shape = pre_f.array_shape()
            shape[0] = arr_index
            pre_f.set_array_shape(shape)
            self.fields.insert(i,pre_f)
            i+=1

        self.fields.insert(i,nf)
        i+=1

        rest_count = of.divisible_count() - end_index
        if rest_count:
            post_f = copy.deepcopy(of)
            shape = post_f.array_shape()
            shape[0] = rest_count
            post_f.set_array_shape(shape)
            post_f.name = post_f.name + "_%s" % end_index
            self.fields.insert(i,post_f)
            i+=1
        pass

    def __len__(self):
        return len(self.fields)




class HFile:
    def __init__(self, filename):
        self.filename = filename

    def struct_list(self):
        pass

    def insert(self, structure):
        pass

    def get(self,struct_name):
        pass




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
	int yy;

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
hs = HeaderStruct(1)
hs.parse(s)


print str(hs)
print "struct size ", hs.size()

hs.split_var("buf2", "int my_new_var", 4)

print str(hs)
print "struct size ", hs.size()


# print "struct field count %s" % len(hs)
#
# print "struct size ", hs.size()
#
