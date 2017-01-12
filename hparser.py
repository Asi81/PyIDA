import idaapi
import re
import copy
from syntax import Where



pointer_size = 8 if idaapi.get_inf_structure().is_64bit() else 4

def raise_error(error_text):
    print error_text
    raise BaseException(error_text)


def sizeof(typ):
    if typ.endswith("*"):
        return pointer_size

    builtin = {'int': 4, 'unsigned int': 4, 'short': 2, 'unsigned short': 2, 'char': 1, 'unsigned char': 1,
               '__int64': 8, 'pvoid': pointer_size, 'pdword': pointer_size, "_DWORD": 4, "_BYTE": 1,
               "_WORD": 2, 'PDWORD': pointer_size, 'PVOID': pointer_size,"_QWORD": 8}

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
        self.arr_hex_num = []
        self.strong_ast = ""
        self.weak_ast = ""
        self.orig_str = ""
        self.sign = ""
        self.name = ""
        self.const_modif = ""
        if item:
            self.parse(item)


    def array_shape(self):
        return copy.copy(self.arr_list)

    def set_array_shape(self,shape):
        self.arr_list = copy.copy(shape)

    def type_string(self):

        def tostr(x,d):
            return  "[%s]" % (hex(x) if d else str(x))
        arrstr = map(tostr,self.arr_list,self.arr_hex_num)
        full_type = "%s %s %s%s %s%s%s" % (self.const_modif, self.sign, self.typ, self.weak_ast, self.strong_ast, self.fun_args, arrstr)
        full_type = re.sub(' +',' ',full_type).strip()
        return full_type

    def __str__(self):
        def tostr(x,d):
            return  "[%s]" % (hex(x) if d else str(x))
        arrstr =  "".join(map(tostr,self.arr_list,self.arr_hex_num))

        show_name = self.name
        if self.strong_ast:
            show_name = self.strong_ast.replace(")", " %s)" % self.name  )
        definition = "%s %s %s%s %s%s%s" % (self.const_modif, self.sign, self.typ, self.weak_ast, show_name, self.fun_args, arrstr)
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


        #get const modif
        m = re.match('\s*(const)|(volatile)', item)
        if m:
            self.const_modif = m.group(0).strip()
            item = item[m.end(0):]


        # get sign prefix
        m = re.match(r'\s*(un)*signed', item)
        if m:
            self.sign = m.group(0).strip()
            item = item[m.end(0):]

        # get typ
        self.typ = ""
        while True:
            m = re.match(r'\s*([A-Za-z_]\w*)', item)
            if not m:
                raise_error("bad string %s" % item)
            self.typ += m.group(1)
            item = item[m.end(0):]

            if item.startswith("::"):
                self.typ += "::"
                item = item[2:]
                continue
            break





        # get strong and weak pointers
        m = re.match(r'([\s*]*)\(([*\s]+)([A-Za-z_]\w*)\s*\)', item)
        if m:
            self.weak_ast = m.group(1).count('*') * '*'
            self.strong_ast = "(" + m.group(2).count('*') * '*' + ")"
            self.name = m.group(3)
        else:
            m = re.match(r'([*\s]*)([A-Za-z_]\w*)', item)
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
                m = re.match(r'\s*\[\s*([0-9A-Fa-fx+\-*/% ]*)\s*\]', item)
                if not m:
                    break
                try:
                    num_text = m.group(1)
                    self.arr_hex_num.append(not re.search("[+\-*/%]",num_text) and "x" in num_text)
                    self.arr_list.append(eval(num_text))
                except SyntaxError:
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
        self.name = ''
        self.align = align
        self.comments = {}


    def __str__(self):

        ret = """struct %s\n{\n%s;\n};"""
        ret %=  (self.name, ";\n".join("\t" + str(f) for f in self.fields))
        ret = self.fill_comments(ret)
        return ret

    def init_comments(self,text):
        text = re.sub(r'/\*[\w\W]*?\*/', "", text)  # remove /**/ comments

        for line in text.split("\n"):
            m = re.search(r'\s*//.*',line)
            if m:
                a = line[:m.start()].strip()
                if a:
                    b = line[m.start():]
                    self.comments[a] = b

    def fill_comments(self,text):
        out = [line + self.comments.get(line.strip(),"") for line in text.split("\n")]
        return "\n".join(out)

    def parse(self, struct):

        """

        :type struct: str
        """
        self.init_comments(struct)
        struct = remove_comments(struct)
        m = re.match(r'\s*struct\s*([a-zA-Z_]\w*)\s*\{([\s\S]*?)\}', struct)
        if not m:
            raise_error("bad declaration")

        self.name = m.group(1)
        body = m.group(2)

        items = [i for i in body.split(";") if re.search(r'\S', i)]
        for item in items:
            f = StructField()
            f.parse(item)
            self.fields.append(f)
            # print f.type_string(), "\titem = ", item.replace("\n", "")

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

    def names(self):
        return [f.name for f in self.fields]

    def split_var(self, field_name, new_var_str, arr_index = 0):

        """

        :param field_name: str
        :param new_var_str: str
        :param arr_index: int

        """
        try:
            i = self.fields.index(Where(lambda x: x.name == field_name))
        except ValueError:
            raise_error("field %s not found" % field_name)

        of = self.fields[i]
        nf = StructField(new_var_str)

        if nf.name in self.names():
            raise_error("Var %s is already in %s" % (nf.name, self.name)  )

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
            post_f.name += "_%s" % end_index
            self.fields.insert(i,post_f)
            i+=1
        pass

    def __len__(self):
        return len(self.fields)




class HFile:
    def __init__(self, filename):
        self.filename = filename
        self.structs = []
        self.struct_bounds = []
        self.text = ""
        self.parse()

    def struct_list(self):
        return [struct.name for struct in self.structs]

    def replace(self, structure):
        idx = self.structs.index(Where(lambda x: x.name == structure.name))
        left,right = self.struct_bounds[idx]
        self.text = self.text[:left] + str(structure) + self.text[right:]

    def save(self,fname = ""):
        if not fname:
            fname = self.filename
        f = open(fname,"w")
        f.write(self.text)
        f.close()

    def get(self,struct_name):
        return Where(lambda x: x.name == struct_name).find(self.structs)

    def bounds(self,struct_name):
        i = self.structs.index(Where(lambda x: x.name == struct_name))
        return self.struct_bounds[i]


    def parse(self):
        f = open(self.filename,"r")
        self.text = f.read()

        start_idx = 0
        while True:
            m = re.search("struct [\w\W]*?\}[\w\W]*?;",self.text[start_idx:])
            if not m:
                break
            try:
                h = HeaderStruct(1)
                h.parse(m.group(0))
                self.structs.append(h)
                self.struct_bounds.append( (m.start() + start_idx,m.end() + start_idx))
                print "struct %s found in %s %s-%s" % (h.name,self.filename,m.start() + start_idx ,m.end() + start_idx)
            except BaseException:
                print "Error in file %s. Skip" % self.filename
            start_idx += m.end()



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
# hs = HeaderStruct(1)
# hs.parse(s)
#
#
# print str(hs)
# print "struct size ", hs.size()
#
# hs.split_var("buf2", "int my_new_var", 4)
#
# print str(hs)
# print "struct size ", hs.size()


# print "struct field count %s" % len(hs)
#
# print "struct size ", hs.size()
#


# import os
#
# for file in os.listdir("D:\IDA\headers"):
#     h = HFile(os.path.join("D:\IDA\headers",file))
#
#     print "file", file, "\n"
#
#     for struct_name in h.struct_list():
#         struct = h.get(struct_name)
#         print str(struct)



# h = HFile(r"D:\IDA\ting.h")
# struct = h.get("ting")
# struct.split_var("m_es_buf0","__int64 yyy",0)
# h.replace(struct)
# h.save(r"D:\IDA\ting_test.h")


