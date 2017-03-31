import idc
import idaapi
import idautils
import constants
from mybase import _declaration


# Searches for immediate values commonly founds in MIPS WPS checksum implementations.
# May be applicable to other architectures as well.


class WPSearch(object):
    def __init__(self):
        self.funcs = {}

    def xrefs(self):
        # Identify functions that reference the WPS checksum functions and resolve their string xrefs.
        # Returns a dictionary of function EAs and a list of their string xrefs.

        self._generate_checksum_xrefs_table()

        for string in idautils.Strings():
            for xref in idautils.XrefsTo(string.ea):
                func = idaapi.get_func(xref.frm)
                if func and self.funcs.has_key(func.startEA):
                    self.funcs[func.startEA].add(str(string))

        return self.funcs

    def scan(self):
        self._search_for_immediates()
        ret = []
        for f in self.funcs.keys():

            l = [str(constants.constants[const]) for const in self.funcs[f]]
            l.sort()
            txt = ";   ".join(l)
            ret.append([f,txt])
        return ret

    def _search_for_immediates(self):
        self.funcs = {}
        for immediate in constants.constants.keys():
            ea = 0
            while ea != idc.BADADDR:
                (ea, n) = idc.FindImmediate(ea, idc.SEARCH_DOWN, self._twos_compliment(immediate))
                if ea != idc.BADADDR:
                    func = idaapi.get_func(ea)
                    if func:
                        s = self.funcs.get(func.startEA,set())
                        s.add(immediate)
                        self.funcs[func.startEA] =  s
                    else:
                        for xref in idautils.XrefsTo(ea):
                            func = idaapi.get_func(xref.frm)
                            if func:
                                s = self.funcs.get(func.startEA, set())
                                s.add(immediate)
                                self.funcs[func.startEA] = s



    def _twos_compliment(self, val):
        if idaapi.BADADDR == 0xFFFFFFFFFFFFFFFFL:
            tv = self.__twos_compliment(val, 64)
        else:
            tv = self.__twos_compliment(val, 32)
        return tv

    @staticmethod
    def __twos_compliment(val, bits):
        # Python converts values larger than 0x7FFFFFFF into longs, which
        # aren't converted properly in the swig translation. Use 2's compliment
        # for large values instead.
        if (val & (1 << (bits - 1))) != 0:
            val -= 1 << bits
        return val

    def _generate_checksum_xrefs_table(self):
        self.funcs = {}

        if not self.cksums:
            self.checksums()

        for cksum in self.cksums:
            func = idaapi.get_func(cksum)
            if func:
                self.funcs[func.startEA] = set()

            for xref in idautils.XrefsTo(cksum):
                func = idaapi.get_func(xref.frm)
                if func and not self.funcs.has_key(func.startEA):
                    self.funcs[func.startEA] = set()

class WPSearchFunctionChooser(idaapi.Choose2):

    DELIM_COL_1 = '-' * 50
    DELIM_COL_2 = '-' * 20
    DELIM_COL_3 = '-' * 125

    def __init__(self):
        idaapi.Choose2.__init__(self,
                                "Checksum/Crypto Functions",
                                [
                                    ["Function", 15 | idaapi.Choose2.CHCOL_PLAIN],
                                    ["Constants", 100 | idaapi.Choose2.CHCOL_PLAIN],
                                ])

        self.icon = 41
        self.wps = WPSearch()

        self.run_scans()
        self.populate_items()

    def OnSelectLine(self, n):
        idc.Jump(self.items[n][-1])

    def OnGetSize(self):
        return len(self.items)

    def OnGetLine(self, n):
        return self.items[n]

    def OnClose(self):
        pass

    def run_scans(self):
        self.checksum_functions = self.wps.scan()
        # self.checksum_string_xrefs = self.wps.xrefs()

    def populate_items(self):
        self.items = []
        for ea, txt in self.checksum_functions:
            nm = _declaration.demangle(idc.GetFunctionName(ea))
            self.items.append([nm, txt, ea])#idc.Name(ea)

    def show(self):
        if self.Show(modal=False) < 0:
            return False
        return True




def launch():
    WPSearchFunctionChooser().show()

