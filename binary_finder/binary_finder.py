############################################################################################################################
#
# Binary Finder and Renamer for IDA
#
# Usage: binary_table_find(start_addr, end_addr, tables, name_tables)
#
# Example:
# tables = [("my_table_name", "HEX MASK WITH SPACE, LIKE: 11 22 33 44", "SIZE IN BYTES, LIKE: 4", "ELEMENT TYPE: BYTE")]
# tables = [("my_table1", "11 22 33 44", 4, "BYTE"), ("my_table2", "AA 01 BB 02", 4, "WORD")]
# binary_table_find(0x1000, 0xFFFF, tables, "MY_TABLES"):
#
# Result in IDA:
# 0x1010: my_table1	DCB	0x11, 0x22, 0x33, 0x44		; Array of 4 bytes
# 0x2010: my_table2	DCW	0x01AA, 0x02BB 			; Array of 2 words
#
############################################################################################################################

from idc import *
import idautils
import gui

def find_binary_strings(start_addr, hex_str, str_size):
    res = []
    next_addr = start_addr
    while True:
        faddr = FindBinary(next_addr, SEARCH_DOWN | SEARCH_CASE, hex_str)
        if faddr == BADADDR:
            break
        res += [faddr]
        next_addr = faddr + str_size
    return res


def rename_public(addr, addr_name):
    if MakeNameEx(addr, addr_name, SN_CHECK | SN_PUBLIC | SN_NON_WEAK | SN_NON_AUTO) == 0:
        print("Can't rename addr=%08X, name=%s" % (addr, addr_name))


def unknown_area(addr, byte_size):
    MakeUnknown(addr, byte_size, DOUNK_SIMPLE)


def data_area(addr, element_type):
    if element_type.upper() == "BYTE":
        if MakeByte(addr)==0:
            print("Can't convert to BYTE at addr=%08X" % addr)

    if element_type.upper() == "WORD":
        if MakeWord(addr)==0:
            print("Can't convert to WORD at addr=%08X" % addr)

    if element_type.upper() == "DWORD":
        if MakeDword(addr)==0:
            print("Can't convert to DWORD at addr=%08X" % addr)

    if element_type.upper() == "QWORD":
        if MakeQword(addr)==0:
            print("Can't convert to QWORD at addr=%08X" % addr)


def element_type_to_size(element_type):
    res = 0
    if element_type.upper() == "BYTE":
        res = 1
    if element_type.upper() == "WORD":
        res = 2
    if element_type.upper() == "DWORD":
        res = 4
    if element_type.upper() == "QWORD":
        res = 8
    return res


def make_array(addr, byte_size, element_type):
    unknown_area(addr, byte_size)
    data_area(addr, element_type)
    element_size = element_type_to_size(element_type)
    element_count = byte_size / element_size

    if MakeArray(addr, element_count)==0:
        print("Can't create Array at addr=%08X" % addr)


def binary_table_find(start_addr, end_addr, tables, name_tables):
    print("Finding %s from 0x%08X to 0x%08X..." % (name_tables, start_addr, end_addr))
    c = 0
    for (xname, xhex_mask, xbyte_size, xelement_type) in tables:
        list_addr = find_binary_strings(start_addr, xhex_mask, xbyte_size)
        c += len(list_addr)
        for xaddr in list_addr:
            if xaddr <= end_addr:
                print("%s found at 0x%08X" % (xname, xaddr))
    print("Finished: found %s items" % c)


def create_binary_table(ea,tables,name_tables):
    print("Creating %s from at 0x%08X..." % (name_tables, ea))

    for xname, xhex_mask, xbyte_size, xelement_type in tables:
        list_addr = find_binary_strings(ea, xhex_mask, xbyte_size)

        if list_addr and list_addr[0] == ea:
            # make name
            addr_name = xname
            nm = [b for a,b in idautils.Names()]
            iname = 2
            while addr_name in nm:
                addr_name = "%s_%d" % (xname, iname)
                iname += 1

            if not gui.ask("Found %s. Create %s?" % (xname,addr_name)):
                return

            # rename in IDA
            rename_public(ea, addr_name)

            # make array in IDA
            make_array(ea, xbyte_size, xelement_type)
            return

    print "No known %s found at 0x%08X" % name_tables,ea
