import binary_finder
import crc_tables
from mybase.database import baseaddress,here

def crc_table_find(start_addr = baseaddress(), end_addr=0xFFFFFFF0):
    binary_finder.binary_table_find(start_addr, end_addr, crc_tables.tables, "CRC TABLES")


def create_crc_table():
    ea = here()
    binary_finder.create_binary_table(ea,crc_tables.tables, "CRC TABLES")