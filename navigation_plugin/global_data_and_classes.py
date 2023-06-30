import ida_name
import ida_nalt
import ida_lines
import ida_kernwin
import idautils
import ida_funcs
import time
import idc
import ida_bytes
import ida_xref


class FuncInfo:
    def __init__(self):
        self.size           = 0
        self.calls          = 0
        self.import_calls   = {} # ea:count
        self.internal_calls = 0
        self.strings        = 0
        self.global_data    = 0
        self.loc_funcs      = set()
        self.sub_funcs      = {} # ea:count
        self.named_funcs    = {} # ea:count
        self.switches       = set()
        self.switches_num   = 0

ALL_FUNC_INFO = {}
ALL_IMP = {}