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
import ida_ua

class FuncInfo:
    def __init__(self):
        self.size               = 0
        self.strings            = 0
        self.global_data        = 0

        self.import_calls       = {} # ea:count
        self.import_calls_num   = 0

        self.loc_funcs          = set()
        self.loc_funcs_num      = 0
        self.sub_funcs          = {} # ea:count
        self.sub_funcs_num      = 0
        self.named_funcs        = {} # ea:count
        self.named_funcs_num    = 0
        self.internal_calls     = 0 #sub_ and named functions

        self.calls              = 0 # internals and import calls

        self.switches           = set()
        self.switches_num       = 0

def is_func(ea):
    func_t_struct =  ida_funcs.get_func(ea)
    if func_t_struct == None:
        return False
    return True

if 'ALL_FUNC_INFO' not in globals():
    ALL_FUNC_INFO = {}
if 'ALL_IMP' not in globals(): 
    ALL_IMP = {}