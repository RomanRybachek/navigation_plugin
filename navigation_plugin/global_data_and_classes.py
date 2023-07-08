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

WEAK_RULE_TRUE  = 0
RULE_TRUE       = 1
RULE_FALSE      = 2


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

        self.has_cycle          = False
        self.hard_to_analyse    = False

def is_func(ea):
    func_t_struct =  ida_funcs.get_func(ea)
    if func_t_struct == None:
        return False
    return True

if 'ALL_FUNC_INFO' not in globals():
    ALL_FUNC_INFO = {}
if 'ALL_IMP' not in globals(): 
    ALL_IMP = {}

def get_info_for_name(ea, obj:FuncInfo):
    def add_tag(tag, val, source_str):
        if val == 0:
            return source_str
        source_str = source_str + tag + str(val) + "_"
        return source_str
    name = ""
    name = add_tag("loc", obj.loc_funcs_num, name)
    name = add_tag("sub", obj.sub_funcs_num, name)
    name = add_tag("named", obj.named_funcs_num, name)
    name = add_tag("imp", obj.import_calls_num, name)
    name = add_tag("switch", obj.switches_num, name)
    if obj.has_cycle == True:
        name = name + "cycle_"
    elif obj.hard_to_analyse == True:
        name = name + "cycleIsPossible_"
    name = add_tag("d", obj.global_data, name)
    name = add_tag("s", obj.strings, name)

    if len(name) >= 1 and name[-1] == '_':
        name = name[:-1]
    return name
