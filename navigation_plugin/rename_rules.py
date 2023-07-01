# ----------- DESCRIPTION: HOW TO ADD A RULE -------------
# Each rule must return True if it has been applied. If a rule has not been applied it must return False,
# and then there will be attempt to apply other rules. If a rule return True there will be no attempt to
# apply other rules to the currently analysed function.

# After a rule has been created it must be added to RULE_SET via setup_rule_set() function.
# Just add to setup_rule_set() line: 
#                                       RULE_SET.append(your_rule_name)

import idaapi
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
import os
import importlib
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

RULE_MODULES = []

def rule_generic_name(ea, obj:FuncInfo):
    def add_tag(tag, val, source_str):
        if val == 0:
            return source_str
        source_str = source_str + tag + str(val) + "_"
        return source_str

    name = "nav_"
    name = add_tag("loc", obj.loc_funcs_num, name)
    name = add_tag("sub", obj.sub_funcs_num, name)
    name = add_tag("named", obj.named_funcs_num, name)
    name = add_tag("imp", obj.import_calls_num, name)
    name = add_tag("switch", obj.switches_num, name)
    name = add_tag("d", obj.global_data, name)
    name = add_tag("s", obj.strings, name)

    if name[-1] == '_':
        name = name[:-1]

    idaapi.set_name(ea, name, idaapi.SN_FORCE | idaapi.SN_NOCHECK)
    return True

def load_rules():
    global RULE_MODULES
    
    cur_dir = __file__[:-len("rename_rules.py")]
    modules_names = ["navigation_plugin.rules." + i[:-3] for i in os.listdir(cur_dir + "rules") if i[-3:] == ".py" and i != "__init__.py"]
    modules = []
    for m in modules_names:
        print(m)
        module = __import__(m, fromlist=["rule_entry"])
        importlib.reload(module)
        modules.append(module)
    RULE_MODULES = modules

def run_rename_rules_for_all_fuctions():
    load_rules()

    for ea, obj in ALL_FUNC_INFO.items():

        if ida_name.get_ea_name(ea)[:4] != "sub_":
            continue
        rule_ret = False
        for module in RULE_MODULES:
            rule_ret = module.rule_entry(ea, obj)
            if rule_ret == True:
                break
        if rule_ret == False:
            # rule_generic_name(ea, obj) # commented for debug
            pass
    RULE_MODULES.clear()