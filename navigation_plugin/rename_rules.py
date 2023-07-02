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

def generic_rule(ea, obj:FuncInfo):
    name = "nav_" + get_info_for_name(ea, obj)
    idaapi.set_name(ea, name, idaapi.SN_FORCE | idaapi.SN_NOCHECK)
    if len(name) >= 1 and name[-1] == '_':
        name = name[:-1]
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

        if ida_name.get_ea_name(ea)[:4] != "sub_" and  \
            ida_name.get_ea_name(ea)[:4] != "nav_":
            continue
        rule_ret = False
        for module in RULE_MODULES:
            rule_ret = module.rule_entry(ea, obj)
            if rule_ret == True:
                break
        if rule_ret == False:
            generic_rule(ea, obj)
            pass
    RULE_MODULES.clear()