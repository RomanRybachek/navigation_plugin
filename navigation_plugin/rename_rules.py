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
LATE_RULE_MODULES = []

def generic_rule(ea, obj:FuncInfo):
    name = "nav_" + get_info_for_name(ea, obj)
    if len(name) >= 1 and name[-1] == '_':
        name = name[:-1]
    return rule_exit(RULE_TRUE, ea, obj, name)

def load_rules():
    global RULE_MODULES
    global LATE_RULE_MODULES
    
    cur_dir = __file__[:-len("rename_rules.py")]
    modules_names = ["navigation_plugin.rules." + i[:-3] for i in os.listdir(cur_dir + "rules") if i[-3:] == ".py" and i != "__init__.py"]
    for m in modules_names:
        module = __import__(m, fromlist=["rule_entry"])
        importlib.reload(module)
        if m.find("LATE_") != -1:
            LATE_RULE_MODULES.append(module)
        else:
            RULE_MODULES.append(module)

def run_rename_rules_for_all_fuctions():
    global RULE_MODULES
    global LATE_RULE_MODULES
    RULE_MODULES.clear()
    LATE_RULE_MODULES.clear()
    load_rules()

    for ea, obj in ALL_FUNC_INFO.items():

        if ida_name.get_ea_name(ea)[:4] != "sub_" and  \
            ida_name.get_ea_name(ea)[:4] != "nav_":
            continue
        rule_ret = RULE_FALSE
        for module in RULE_MODULES:
            rule_ret = module.rule_entry(ea, obj) # If RULE_FALSE or WEAK_RULE_TRUE
            if rule_ret == RULE_TRUE:
                break
        if rule_ret == RULE_FALSE:
            generic_rule(ea, obj)
        for module in LATE_RULE_MODULES:
            module.rule_entry(ea, obj) # If RULE_FALSE or WEAK_RULE_TRUE

    RULE_MODULES.clear()
    LATE_RULE_MODULES.clear()

def run_rules_for_function_under_cursor():
    global RULE_MODULES
    global LATE_RULE_MODULES
    load_rules()

    ea = ida_kernwin.get_screen_ea()
    obj = ALL_FUNC_INFO.get(ea, None)
    if obj == None:
        print("There is no unexplored function under cursor")
        return

    for module in RULE_MODULES:
        rule_ret = module.rule_entry(ea, obj)
        if rule_ret == RULE_TRUE:
            break
    if rule_ret == RULE_FALSE:
        generic_rule(ea, obj)
        pass
    RULE_MODULES.clear()
    LATE_RULE_MODULES.clear()