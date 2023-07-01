import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def rule_entry(ea, obj):
    print("rule 1 works it is cool")
    return False