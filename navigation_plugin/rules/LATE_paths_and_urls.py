import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

def has_url(s):
    if b"http:" in s or \
        b"https:" in s or \
        b"html" in s or \
        b"www." in s:
        return "_has_url"
    return ''

# def has_path(s):
#     if "exe" in s or \
#         "C:" in s or \
#         "www." in s:
#         return "has_url"
#     return ''

def rule_entry(ea, obj:FuncInfo):
    new_name = ida_name.get_ea_name(ea) 

    url_s = ''

    for s_ea, c in obj.strings.items():
        s_content = idc.get_strlit_contents(s_ea)
        if len(url_s) == 0:
            url_s = has_url(s_content)

    new_name += url_s
    idaapi.set_name(ea, new_name, idaapi.SN_FORCE | idaapi.SN_NOCHECK)
    pass