import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

path_strings    = [b"c:", b".exe", b".txt", b".dll", b'.tmp', \
                   b".cpp", b".tmp"]
url_strings     = [b"http:", b"https:", b"www"]

def is_contain_str(target_str:bytes, substr:bytes):
    if target_str.find(substr) != -1:
        return True
    return False

def contain_str_from_list(target_str:bytes, str_list):
    lower_case = target_str.lower()
    for s in str_list:
        if is_contain_str(lower_case, s) == True:
            return True
    return False

def there_are_paths_among_strings(obj):
    for s_ea, c in obj.strings.items():
        s_content = idc.get_strlit_contents(s_ea)
        if contain_str_from_list(s_content, path_strings) == True:
            return "_paths"
    return ''

def there_are_urls_among_strings(obj):
    for s_ea, c in obj.strings.items():
        s_content = idc.get_strlit_contents(s_ea)
        if contain_str_from_list(s_content, url_strings) == True:
            return "_urls"
    return ''

def rule_entry(ea, obj:FuncInfo):
    name = obj.new_name
    add_to_name = ''
    add_to_name += there_are_paths_among_strings(obj)
    add_to_name += there_are_urls_among_strings(obj)
    if len(add_to_name) > 0:
        name += add_to_name
        idaapi.set_name(ea, name, idaapi.SN_FORCE | idaapi.SN_NOCHECK)
        rule_exit(RULE_TRUE, ea, obj, name)