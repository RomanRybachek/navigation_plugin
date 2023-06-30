import idaapi

from navigation_plugin.basic_analysis import *
from navigation_plugin.global_data_and_classes import *

idaapi.require("navigation_plugin.basic_analysis")
idaapi.require("navigation_plugin.global_data_and_classes")

def print_all_funcinfo():
    for k, v in ALL_FUNC_INFO.items():
        print("func:", hex(k))
        for sub_r, sub_c in v.named_funcs.items():
            print("named:", hex(sub_r), sub_c)
        for loc in v.loc_funcs:
            print("loc:", hex(loc))
        for sub in v.sub_funcs:
            print("sub:", hex(sub))
        for imp in v.import_calls:
            print("imp:", hex(imp))
        if v.strings > 0:
            print("Str:", v.strings)
        if v.global_data > 0:
            print("data:", v.global_data)
        for sw in v.switches:
            print("switch:", hex(sw))
        print()

def advanced_analysis():
    pass

def basic_analysis():

    global ALL_FUNC_INFO
    heads = idautils.Heads()

    check_deb = []
    for head in heads:                          # Go through all data and code marks.

        hdr_name    = ida_name.get_ea_name(head)
        flags       = ida_bytes.get_flags(head)

        if len(hdr_name) == 0:
            continue

        if ida_bytes.is_flow(flags) == True or hdr_name[:4] == "loc_":              # Handle local routines
            handle_loc_xref(head)
        elif hdr_name[:4] == "sub_":            # Handle custom functions
            handle_sub_xref(head)
        elif hdr_name[:4] == "jpt_":            # Handle switch
            handle_jpt_xrefs(head)
        elif ida_bytes.is_strlit(flags) == True:    # Handle strings
            handle_strings_xrefs(head)
        elif head in ALL_IMP:
            handle_imp_xrefs(head)
        elif ida_bytes.is_data(flags) == True:    # Handle strings
            handle_data_xrefs(head)
        else:
            pass
    
    named_subs, import_wraps = obtain_named_subroutines_and_import_wrappers()
    for n in named_subs:
        handle_named_sub_xref(n)
    for i in import_wraps:
        handle_imp_xrefs(i)

def init():
    global ALL_IMP
    ALL_IMP = get_all_imports()

def main():
    init()
    basic_analysis()
    print_all_funcinfo()

    # check_funcs()
    pass

class navigation_plugin_class(idaapi.plugin_t):

    flags = idaapi.PLUGIN_UNL
    comment = "This plugin helps to navigate among the large number of unexplored functions in the ida pro disassembler."
    help = ""
    wanted_name = "navigation_plugin"
    wanted_hotkey = "Ctrl+F7"

    def init(self):
        idaapi.msg("Navigation_plugin init() called!\n")
        return idaapi.PLUGIN_OK
    def run(self, arg):
        start_time = time.time()
        main()
        print("--- %s seconds ---" % (time.time() - start_time))
        pass

    def term(self):
        idaapi.msg("term() called!\n")
        pass

def PLUGIN_ENTRY():
    return navigation_plugin_class()