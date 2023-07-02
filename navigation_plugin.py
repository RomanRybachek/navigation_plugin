import idaapi

from navigation_plugin.basic_analysis import *
from navigation_plugin.global_data_and_classes import *
from navigation_plugin.rename_rules import *

idaapi.require("navigation_plugin.basic_analysis")
idaapi.require("navigation_plugin.global_data_and_classes")
idaapi.require("navigation_plugin.rename_rules")

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
    # Что должен мочь advanced analysis?
    # - Находить циклы.
    # - Находить xrefы на unk_ данные.
    # - Находить вызовы через регистры: call rax:

    # хм... Чет как будто функционал не стоит реализации. 
    pass

def basic_analysis():

    global ALL_FUNC_INFO
    heads = idautils.Heads()

    check_deb = []
    for head in heads:                                                  # Go through all data and code marks.

        hdr_name    = ida_name.get_ea_name(head)
        flags       = ida_bytes.get_flags(head)

        if len(hdr_name) == 0:
            continue

        if ida_bytes.is_flow(flags) == True or hdr_name[:4] == "loc_":  # Handle local routines
            handle_loc_xref(head)
        elif hdr_name[:4] == "sub_" or hdr_name[:4] == "nav_":          # Handle custom functions
            handle_sub_xref(head)
        elif hdr_name[:4] == "jpt_":                                    # Handle switches
            handle_jpt_xrefs(head)
        elif ida_bytes.is_strlit(flags) == True:                        # Handle strings
            handle_strings_xrefs(head)
        elif head in ALL_IMP:                                           # Handle imports (but not import wrappers)
            handle_imp_xrefs(head)
        elif ida_bytes.is_data(flags) == True:                          # Handle data
            handle_data_xrefs(head)
        else:
            pass
    
    named_subs, import_wraps = obtain_named_subroutines_and_import_wrappers()
    for n in named_subs:
        handle_named_sub_xref(n)
    for i in import_wraps:                                              # Import wrappers are functions that only have
        handle_imp_xrefs(i)                                             # jmp instruction to address of imported function

    all_funcs = idautils.Functions()
    for f in all_funcs:
        if f not in ALL_FUNC_INFO:
            ALL_FUNC_INFO.update({f:FuncInfo()})

    setup_FuncInfo_objects()

def init():
    global ALL_IMP
    ALL_IMP = get_all_imports()

def fini():
    global ALL_IMP
    global ALL_FUNC_INFO

    ALL_FUNC_INFO.clear()
    ALL_IMP.clear()

def main():
    init()
    basic_analysis()
    run_rename_rules_for_all_fuctions()
    fini()

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
