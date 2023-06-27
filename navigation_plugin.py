import ida_name
import ida_lines
import ida_kernwin
import idautils
import ida_funcs
import idaapi
import time
import idc
import ida_bytes
import ida_xref

class FuncInfo:
    def __init__(self):
        self.size           = 0
        self.calls          = 0
        self.import_calls   = {} # ea:count
        self.internal_calls = 0
        self.strings        = 0
        self.global_data    = 0
        self.loc_funcs      = set()
        self.sub_funcs      = {} # ea:count
        self.named_funcs    = {} # ea:count

ALL_FUNC_INFO = {}
DATA_OFFSET = 1
CODE_NEAR_CALL = 17
CODE_NEAR_JUMP = 19
ORDINARY_FLOW = 21

def print_all_funcinfo():
    for k, v in ALL_FUNC_INFO.items():
        print("func:", hex(k))
        for sub_r, sub_c in v.named_funcs.items():
            print("named:", hex(sub_r), sub_c)
        print()


def advanced_analysis():
    pass

def handle_loc_xref(ea):
    global ALL_FUNC_INFO

    for xref in idautils.XrefsTo(ea):                                   # Go through all xrefs pointing to this local routine
        func_struct = ida_funcs.get_func(xref.frm)                      # Try to get function from xref
        if func_struct == None:                                         # If it is not a function go ahead
            continue
        func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)      # If it is a function we try to find it in the global dict
        if func_info_obj == 0:                                          # If we did not find it we create new FuncInfo object
            func_info_obj = FuncInfo()
            func_info_obj.loc_funcs.add(ea)                             # FuncInfo has a set for local routines.
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})  # We add this local routine to this set.
        else:
            func_info_obj.loc_funcs.add(ea)

def handle_sub_xref(ea):
    global ALL_FUNC_INFO

    for xref in idautils.XrefsTo(ea):                                   # Go through all xrefs pointing to this subroutine 
        func_struct = ida_funcs.get_func(xref.frm)                      # Try to get function from xref
        if func_struct == None:                                         # If it is not a function go ahead
            continue
        print(hex(func_struct.start_ea))
        func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)
        if func_info_obj == 0:
            func_info_obj = FuncInfo()
            func_info_obj.sub_funcs.update({ea:1})                      
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})
        else:
            count = func_info_obj.sub_funcs.get(ea, 0)
            if count == 0:
                func_info_obj.sub_funcs.update({ea:1})
            else:
                func_info_obj.sub_funcs.update({ea:count + 1})

def handle_named_sub_xref(ea):
    global ALL_FUNC_INFO

    for xref in idautils.XrefsTo(ea):                                   
        func_struct = ida_funcs.get_func(xref.frm)                      
        if func_struct == None:                                         
            continue
        print(hex(func_struct.start_ea))
        func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)
        if func_info_obj == 0:
            func_info_obj = FuncInfo()
            func_info_obj.named_funcs.update({ea:1})                      
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})
        else:
            count = func_info_obj.named_funcs.get(ea, 0)
            if count == 0:
                func_info_obj.named_funcs.update({ea:1})
            else:
                func_info_obj.named_funcs.update({ea:count + 1})

def handle_imp_wraps_xrefs(ea):
    global ALL_FUNC_INFO

    for xref in idautils.XrefsTo(ea):                                   
        func_struct = ida_funcs.get_func(xref.frm)                      
        if func_struct == None:                                         
            continue
        print(hex(func_struct.start_ea))
        func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)
        if func_info_obj == 0:
            func_info_obj = FuncInfo()
            func_info_obj.import_calls.update({ea:1})                      
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})
        else:
            count = func_info_obj.import_calls.get(ea, 0)
            if count == 0:
                func_info_obj.import_calls.update({ea:1})
            else:
                func_info_obj.import_calls.update({ea:count + 1})

def is_import_wrap(ea):
    func_struct = ida_funcs.get_func(ea)
    if func_struct.size() < 10:
        disasm_line = idc.GetDisasm(ea)
        if disasm_line.find("_imp_") != -1:
            # print(disasm_line)
            return True
    return False

def obtain_named_subroutines_and_import_wrappers():

    all_funcs = idautils.Functions()
    named_subs = []
    import_wrappers = []
    for f in all_funcs:
        func_name = ida_name.get_name(f)
        if func_name[:4] == "sub_":
            continue
        if is_import_wrap(f) == True:
            import_wrappers.append(f)
        else:
            named_subs.append(f)
    return named_subs, import_wrappers

def basic_analysis():

    global ALL_FUNC_INFO
    heads = idautils.Heads()

    for head in heads:

        hdr_name = ida_name.get_ea_name(head)
        if len(hdr_name) == 0:
            continue
        if hdr_name[:4] == "loc_":
            handle_loc_xref(head)
        elif hdr_name[:4] == "sub_":
            handle_sub_xref(head)
    
    named_subs, import_wraps = obtain_named_subroutines_and_import_wrappers()
    for n in named_subs:
        handle_named_sub_xref(n)
    for i in import_wraps:
        handle_imp_wraps_xrefs(i)


def main():
    basic_analysis()
    # print_all_funcinfo()

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