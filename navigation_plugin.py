import ida_name
import ida_nalt
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
        self.switches       = set()
        self.switches_num   = 0

ALL_FUNC_INFO = {}
ALL_IMP = {}
DATA_OFFSET = 1
CODE_NEAR_CALL = 17
CODE_NEAR_JUMP = 19
ORDINARY_FLOW = 21

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

def get_all_imports(): 

    all_imports = {}
    modules_num = ida_nalt.get_import_module_qty()

    for module in range(modules_num):
        def imp_cb(ea, imp_name, ordinal):
            all_imports[ea] = imp_name
            return True
        ida_nalt.enum_import_names(module, imp_cb)
    return all_imports

def handle_loc_xref(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
        if func_info_obj == 0:                                          # If we did not find it we create new FuncInfo object
            func_info_obj = FuncInfo()
            func_info_obj.loc_funcs.add(ea)                             # FuncInfo has a set for local routines.
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})  # We add this local routine to this set.
        else:
            func_info_obj.loc_funcs.add(ea)
    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def handle_sub_xref(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
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
    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def handle_named_sub_xref(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
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
    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def handle_imp_xrefs(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
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

    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def handle_strings_xrefs(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
        if func_info_obj == 0:
            func_info_obj = FuncInfo()
            func_info_obj.strings += 1
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})
        else:
            func_info_obj.strings += 1
        pass
    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def handle_data_xrefs(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
        if func_info_obj == 0:
            func_info_obj = FuncInfo()
            func_info_obj.global_data += 1
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})
        else:
            func_info_obj.global_data += 1
        pass
    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def handle_jpt_xrefs(ea):
    def specific_part_for_xrefs_handler(func_info_obj, func_struct, ea):
        if func_info_obj == 0:                                          # If we did not find it we create new FuncInfo object
            func_info_obj = FuncInfo()
            func_info_obj.switches.add(ea)                             # FuncInfo has a set for local routines.
            ALL_FUNC_INFO.update({func_struct.start_ea:func_info_obj})  # We add this local routine to this set.
        else:
            func_info_obj.switches.add(ea)
    generic_part_for_xrefs_handler(ea, specific_part_for_xrefs_handler)

def generic_part_for_xrefs_handler(ea, add_xref_handler):
    global ALL_FUNC_INFO
    
    for xref in idautils.XrefsTo(ea):                                   # Go through all xrefs and create FuncInfo objects
        func_struct = ida_funcs.get_func(xref.frm)                      # Check if xrefs from function
        if func_struct == None:                                         
            continue
        func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)      # If it is, we are trying to get already created FuncInfo obj 
        add_xref_handler(func_info_obj, func_struct, ea)                             # And in this handler we do actions that specific for different xrefs

def is_import_wrap(ea)->bool:
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

    for head in heads:                          # Go through all data and code marks.

        hdr_name    = ida_name.get_ea_name(head)
        flags       = ida_bytes.get_flags(head)

        if len(hdr_name) == 0:
            continue
        if hdr_name[:4] == "loc_":              # Handle local routines
            handle_loc_xref(head)
            pass
        elif hdr_name[:4] == "sub_":            # Handle custom functions
            handle_sub_xref(head)
            pass
        elif hdr_name[:4] == "jpt_":            # Handle switch
            handle_jpt_xrefs(head)
            pass
        elif ida_bytes.is_strlit(flags) == True:    # Handle strings
            handle_strings_xrefs(head)
        elif head in ALL_IMP:
            handle_imp_xrefs(head)
        elif ida_bytes.is_data(flags) == True:    # Handle strings
            handle_data_xrefs(head)
            pass
        else:
            # if ida_bytes.is_data(f):
            #     print("is data", end=' ')
            # elif ida_bytes.is_func(f):
            #     print("is func", end=' ')
            # print(hdr_name)
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