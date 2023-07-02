import idaapi
import ida_gdl
import ida_kernwin
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
from navigation_plugin.global_data_and_classes import *
from navigation_plugin.cycles_detection import *

idaapi.require("navigation_plugin.cycles_detection")

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

# def generic_part_for_xrefs_handler(ea, add_xref_handler):
#     global ALL_FUNC_INFO
    
#     for xref in idautils.XrefsTo(ea):                                   # Go through all xrefs and create FuncInfo objects
#         func_struct = ida_funcs.get_func(xref.frm)                      # Check if xrefs from function
#         if func_struct == None:                                         
#             continue
#         func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)      # If it is, we are trying to get already created FuncInfo obj 
#         add_xref_handler(func_info_obj, func_struct, ea)                             # And in this handler we do actions that specific for different xrefs

def generic_part_for_xrefs_handler(ea, add_xref_handler):
    global ALL_FUNC_INFO
    xref_places = set()

    for xref in idautils.XrefsTo(ea):   # Go through all xrefs 
        if is_func(xref.frm) == False:  # Check if it is from functions
            continue
        xref_places.add(xref.frm)       # Collect xrefs only from different locations
        # (there are cases then two xrefs pointing the same target data from one disasm line)

    for xref in xref_places:
        func_struct = ida_funcs.get_func(xref)                      
        func_info_obj = ALL_FUNC_INFO.get(func_struct.start_ea, 0)  
        add_xref_handler(func_info_obj, func_struct, ea)  # In this handler we do actions that specific for different xrefs

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
        func_name = ida_name.get_ea_name(f)
        if func_name[:4] == "sub_" or func_name[:4] == "nav_":
            continue
        if is_import_wrap(f) == True:
            import_wrappers.append(f)
        else:
            named_subs.append(f)
    return named_subs, import_wrappers

def setup_FuncInfo_objects():
    global ALL_FUNC_INFO
    for ea, obj in ALL_FUNC_INFO.items():
        func_t_obj                  = ida_funcs.get_func(ea)
        obj.size                    = func_t_obj.size()

        obj.loc_funcs_num           = len(obj.loc_funcs)
        obj.has_cycle               = detect_cycle(ea, obj)
        for imp, count in obj.import_calls.items():
            obj.import_calls_num += count

        for sub, count in obj.sub_funcs.items():
            obj.sub_funcs_num += count

        for named, count in obj.named_funcs.items():
            obj.named_funcs_num += count

        obj.internal_calls          = obj.sub_funcs_num + obj.named_funcs_num
        obj.calls                   = obj.import_calls_num + obj.internal_calls

        obj.switches_num            = len(obj.switches)