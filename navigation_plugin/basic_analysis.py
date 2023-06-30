import idaapi
from navigation_plugin.global_data_and_classes import *

idaapi.require("navigation_plugin.global_data_and_classes")

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
