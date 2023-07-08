import idaapi
import ida_name
import ida_gdl
from navigation_plugin.global_data_and_classes import *

idaapi.require("navigation_plugin.global_data_and_classes")

class node:
    def __init__(self, block:ida_gdl.BasicBlock):
        self.pr_node    = None
        self.block      = block
        self.ea         = block.start_ea
        self.ch_blocks  = list(block.succs())
        # self.ch_nodes   = []
        self.ch_passed  = 0
        self.ch_max     = len(self.ch_blocks)

def tree(tree:ida_gdl.FlowChart, ea, obj:FuncInfo):

    parent_ea_chain   = []
    root            = node(tree[0])
    curr_node       = root
    deep            = 0
    
    while root.ch_passed < root.ch_max:
        # Check if graph is looped
        # print("Curr:", hex(curr_node.ea))
        # print("Childs:", end=" ")
        # for i in curr_node.ch_blocks:
        #     print(hex(i.start_ea), end=" ")
        # print()
        # print("Parents:", end=" ")
        # for i in parent_ea_chain:
        #     print(hex(i), end=" ")
        # print()

        if curr_node.ch_passed == 0:
            # print("zero")
            for n in curr_node.ch_blocks:
                if n.start_ea in parent_ea_chain or curr_node.ea == n.start_ea:
                    # print("THERE IS TRUE")
                    return True

        # Go down
        if curr_node.ch_passed < curr_node.ch_max:
            deep += 1
            deep_restr = 5000
            if deep == deep_restr:
                print("Functions at address", hex(ea), "is too difficult to detect cycles. Restriction =", deep_restr)
                obj.hard_to_analyse = True
                return False
            # print(curr_node.ch_passed, "/", curr_node.ch_max) 
            cur_child_indx      = curr_node.ch_passed
            cur_child           = curr_node.ch_blocks[cur_child_indx]
            
            child_node          = node(cur_child)
            child_node.pr_node  = curr_node

            parent_ea_chain.append(curr_node.ea)

            curr_node = child_node
        # Go up
        else:
            parent_ea_chain.pop()
            curr_node = curr_node.pr_node
            curr_node.ch_passed += 1

    return False

def detect_cycle(ea, obj:FuncInfo):
    # print(ida_name.get_ea_name(ea))
    if obj.loc_funcs_num == 0:
        return 0
    xref_from_higher = False
    for l in obj.loc_funcs:                                             # if address of xref.frm is highter than xref.to
        for xref in idautils.XrefsTo(l):                                # there could be a cycle
            if idautils.XrefTypeName(xref.type) != "Code_Near_Jump":
                continue
            if xref.frm > xref.to:
                xref_from_higher = True
                break
        if xref_from_higher == True:
            break
    if xref_from_higher == False:
        return 0
    flow_chart = ida_gdl.FlowChart(ida_funcs.get_func(ea))

    return(tree(flow_chart, ea, obj))