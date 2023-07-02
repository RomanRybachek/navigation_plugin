import idaapi
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

def tree(tree:ida_gdl.FlowChart):

    parent_ea_chain   = []
    root            = node(tree[0])
    curr_node       = root

    while curr_node.ch_passed != curr_node.ch_max:
        # Check if graph is looped
        if curr_node.ch_passed == 0:
            for n in curr_node.ch_blocks:
                if n.start_ea in parent_ea_chain:
                    return True

        # Go down
        if curr_node.ch_passed < curr_node.ch_max:
            
            cur_child_indx      = curr_node.ch_passed
            cur_child           = curr_node.ch_blocks[cur_child_indx]
            
            child_node          = node(cur_child)
            child_node.pr_node  = curr_node

            curr_node.ch_passed += 1
            parent_ea_chain.append(curr_node.ea)

            curr_node = child_node
        # Go up
        else:
            parent_ea_chain.pop()
            curr_node = curr_node.pr_node

    return False

def detect_cycle(ea, obj:FuncInfo):
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

    return(tree(flow_chart))