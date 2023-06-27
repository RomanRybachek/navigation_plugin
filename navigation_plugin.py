import ida_name
import ida_kernwin
import idautils
import ida_funcs
import idaapi
import time
import idc
import ida_bytes
import ida_xref


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
        # main()
        print("hello")
        print("--- %s seconds ---" % (time.time() - start_time))
        pass

    def term(self):
        idaapi.msg("term() called!\n")
        pass

def PLUGIN_ENTRY():
    return navigation_plugin_class()