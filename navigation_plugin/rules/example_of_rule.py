# This is example of rule for navigation plugin.
# First, we need to import all the necessary modules:

import idaapi
from navigation_plugin.global_data_and_classes import *
idaapi.require("navigation_plugin.global_data_and_classes")

# The rule must have this prototype:

def rule_entry(ea, obj:FuncInfo):

    # return rule_exit(RULE_TRUE, ea, obj, new_name) 
    # The rule has been applied. There will be no attempt to apply other rules

    # return rule_exit(WEAK_RULE_TRUE, ea, obj, new_name) 
    # The rule has been applied, but it has low priority and there will be attempt to apply other rules

    return rule_exit(RULE_FALSE) # The rule is not applied, will be attempt to apply other rules
 

# Parameters:
# ea - address of the function that we will rename
# obj - object of the function. It contains info about the function. 
# It is declarated in global_data_and_classes.py and you should use it for writing your rules.

# Return values:
# The rule must return the result of the rule_exit(...) when it finishes its work.
#
# If the rule has not been applied it must to set first parameter of rule_exit to RULE_FALSE.
# In this case the other parameters are not needed.
#
# If the rule has been applied and you do not want other rules to change the name of the function,
# you must return rule_exit(RULE_TRUE, ea, obj, new_name). In this case rule_exit will rename function
# to new name that you created for it.
#
# If the rule has been applied but you want other rules can change the name of the function, you must
# return rule_exit(WEAK_RULE_TRUE, ea, obj, new_name)

# The late rules:
# 
# The late rules will be applied after all rules has been applied.
# There will be an attempt to apply all late rules in any case. If you want to create late rule
# your rule must have LATE_ prefix in its name.
# If late rule ends with success it must return rule_exit(RULE_TRUE, ea, obj, new_name), but
# there will still be an attempt to apply other late rules. If late rule fails it is not necessary 
# to return anything.