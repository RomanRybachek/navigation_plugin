# navigation_plugin
This plugin helps to navigate among the large number of unexplored functions in the ida pro disassembler. 

When you are reverse-engineering a huge file and don't have time to analyze every function, it would be useful to get general information about the functions and show it in their names.
- The plugin makes the names of unexplored functions (sub_*) more informative.
- It is easy to write your own rules or remove existing ones, because each rule is in its own python file and all you need to create a rule is to create a file in the rules folder with a function that has a specific name and prototype.
## Generic rule for renaming functions
The generic rule makes names like this:
```
nav_loc70_sub5_named3_imp6_switch2_cycle_d10_s5
```
It looks long, but not every function has all the tags like this one. Shorter examples:
```
nav_loc84_switch1_d1
```
```
nav_sub1_named3_d6
```
```
nav_imp2
```
```
nav_loc6_imp1
```
```
nav_loc1_cycle_s1
```
### Tags:
**nav** - means that function has been renamed with this plugin.<br />
**loc** - shows number of local routines inside the function. It helps to determine the level of complexity of the function.<br />
**sub** - shows number of unexplored functions (that had sub_ in it's default name) inside the analysed function.<br />
**named** - shows number of functions that already have names.<br />
**imp** - shows number of imported functions.<br />
**switch** - shows number of switches inside the function.<br />
**cycle** - that tag means that the function has one or several cycles.<br />
**cycleIsPossible** - means that there was attampt to find cycle in the function, but the function is too complex to analyse.<br />
**d** - shows number of global data usage.<br />
**s** - shows number of strings usage.<br />

## Custom rules:
### Tiny_functions rule:
This rule renames functions that have less than 5 lines of asm code.<br />
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/tiny2.png" alt="drawing" width="200"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/tiny4.png" alt="drawing" width="200"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/tiny3.png" alt="drawing" width="200"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/tiny1.png" alt="drawing" width="100"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/tiny6.png" alt="drawing" width="100"/>
### Only_one_call rule:
This rule renames functions that have only one call.<br />
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/one3.png" alt="drawing" width="200"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/one2.png" alt="drawing" width="200"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/one4.png" alt="drawing" width="200"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/one1.png" alt="drawing" width="200"/>
### Same_call_several_times:
This rule renames functions that have several calls of the same function and have no other calls.<br />
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/times2.png" alt="drawing" width="150"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/times1.png" alt="drawing" width="180"/>
<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/times.png" alt="drawing" width="180"/>
### LATE_set_tag_by_string:
This rule adds tags if it found usage of specified strings. It just add to the end of the name of the function "paths" or "urls" if strings that the functions uses contain something related with paths or urls.
## How to create your own rule:
This is the folder with rules. All rules that are there can be deleted or changed. You can add your own rule to this folder.<br />

<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/folder_with_rules.png" alt="drawing" width="200"/><br />

This is an example of simple rule that do nothing. You can find it in navigation_plugin/rules/example_of_rule.py.<br />

<img src="https://github.com/RomanRybachek/navigation_plugin/blob/main/pictures_for_github/simple_rule_that_does_nothing.png" alt="drawing" width="500"/><br />

A rule must return one of these values:
```
rule_exit(RULE_TRUE, ea, obj, new_name) 
rule_exit(WEAK_RULE_TRUE, ea, obj, new_name) 
rule_exit(RULE_FALSE)
```
The function **rule_exit** changes function name in IDA and return RULE_TRUE, WEAK_RULE_TRUE or RULE_FALSE.<br />
**RULE_TRUE** - the function satisfies the conditions of the rule. The rule will be applied. Other rules will be ignored. <br />
**WEAK_RULE_TRUE** - the function satisfies the conditions of the rule. The rule will be applied, but there will be attempt to apply other rules. <br />
**RULE_FALSE** - the function does not satisfies the conditions of the rule. There will be attempt to apply other rules. <br />

The parametr obj:FuncInfo is defined in global_data_and_classes.py. It has info about all xrefs that function uses.

If you want your rule runs anyway, you can add to your rule name "LATE_" prefix. Rules with that prefix run after other rules. But your rule still must exit with ```rule_exit(RULE_TRUE, ea, obj, new_name)``` or ```rule_exit(RULE_FALSE)```.
## Installation:
Just copy navigation_plugin.py and navigation_plugin folder in %path_to_ida%\plugins.
## Usage:
Edit->Plugins->navigation_plugin
