# navigation_plugin
This plugin helps to navigate among the large number of unexplored functions in the ida pro disassembler. 

When you are reverse-engineering a huge file and don't have time to analyze every function, it would be useful to get general information about the functions and show it in their names.
- The plugin makes the names of unexplored functions (sub_*) more informative.
- It is easy to write your own rules or remove existing ones, because each rule is in its own python file and all you need to create a rule is to create a file in the rules folder with a function that has a specific name and prototype.
## Generic rule for renaming functions
The generic rule makes names like this:
> nav_loc70_sub5_named3_imp6_switch2_cycle_d10_s5

It looks long, but not every function has all the tags like this one. Shorter examples:
> nav_loc84_switch1_d1

> nav_sub1_named3_d6

> nav_imp2

> nav_loc6_imp1

> nav_loc1_cycle_s1

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
