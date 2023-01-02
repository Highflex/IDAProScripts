# Copyright Highflex 2022
# Generate a IDA runnable python script to load data from MSVC .map files
#
#
# Version 0.1a
#   - apply function name
#
# potential TODO: function types and arguments? ( need more data for this )
#

import re;
from subprocess import PIPE, Popen
import inspect

fname_container = {}

# please adjust the input parameters
input_file = "C:\\Projects\\Reverse\\TestClient-Win64-Shipping.map"
output_file = "C:\\Projects\\Reverse\\ida_load_test_map_gen.py"
undname_path = "undname.exe"

# used to rename function inside IDA
def rename_function(ea, new_name):
    """Rename a function at the specified address."""
    func = idaapi.get_func(ea)
    if func is not None:
        idaapi.set_name(ea, new_name, idaapi.SN_CHECK)

def apply_names(container):
    for name, rva_string in container.items():
        rva = int(rva_string, 16)  
        rename_function(rva, name)

# convert decorated c++ name back to be readable using undname
def undecorate_entry(entry_name):
    command = "ntpq -p"
    with Popen([undname_path, entry_name], stdout=PIPE, stderr=None, shell=True) as process:
        output = process.communicate()[0].decode("utf-8")
        return output.split("is :- ")[1].split('"')[1]

def process_line(line):
    global fname_container
    splitted = line.split()
    if len(splitted) > 0:
        address = splitted[0]
        #if(address == "0001:003bd260"):
        if address != "0000:00000000":
            identifier = splitted[1]
            # we only want entries that are C++ decorated names
            if(identifier.find('?') == 0):
                rva = splitted[2]

                # get undecorated result, not needed for IDA. just here for understanding
                #undecorated_name = undecorate_entry(identifier)
                # split out function type, name and parameter types
                #function_name = undecorated_name.split("__cdecl ")[1].split("(")[0]
                #function_type = undecorated_name.split("__cdecl ")[0].split()[-1] # for now just use last element
                #parameter_types = undecorated_name.split("__cdecl ")[1].split("(")[1].split(")")[0].split(",")
                #print("Adding Function: " + rva + "\n")

                # IDA identifies "< > -" as bad characters so adjust it
                '''
                if("<" in identifier):
                    identifier = identifier.replace("<", "")
                if(">" in identifier):
                    identifier = identifier.replace(">", "")
                if("-" in identifier):
                    identifier = identifier.replace("-", "")
                '''
                fname_container.update({identifier : rva}) 
            
# function finds the beginning of parse section in a map
parse_block_found = False
def read_line(line):
    global parse_block_found

    # we have found the parse block, process the line now
    if parse_block_found:
        process_line(line)
    else: # see if we have reached the right section
        splitted = line.split()
        if len(splitted) >= 4 and splitted[0] == "Address":
            print("Start Offset found!\n")
            parse_block_found = True

# the main function used
def gen_ida_script_from_map():
    global fname_container
    
    # open the specified map file
    with open(input_file) as f:
        for line in f:
            read_line(line)

    # now generate the script
    f = open(output_file, "w")

    f.write("# Copyright Highflex 2022\n")
    f.write("# GENERATED FILE BY MAP2IDA\n")
    f.write("import idaapi\n")

    # write result container
    f.write("\n")
    f.write("fname_container = ")
    f.write(str(fname_container))
    f.write("\n")

    # write functions
    f.write("\n")
    f.write(inspect.getsource(rename_function))
    f.write("\n")

    f.write("\n")
    f.write(inspect.getsource(apply_names))
    f.write("\n")

    f.write("\n")
    f.write("apply_names(fname_container)\n")
    f.write('print("Function Names applied!")')
    f.write("\n")
    
    f.close()

print("Generating IDA Script....")
gen_ida_script_from_map()
print("Script: " + output_file + " has been generated!\n")
