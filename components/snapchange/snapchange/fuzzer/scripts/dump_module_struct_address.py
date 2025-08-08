import gdb
import json

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'

def color_print(text, color):
    gdb.write(color + text + Color.END + '\n')

def get_offset_of_list():
    for field in gdb.lookup_type("struct module").fields():
        if field.name == "list":
            return field.bitpos // 8
    return None

def dump_module_struct_address(module_name, output_file):
    color_print("[>] Dumping module struct",Color.MAGENTA)
    symbol_data = []
    offset_of_list = get_offset_of_list()
    module_list_head = gdb.parse_and_eval("modules")
    module_list_next = module_list_head['next']
    module_list_prev = module_list_head['prev']
    
    while module_list_next != module_list_head.address:
        computed_address = int(str(module_list_next), 16) - offset_of_list
        gdb_value = gdb.Value(computed_address)
        module_struct_pointer = (gdb_value).cast(gdb.lookup_type("struct module").pointer())
        module_struct = module_struct_pointer.dereference()
        current_module_name = module_struct['name'].string()
        
        if current_module_name == module_name:
            start_address = int(module_struct['core_layout']['base'])
            size = int(module_struct['core_layout']['size'])
            symbol_data.append({
                "name": module_name,
                "struct_address": hex(gdb_value),
                "size":hex(size),
                "start":hex(start_address)
                })

            with open(output_file, 'w') as json_file:
                json.dump(symbol_data, json_file)
            
            color_print(f"[+]{module_name} module struct address dumped to {output_file}", Color.GREEN)
            return
        module_list_next = module_list_next['next']

    color_print(f"[-]{module_name} module struct NOT found !!",Color.RED)

class DumpModuleStructAddressCommand(gdb.Command):
    """Dump a kernel module's memory to a file."""

    def __init__(self):
        super(DumpModuleStructAddressCommand, self).__init__("dump_modules_struct_address", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            color_print("Usage: dump_modules_struct_address <module_name> <output_file>", Color.CYAN)
        else:
            dump_module_struct_address(args[0], args[1])

DumpModuleStructAddressCommand()
