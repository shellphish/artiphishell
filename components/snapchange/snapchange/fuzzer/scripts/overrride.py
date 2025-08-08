import gdb

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

def overwrite_module_with_dump(dump_file_path, target_module_name):
    with open(dump_file_path, 'rb') as f:
        dumped_module_data = f.read()
    
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
        
        if current_module_name == target_module_name:
            print(current_module_name)
            start_address = int(module_struct['core_layout']['base'])
            size = int(module_struct['core_layout']['size'])

            if len(dumped_module_data) != size:
                print(f"Size mismatch! Dumped module size: {len(dumped_module_data)}, target module size: {size}")
                #return
            
            gdb.selected_inferior().write_memory(start_address, dumped_module_data)
            # Python Exception <class 'NotImplementedError'>: Setting of struct elements is not currently supported.
            # module_struct['name'] = target_module_name
            # new_size = len(dumped_module_data)
            # module_struct['core_layout']['size'] = new_size

            print(f"Overwrote {target_module_name} with data from {dump_file_path}")
            return
        
        module_list_next = module_list_next['next']
    
    print(f"Kernel module {target_module_name} not found")

class OverwriteModuleCommand(gdb.Command):
    """Overwrite a kernel module's memory with a dump file."""

    def __init__(self):
        super(OverwriteModuleCommand, self).__init__("overwrite_module", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: overwrite_module <dump_file_path> <target_module_name>")
        else:
            overwrite_module_with_dump(args[0], args[1])

OverwriteModuleCommand()
