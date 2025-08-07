import gdb

def get_offset_of_list():
    for field in gdb.lookup_type("struct module").fields():
        if field.name == "list":
            return field.bitpos // 8
    return None

def sym_finder(module_name, sym_name):
    # Read dumped kernel module
    
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
            print(current_module_name)
            # Get module's start address and size
            start_address = int(module_struct['core_layout']['base'])
            size = int(module_struct['core_layout']['size'])
            print(f"start_address: {hex(start_address)}, target module size: {size}")
            return
        
        module_list_next = module_list_next['next']
    
    print(f"Kernel module {target_module_name} not found")

class OverwriteModuleCommand(gdb.Command):
    """Overwrite a kernel module's memory with a dump file."""

    def __init__(self):
        super(OverwriteModuleCommand, self).__init__("sym_finder", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: sym_finder <target_module_name> <target_sym_name>")
        else:
            sym_finder(args[0],args[0])

OverwriteModuleCommand()
