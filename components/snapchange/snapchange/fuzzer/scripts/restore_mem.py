import gdb
import json

def restore_memory_from_json(file_a, file_b):
    with open(file_a, 'r') as f:
        data_a = json.load(f)

    with open(file_b, 'r') as f:
        data_b = json.load(f)

    value_map = {entry['name']: entry['value'] for entry in data_b}
    address_map = {entry['name']: entry['address'] for entry in data_b}

    for entry in data_a:
        name = entry['name']
        value = entry['value']
        address_A = int(entry['address'], 16) 
        if name in value_map:
            address_B = int(address_map[name] , 16)
            value_B = int(value_map[name], 16)
            value_A = int(value , 16)
            print(f"a  > {hex(value_A)}")
            print(f"b > {hex(value_B)}")
            gdb_cmd = f"set *(unsigned long*)0x{address_A:x} = 0x{value_B:x}"
            print(gdb_cmd)
            gdb.execute(gdb_cmd)

    print(f"Restore memory locations based on {file_a} and {file_b}.")



class UpdateMemoryFromJsonCommand(gdb.Command):
    """Updates memory locations from JSON files."""

    def __init__(self):
        super(UpdateMemoryFromJsonCommand, self).__init__("restore_memory_from_json", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: restore_memory_from_json <file_a> <file_b>")
            return
        restore_memory_from_json(args[0], args[1])

# Register the new command
UpdateMemoryFromJsonCommand()
