import gdb
import json

def fix_btusb_data(file_a, btusb_data_address):
    with open(file_a, 'r') as f:
        data_a = json.load(f)

    value_map = {entry['name']: entry['value'] for entry in data_a}
    address_map = {entry['name']: entry['address'] for entry in data_a}

    for entry in data_a:
        name = entry['name']
        value = entry['value']
        address_A = int(entry['address'], 16)
        if name in value_map:
            final_address_eval = f"{hex(btusb_data_address)}"
            final_address = gdb.parse_and_eval(final_address_eval)
            print(f"final address {final_address}")
            print(f"value_B {value}")
            gdb_cmd = f"set *(unsigned long*){final_address} = {hex(address_A)}"
            print(f" -> {gdb_cmd}")
            gdb.execute(gdb_cmd)

    print(f"Restore btusb data")



class FixBtusbdataPointersCommand(gdb.Command):
    """Updates memory locations from JSON files."""

    def __init__(self):
        super(FixBtusbdataPointersCommand, self).__init__("fix_btusbdata_pointers", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("Usage: fix_btusbdata_pointers <file_a> <btuusb_data_address>")
            return
        fix_btusb_data(args[0], int(args[1] , 16))

# Register the new command
FixBtusbdataPointersCommand()
