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

def dump_symbols_to_json_file(symbol_list, json_file_name):
    color_print("[>] Dumping address and value of symbols",Color.MAGENTA)
    symbol_data = []

    for symbol_name in symbol_list:
        try:
            symbol = gdb.lookup_global_symbol(symbol_name)
            if symbol is None:
                symbol = gdb.lookup_static_symbol(symbol_name)
                if symbol is None:
                    continue

            try:
                symbol_value = symbol.value()
                symbol_address = int(symbol_value.address)
                address_str = hex(symbol_address)
            except gdb.MemoryError:
                color_print(f"[*]{symbol_name} address is {address_str} , the valus is 0x00" , Color.BLUE)
                symbol_data.append({
                "name": symbol_name,
                "address": address_str,
                "value": "0x0"  # Using the dereferenced value or "0x0"
                })
                continue
                
            if not symbol_value :
                actual_value = hex(0)
            else:
                try:
                    core_type = symbol.type.strip_typedefs()
                    if core_type.code == gdb.TYPE_CODE_PTR and core_type.target().code == gdb.TYPE_CODE_PTR:
                        #print("is a pointer to pointer")
                        actual_value = gdb.parse_and_eval(f"*({symbol_name})")
                    elif core_type.code == gdb.TYPE_CODE_PTR:
                        #print("is a pointer")
                        actual_value = gdb.parse_and_eval(f"({symbol_name})")
                    else:
                        #print("is a val")
                        actual_value = gdb.parse_and_eval(f"({symbol_name})")

                    actual_value = str(actual_value).split(' ')[0] if ' ' in str(actual_value) else str(actual_value)
                except gdb.MemoryError:
                    actual_value = "0x0"  # Handle NULL or uninitialized pointers
                except Exception as e:
                    actual_value = "0x0"  # Handle NULL pointers
            color_print(f"[*]{symbol_name} address is {address_str} , the valus is {str(actual_value)}", Color.BLUE)
            symbol_data.append({
                "name": symbol_name,
                "address": address_str,
                "value": str(actual_value)  # Using the dereferenced value or "0x0"
            })
        except Exception as e:
            color_print(f"An error occurred while processing {symbol_name}: {e}" , Color.RED)

    color_print(f"[+]symbols address dumped to {json_file_name}" , Color.GREEN)
    with open(json_file_name, 'w') as json_file:
        json.dump(symbol_data, json_file)


class DumpSymbolsCommand(gdb.Command):
    """Dump symbol information to a JSON file."""

    def __init__(self):
        super(DumpSymbolsCommand, self).__init__("dump_symbols", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) < 2:
            color_print("Usage: dump_symbols <symbol1,symbol2,...> <json_file>" , Color.CYAN)
        else:
            symbols = args[0].split(",")
            json_file_name = args[1]
            dump_symbols_to_json_file(symbols, json_file_name)

DumpSymbolsCommand()
