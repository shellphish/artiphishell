import gdb

def cleanup_address(address):
    return str(address).split(' ')[0]


def fix_list(new_hlist_address,old_hlist_address):
    module_list_head = gdb.parse_and_eval("modules")
    module_list_next = module_list_head['next']
    module_list_prev = module_list_head['prev']

    print(f"root : {module_list_head.address}")
    
    while module_list_next != module_list_head.address:
        print(f"next : {module_list_next} add : {module_list_next.address}")
        if int(str(module_list_next), 16) == int(str(old_hlist_address), 16):
            print(f"The next was the old one")
            cmd_next = "set ((struct list_head *){})->next = (struct list_head *){}".format(cleanup_address(module_list_next.address), new_hlist_address)
            print(f"cmd 1 :{cmd_next}")
            gdb.execute(cmd_next)
            break
        module_list_next = module_list_next['next']

    module_list_head = gdb.parse_and_eval("modules")
    module_list_next = module_list_head['next']
    module_list_prev = module_list_head['prev']

    print(f"root : {module_list_head.address}")
    while module_list_prev != module_list_head.address:
        print(f"prev : {module_list_prev} add : {module_list_prev.address}")
        if int(str(module_list_prev), 16) == int(str(old_hlist_address), 16):
            print(f"The prev was the old one")
            cmd_next = "set ((struct list_head *){})->prev = (struct list_head *){}".format(cleanup_address(hex(int(str(module_list_prev.address), 16)-0x8)), new_hlist_address)
            print(f"cmd 2 :{cmd_next}")
            gdb.execute(cmd_next)
            break
        module_list_prev = module_list_prev['prev']

class UpdateModulesStruct(gdb.Command):
     
    def __init__(self):
        super(UpdateModulesStruct, self).__init__("update_modules_struct", gdb.COMMAND_DATA)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            print("usage: update_modules_struct <new_module_listhead_address> <old_module_listhead_address>")
            return
        else:
            fix_list(args[0], args[1])


UpdateModulesStruct()
