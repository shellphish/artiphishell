# Load symbols
lx-symbols ../compiler/output/usb/bluetooth_usb_driver/

# dump module function for syscalls
dump_symbols module_init_bt_dev_ptr,module_init_bt_conn_ptr,module_init_bt_address_ptr,module_bt_process_frame_ptr rtk_1.json

# dump btusb_data and share_memory
dump_symbols data,shared_memory rtk_2.json

# dumo btusb_recv_bulk address
dump_symbols_address btusb_recv_bulk rtk_3.json

# dumo modules struct address head
dump_symbols_address modules rtk_4.json

# dumo the address of module struct for specific module
dump_modules_struct_address rtk_btusb rtk_5.json

# dump a module memory
dump_kernel_module rtk_btusb ./rtk.bin