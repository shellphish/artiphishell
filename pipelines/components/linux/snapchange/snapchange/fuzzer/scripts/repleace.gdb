# load symbols
lx-symbols

# dump module function for syscalls
dump_symbols module_init_bt_dev_ptr,module_init_bt_conn_ptr,module_init_bt_address_ptr,module_bt_process_frame_ptr intel_1.json

# dump btusb_data and share_memory
dump_symbols data,shared_memory intel_2.json

# dumo modules struct address head
dump_symbols_address modules intel_3.json

# dumo the address of module struct for specific module
dump_modules_struct_address rtk_btusb intel_4.json

# dump the module memory
dump_kernel_module btusb ./intel.bin

#overwrite module
overwrite_module ./rtk.bin btusb

# fix module struct
# relink <new_module_listhead_address> <old_module_listhead_address>

# resotre value after overwrite
restore_memory_from_json ./rtk_2.json ./intel_2.json

# update to new value after overwite
update_memory_from_json ./rtk_1.json ./intel_1.json

# fix btusb_recv_bulk
fix_btusbdata_pointers <file_a> <btuusb_data_address>

# update PTE
update_kernel_pgt <module_start_address> <module_size>