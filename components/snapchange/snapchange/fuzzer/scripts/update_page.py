import gdb
BASE_ADDRESS = 0xffff000000000000

NX_MASK = ~(1 << 63)
NX_BIT = 1 << 63
MASK_64BIT = 0xFFFFFFFFFFFFFFFF

class UpdateKernelPGTCommand(gdb.Command):
     
    def __init__(self):
        super(UpdateKernelPGTCommand, self).__init__("update_kernel_pgt", gdb.COMMAND_DATA)
        self.pgd_index = 0
        self.pud_index = 0
        self.pmd_index = 0
        self.pte_index = 0
        self.address = []
        self.start_address = 0
        self.size = 0

    def write_pte(self, address, modified_pte):
        """Write the modified PTE back to the specified address using GDB."""
        gdb.selected_inferior().write_memory(address, modified_pte, 8)  # Assuming 64-bit PTE

    def is_page_executable(self,entry):
        return not(entry &  NX_BIT)

    def make_entry_executable(self,entry):
        inverted_nx_bit = ~NX_BIT & MASK_64BIT
        return entry & inverted_nx_bit

    def create_address_list(self,file_path):
        with open(file_path , 'r') as file:
            for line in file:
                self.address.append(int(line.strip(),16))
        
    def reconstruct_virtual_address(self,level):
        VA = BASE_ADDRESS
        match int(level):
            case 1:
                VA += self.pgd_index << 39
                VA += self.pud_index << 30
            case 2:
                VA += self.pgd_index << 39
                VA += self.pud_index << 30
                VA += self.pmd_index << 21
            case 3:
                VA += self.pgd_index << 39
                VA += self.pud_index << 30
                VA += self.pmd_index << 21
                VA += self.pte_index << 12
        return VA

    def verbose_print(*args, verbose=True, **kwargs):
        if verbose:
            print(*args, **kwargs)

    def is_page_present(self,pte_value):
        return pte_value & 0x1 == 1

    def extract_address(self, entry, type_name):
        address = (entry & 0x0000fffffffff000)
        return address.cast(gdb.lookup_type(type_name).pointer())

    def is_bit_8_set(self,entry):   
        return (entry & (1 << 7)) != 0

    def print_final_page(self,entry,level):
        need_update = False
        if self.is_page_present(entry):
            phys_address = (int(entry) & 0x0000fffffffff000) # extrar physical address
            gdb_s = str(phys_address)+" + 0xffffffff80000000" # convert the physical address to V
            virt_address_of_page = gdb.parse_and_eval(gdb_s)
            vt_begining = self.reconstruct_virtual_address(level) # recreate virtual address
            
            match int(level): # calculate page size base on page table entry
                case 1: # 1G
                    vt_end = vt_begining+0x40000000
                    self.verbose_print(f"[+]1G pagesize , entry : {entry}, phy : {hex(phys_address)} ,  start of : {hex(vt_begining)} to : {hex(vt_end)}")
                case 2: # 2M
                    vt_end = vt_begining+0x200000
                    self.verbose_print(f"[+]2M pagesize , entry : {entry}, phy : {hex(phys_address)} ,  start of : {hex(vt_begining)} to : {hex(vt_end)}")
                case 3: # 4K
                    vt_end = vt_begining+0x1000
                    self.verbose_print(f"[+]4K pagesize , entry : {entry}, phy : {hex(phys_address)} ,  start of : {hex(vt_begining)} to : {hex(vt_end)}")
            
            #if vt_begining == self.start_address:
            if self.start_address <= vt_begining < (self.start_address+self.size):
                self.verbose_print(f"This page has to be update")
                need_update = True
            return need_update

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 2:
            self.verbose_print("usage: update_kernel_pgt <module_start_address> <module_size>")
            return
        self.start_address = int(args[0] , 16)
        self.size = int(args[1] , 16)

        pgd = gdb.parse_and_eval("&init_top_pgt").cast(gdb.lookup_type("pgd_t ").pointer())
        for i in range(512,-1,-1):
            self.pgd_index = i
            try:
                entry = pgd[i]["pgd"]
                if self.is_page_present(entry):
                    pud_base = self.extract_address(entry, "pud_t")
                    virtual_address = gdb.parse_and_eval("0x%x + 0xffff888000000000" % pud_base)
                    self.walk_pud(virtual_address)
            except gdb.MemoryError as e:
                continue
    
    def walk_pud(self, pud_base_addr):
        pud_base = pud_base_addr.cast(gdb.lookup_type("pud_t").pointer())
        for i in range(512,-1,-1):
            self.pud_index = i
            try:
                entry = pud_base[i]["pud"]
                if self.is_page_present(entry):
                    if(self.is_bit_8_set(entry)):
                        self.print_final_page(entry,2)
                        continue
                    pmd_base = self.extract_address(entry, "pmd_t")
                    virtual_address = gdb.parse_and_eval("0x%x + 0xffff888000000000" % pmd_base)
                    self.walk_pmd(virtual_address)
            except gdb.MemoryError:
                continue

    def walk_pmd(self, pmd_base_addr):
        pmd = pmd_base_addr.cast(gdb.lookup_type("pmd_t").pointer())
        for i in range(512,-1,-1):
            self.pmd_index = i
            try:
                entry = pmd[i]["pmd"]
                if self.is_page_present(entry):
                    if(self.is_bit_8_set(entry)):
                        self.print_final_page(entry,2)
                        continue
                    pte_base = self.extract_address(entry, "pte_t")
                    virtual_address = gdb.parse_and_eval("0x%x + 0xffff888000000000" % pte_base)
                    self.walk_pte(virtual_address)
            except gdb.MemoryError as e:
                continue

    def walk_pte(self, pte_base_addrr):
        pte = pte_base_addrr.cast(gdb.lookup_type("pte_t").pointer())
        for i in range(512,-1,-1):
            self.pte_index = i
            try:
                entry = pte[i]["pte"]
                if self.is_page_present(entry):
                    phys_address = (int(entry) & 0x000ffffffffff000)
                    gdb_s = str(phys_address)+" + 0xffff888000000000"
                    virt_address_of_page = gdb.parse_and_eval(gdb_s)
                    is_in_range = self.print_final_page(entry,3)
                    if is_in_range:
                        is_exec = self.is_page_executable(entry)
                        if is_exec:
                            print("The page is executable")
                        else:
                            modified_entry = self.make_entry_executable(entry)
                            pte_address = pte[i].address
                            gdb.execute(f"set *(unsigned long *){pte_address} = {hex(modified_entry)}")
                            print("The page is NOT executable")
            except gdb.MemoryError as e:
                #print(f"MemoryError at PTE index {i}: {e}")
                continue

UpdateKernelPGTCommand()
