#define _GNU_SOURCE // For strdup
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libdwarf.h>
#include <dwarf.h>
#include <assert.h>

#ifdef DEBUG
#define PRINT_DEBUG(...) printf(__VA_ARGS__)
#else
#define PRINT_DEBUG(...) ((void)0)
#endif
#define printf(...) PRINT_DEBUG(__VA_ARGS__)

typedef struct
{
    Dwarf_Addr low_pc;
    Dwarf_Addr high_pc;
    char *name;
    char *call_file;
    Dwarf_Unsigned call_line;
    Dwarf_Unsigned call_column;
    Dwarf_Off die_offset;
} InlinedSubroutine;

// Function to get string attribute value
char *get_string_attr(Dwarf_Debug dbg, Dwarf_Die die, Dwarf_Half attr)
{
    Dwarf_Attribute attr_obj;
    Dwarf_Error error;
    char *string_val = NULL;

    if (dwarf_attr(die, attr, &attr_obj, &error) == DW_DLV_OK)
    {
        if (dwarf_formstring(attr_obj, &string_val, &error) == DW_DLV_OK)
        {
            // Make a copy since libdwarf memory management can be tricky
            char *result = strdup(string_val);
            dwarf_dealloc(dbg, attr_obj, DW_DLA_ATTR);
            return result;
        }
        dwarf_dealloc(dbg, attr_obj, DW_DLA_ATTR);
    }
    return NULL;
}

// Function to get unsigned attribute value
int get_unsigned_attr(Dwarf_Die die, Dwarf_Half attr, Dwarf_Unsigned *value)
{
    Dwarf_Attribute attr_obj;
    Dwarf_Error error;

    if (dwarf_attr(die, attr, &attr_obj, &error) == DW_DLV_OK)
    {
        if (dwarf_formudata(attr_obj, value, &error) == DW_DLV_OK)
        {
            return 1; // Success
        }
    }
    return 0; // Failed
}

// Function to get address attribute value
int get_addr_attr(Dwarf_Die die, Dwarf_Half attr, Dwarf_Addr *addr)
{
    Dwarf_Attribute attr_obj;
    Dwarf_Error error;

    if (dwarf_attr(die, attr, &attr_obj, &error) == DW_DLV_OK)
    {
        if (dwarf_formaddr(attr_obj, addr, &error) == DW_DLV_OK)
        {
            return 1; // Success
        }
    }
    return 0; // Failed
}

// Function to resolve abstract origin name
char *resolve_abstract_origin_name(Dwarf_Debug dbg, Dwarf_Die die)
{
    Dwarf_Attribute attr_obj;
    Dwarf_Error error;
    Dwarf_Off offset;

    if (dwarf_attr(die, DW_AT_abstract_origin, &attr_obj, &error) == DW_DLV_OK)
    {
        if (dwarf_global_formref(attr_obj, &offset, &error) == DW_DLV_OK)
        {
            // Get the referenced DIE
            Dwarf_Die ref_die;
            if (dwarf_offdie_b(dbg, offset, 1, &ref_die, &error) == DW_DLV_OK)
            {
                char *name = get_string_attr(dbg, ref_die, DW_AT_name);
                dwarf_dealloc(dbg, ref_die, DW_DLA_DIE);
                dwarf_dealloc(dbg, attr_obj, DW_DLA_ATTR);
                return name;
            }
        }
        dwarf_dealloc(dbg, attr_obj, DW_DLA_ATTR);
    }
    return NULL;
}

void process_ranges(Dwarf_Debug dbg, Dwarf_Die die, InlinedSubroutine *inlined)
{
    Dwarf_Attribute attr_obj;
    Dwarf_Error error = 0;

    if (dwarf_attr(die, DW_AT_ranges, &attr_obj, &error) == DW_DLV_OK)
    {
        Dwarf_Half form;
        dwarf_whatform(attr_obj, &form, &error);

        if (form == DW_FORM_rnglistx) // DWARF5 rnglist format
        {
            Dwarf_Unsigned rnglist_index;
            if (dwarf_formudata(attr_obj, &rnglist_index, &error) == DW_DLV_OK)
            {
                printf("DEBUG: Processing rnglist index: 0x%llx\n", (unsigned long long)rnglist_index);

                Dwarf_Rnglists_Head head_out;
                Dwarf_Unsigned count, global_offset_value_out_head;

                if (dwarf_rnglists_get_rle_head(attr_obj,
                                                form,
                                                rnglist_index, // Use rnglist_index directly, not offset_value_out
                                                &head_out,
                                                &count,
                                                &global_offset_value_out_head,
                                                &error) == DW_DLV_OK)
                {
                    printf("DEBUG: Found %llu range list entries\n", (unsigned long long)count);

                    // Process each range list entry
                    for (Dwarf_Unsigned i = 0; i < count; i++)
                    {
                        Dwarf_Addr raw1 = 0, raw2 = 0, cooked1 = 0, cooked2 = 0;
                        unsigned entrylen = 0;
                        unsigned rle_value_out = 0;
                        Dwarf_Bool debug_addr_unavailable = 0;

                        if (dwarf_get_rnglists_entry_fields_a(head_out,
                                                              i,
                                                              &entrylen,
                                                              &rle_value_out,
                                                              &raw1,
                                                              &raw2,
                                                              &debug_addr_unavailable,
                                                              &cooked1,
                                                              &cooked2,
                                                              &error) == DW_DLV_OK)
                        {
                            switch (rle_value_out)
                            {
                            case DW_RLE_end_of_list:
                                printf("        END_OF_LIST marker\n");
                                goto done_processing; // Exit the loop when we hit end of list

                            case DW_RLE_offset_pair:
                            case DW_RLE_start_end:
                            case DW_RLE_start_length:
                            case DW_RLE_startx_endx:
                            case DW_RLE_startx_length:
                                // These are actual address ranges
                                if (cooked1 != 0 || cooked2 != 0) // Valid range
                                {
                                    printf("        LOW_PC: [0x%016llx] HIGH_PC: [0x%016llx] RAW1: [0x%016llx] RAW2: [0x%016llx] ENTRYLEN: [%u] RLE_VALUE: [%u] DEBUG_ADDR_UNAVAILABLE: [%d]\n",
                                           (unsigned long long)cooked1,
                                           (unsigned long long)cooked2,
                                           (unsigned long long)raw1,
                                           (unsigned long long)raw2,
                                           entrylen,
                                           rle_value_out,
                                           debug_addr_unavailable);
#ifndef COMPLETE
                                    fprintf(stderr, "0x%016llx\n", (unsigned long long)cooked1);
#else
                                    fprintf(stderr, "0x%016llx 0x%016llx\n", (unsigned long long)cooked1, (unsigned long long)cooked2);
#endif
                                    // Store the first valid range in the inlined structure
                                    if (!inlined->low_pc)
                                    {
                                        inlined->low_pc = cooked1;
                                        inlined->high_pc = cooked2; // Assuming you have this field
                                    }
                                }
                                break;

                            case DW_RLE_base_addressx:
                            case DW_RLE_base_address:
                                printf("        BASE_ADDRESS: [0x%016llx] RLE_VALUE: [%u]\n",
                                       (unsigned long long)cooked1,
                                       rle_value_out);
#ifndef COMPLETE
                                fprintf(stderr, "0x%016llx\n", (unsigned long long)cooked1);
#else
                                fprintf(stderr, "0x%016llx 0x%016llx\n", (unsigned long long)cooked1, (unsigned long long)cooked2);
#endif
                                break;

                            default:
                                printf("        UNKNOWN RLE_VALUE: [%u]\n", rle_value_out);
                                break;
                            }
                        }
                        else
                        {
                            printf("ERROR: Failed to get range list entry fields for index %llu\n",
                                   (unsigned long long)i);
                            break;
                        }
                    }

                done_processing:
                    dwarf_dealloc_rnglists_head(head_out);
                }
                else
                {
                    printf("ERROR: Failed to get range list head for index 0x%llx\n",
                           (unsigned long long)rnglist_index);
                }
            } //
            else
            {
                printf("ERROR: Failed to get rnglist index from attribute\n");
            }
        } // if rnglist
        else if (form == DW_FORM_sec_offset) // DWARF4 style ranges
        {
            Dwarf_Off ranges_offset;
            if (dwarf_global_formref(attr_obj, &ranges_offset, &error) == DW_DLV_OK)
            {
                printf("DEBUG: Processing DWARF4 ranges at offset 0x%llx\n",
                       (unsigned long long)ranges_offset);

                Dwarf_Ranges *ranges;
                Dwarf_Signed ranges_count;

                if (dwarf_get_ranges_a(dbg, ranges_offset, die, &ranges, &ranges_count,
                                       NULL, &error) == DW_DLV_OK)
                {
                    for (Dwarf_Signed i = 0; i < ranges_count; i++)
                    {
                        if (ranges[i].dwr_type == DW_RANGES_ENTRY)
                        {
                            printf("        LOW_PC: [0x%016llx] HIGH_PC: [0x%016llx]\n",
                                   (unsigned long long)ranges[i].dwr_addr1,
                                   (unsigned long long)ranges[i].dwr_addr2);

                            if (!inlined->low_pc)
                            {
                                inlined->low_pc = ranges[i].dwr_addr1;
                                inlined->high_pc = ranges[i].dwr_addr2;
                            }
                        }
                        else if (ranges[i].dwr_type == DW_RANGES_ADDRESS_SELECTION)
                        {
                            printf("        BASE_ADDRESS: [0x%016llx]\n",
                                   (unsigned long long)ranges[i].dwr_addr2);
                        }
                    }
                    dwarf_ranges_dealloc(dbg, ranges, ranges_count);
                }
                else
                {
                    printf("ERROR: Failed to get ranges for offset 0x%llx\n",
                           (unsigned long long)ranges_offset);
                }
            }
            else
            {
                printf("ERROR: Failed to get ranges offset from attribute\n");
            }
        }
        else // dwarf4-style ranges
        {
            printf("WARNING: Unsupported ranges form: %u\n", form);
        }

        dwarf_dealloc(dbg, attr_obj, DW_DLA_ATTR);
    }
    else // Fallback to DW_AT_low_pc/DW_AT_high_pc
    {
        Dwarf_Attribute attr;
        Dwarf_Error error = 0;

        if (dwarf_attr(die, DW_AT_low_pc, &attr, &error) == DW_DLV_OK)
        {
            Dwarf_Addr low_pc = 0;
            if (dwarf_formaddr(attr, &low_pc, &error) == DW_DLV_OK)
            {
                printf("        LOW_PC: [0x%016llx]\n", (unsigned long long)low_pc);
                inlined->low_pc = low_pc;

                // Try to get high_pc as well
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);

                if (dwarf_attr(die, DW_AT_high_pc, &attr, &error) == DW_DLV_OK)
                {
                    Dwarf_Half form;
                    dwarf_whatform(attr, &form, &error);

                    if (form == DW_FORM_addr)
                    {
                        Dwarf_Addr high_pc = 0;
                        if (dwarf_formaddr(attr, &high_pc, &error) == DW_DLV_OK)
                        {
                            printf("        HIGH_PC: [0x%016llx] (absolute)\n",
                                   (unsigned long long)high_pc);
                            inlined->high_pc = high_pc;
                        }
                    }
                    else
                    {
                        // high_pc is an offset from low_pc
                        Dwarf_Unsigned high_pc_offset = 0;
                        if (dwarf_formudata(attr, &high_pc_offset, &error) == DW_DLV_OK)
                        {
                            Dwarf_Addr high_pc = low_pc + high_pc_offset;
                            printf("        HIGH_PC: [0x%016llx] (offset +0x%llx)\n",
                                   (unsigned long long)high_pc,
                                   (unsigned long long)high_pc_offset);
                            inlined->high_pc = high_pc;
                        }
                    }
                    dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
                }
            }
            else
            {
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
        }
    }
}

// Recursive function to traverse DIEs and find inlined subroutines
void traverse_dies(Dwarf_Debug dbg, Dwarf_Die die, int depth)
{
    Dwarf_Error error;
    Dwarf_Half tag;
    Dwarf_Die child_die, sibling_die;

    if (dwarf_tag(die, &tag, &error) != DW_DLV_OK)
    {
        return;
    }

    // Check if this is an inlined subroutine
    if (tag == DW_TAG_inlined_subroutine)
    {
        InlinedSubroutine inlined = {0};

        inlined.name = resolve_abstract_origin_name(dbg, die);

        if (inlined.name)
        {
            printf("    Name: %s\n", inlined.name);
        }

        // Process address ranges
        process_ranges(dbg, die, &inlined);

        // Clean up allocated strings
        if (inlined.name)
            free(inlined.name);
        if (inlined.call_file)
            free(inlined.call_file);
    }

    // Recursively process children
    if (dwarf_child(die, &child_die, &error) == DW_DLV_OK)
    {
        traverse_dies(dbg, child_die, depth + 1);
        dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
    }

    // Process siblings
    if (dwarf_siblingof(dbg, die, &sibling_die, &error) == DW_DLV_OK)
    {
        traverse_dies(dbg, sibling_die, depth);
        dwarf_dealloc(dbg, sibling_die, DW_DLA_DIE);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <executable>\n", argv[0]);
        return 1;
    }

    Dwarf_Debug dbg;
    Dwarf_Error error = 0;
    int res;

    res = dwarf_init_path(argv[1],
                          NULL,
                          0,
                          DW_DLC_READ,
                          DW_GROUPNUMBER_ANY,
                          NULL,
                          NULL,
                          &dbg,
                          NULL,
                          0,
                          NULL,
                          &error);

    if (res != DW_DLV_OK)
    {
        if (res == DW_DLV_ERROR && error)
        {
            fprintf(stderr, "Failed to initialize DWARF: %s\n",
                    dwarf_errmsg(error));
        }
        else
        {
            fprintf(stderr, "Failed to initialize DWARF (no debug info or file not found?)\n");
        }
        return 1;
    }

    printf("Parsing inlined subroutines from: %s\n\n", argv[1]);

    Dwarf_Bool is_info = 1;
    while (1)
    {
        Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
        Dwarf_Half version_stamp, address_size, header_cu_type;
        Dwarf_Die cu_die;
        Dwarf_Sig8 signature;
        Dwarf_Unsigned typeoffset;

        res = dwarf_next_cu_header_d(dbg, is_info, &cu_header_length,
                                     &version_stamp, &abbrev_offset,
                                     &address_size, NULL, NULL, &signature,
                                     &typeoffset, &next_cu_header,
                                     &header_cu_type, &error);

        if (res == DW_DLV_NO_ENTRY)
        {
            break; // No more compilation units
        }

        if (res != DW_DLV_OK)
        {
            fprintf(stderr, "Error reading CU header: %s\n",
                    dwarf_errmsg(error));
        }

        // Get the compilation unit DIE
        if (dwarf_siblingof_b(dbg, NULL, is_info, &cu_die, &error) == DW_DLV_OK)
        {
            char *cu_name = get_string_attr(dbg, cu_die, DW_AT_name);
            if (cu_name)
            {
                printf("=== Compilation Unit: %s ===\n", cu_name);
                free(cu_name);
            }
            else
            {
                printf("=== Compilation Unit (unnamed) ===\n");
            }

            traverse_dies(dbg, cu_die, 0);

            dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
        }
    }

    // Clean up
    dwarf_finish(dbg, &error);

    return 0;
}