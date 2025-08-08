#include <stdio.h>
#include <string.h> /* for memset */
#include <stddef.h> /* for offsetof */
#include <glib.h>   /* for GHashTable */
#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drutil.h"
#include "drx.h"
#include "drwrap.h"
#include "drsyms.h"
#include <assert.h>

#define MAX_OFFSETS 50000
#define BUFFER_SIZE 4096 * 4096
#define MAX_BYTES_READ 2000000

// Thread-local storage structure
typedef struct
{
    file_t trace_file;
    char buffer[BUFFER_SIZE];
    thread_id_t tid;
} thread_data_t;

// Global shared data (read-only after initialization)
static app_pc main_module_base;
static app_pc main_module_end;
static GHashTable *offset_hash; // GHashTable for O(1) offset lookups
static int offset_count = 0;
static int installed_calls = 0;
static void *offset_hash_lock;

static int threads = 0;
static void *threads_lock = NULL; // Mutex to protect access to 'threads'

// Thread-local storage
static int tls_idx;

// Configuration
char outfile[256];
char offsets_file[256];

static inline bool in_main_module(app_pc addr)
{
    return main_module_base <= addr && addr <= main_module_end;
}

// Get thread-local data
static inline thread_data_t *get_thread_data(void *drcontext)
{
    return (thread_data_t *)drmgr_get_tls_field(drcontext, tls_idx);
}

static inline void write_offset_safe(app_pc addr, void *drcontext)
{
    thread_data_t *tdata = get_thread_data(drcontext);
    if (!tdata)
        return;

    ptr_uint_t offset = (ptr_uint_t)addr;
    char hex_str[32];
    int len = dr_snprintf(hex_str, sizeof(hex_str), "0x%lx\n", offset);
    if (len > 0) {
        dr_write_file(tdata->trace_file, hex_str, len);
    }
}

// Instrumentation callback with hash table lookup
static dr_emit_flags_t event_bb_insertion(void *drcontext, void *tag,
                                          instrlist_t *bb, instr_t *instr,
                                          bool for_trace, bool translating,
                                          void *user_data)
{
    app_pc pc = instr_get_app_pc(instr);

    // Fast hash table lookup - O(1) average case
    if (in_main_module(pc) && offset_hash != NULL)
    {
        dr_mutex_lock(offset_hash_lock);
        bool found = g_hash_table_contains(offset_hash, GINT_TO_POINTER((gint)(pc - main_module_base)));
        if (found)
        {
            // Remove to avoid duplicate instrumentation
            g_hash_table_remove(offset_hash, GINT_TO_POINTER((gint)(pc - main_module_base)));
            installed_calls++;
        }
        dr_mutex_unlock(offset_hash_lock);

        if (found)
        {
            // Insert clean call before instruction
            dr_insert_clean_call(drcontext, bb, instr, (void *)write_offset_safe,
                                 false, 2, OPND_CREATE_INTPTR(pc-main_module_base), OPND_CREATE_INTPTR(drcontext));
        }
    }

    return DR_EMIT_DEFAULT;
}

// Thread initialization
static void event_thread_init(void *drcontext)
{
    thread_id_t tid = dr_get_thread_id(drcontext);
    dr_printf("\033[0;32m[+] Thread init: id=%d\033[0m\n", tid);

    // Allocate thread-local data
    thread_data_t *tdata = (thread_data_t *)dr_thread_alloc(drcontext, sizeof(thread_data_t));
    memset(tdata, 0, sizeof(thread_data_t));
    tdata->tid = tid;

    // Create thread-specific trace file
    char thread_filename[512];

    dr_mutex_lock(threads_lock);
    if (threads == 0) // first thread
        snprintf(thread_filename, sizeof(thread_filename), "%s", outfile);
    else
        snprintf(thread_filename, sizeof(thread_filename), "/dev/null");
    threads++;
    dr_mutex_unlock(threads_lock);

    tdata->trace_file = dr_open_file(thread_filename, DR_FILE_WRITE_OVERWRITE);
    if (tdata->trace_file == INVALID_FILE)
    {
        dr_printf("ERROR: Cannot create thread trace file: %s\n", thread_filename);
        dr_thread_free(drcontext, tdata, sizeof(thread_data_t));
        return;
    }

    // Store in TLS
    drmgr_set_tls_field(drcontext, tls_idx, tdata);

    dr_printf("Thread %d: trace file %s created\n", tid, thread_filename);
}

// Thread exit
static void event_thread_exit(void *drcontext)
{
    thread_data_t *tdata = get_thread_data(drcontext);
    if (!tdata)
        return;

    thread_id_t tid = tdata->tid;
    dr_printf("Thread exiting: id=%d\n", tid);

    // Close thread's trace file
    dr_close_file(tdata->trace_file);

    // Free thread-local data
    dr_thread_free(drcontext, tdata, sizeof(thread_data_t));
    drmgr_set_tls_field(drcontext, tls_idx, NULL);

    dr_printf("Thread %d: cleanup complete\n", tid);
}

// Module load event
static void event_module_load(void *drcontext, const module_data_t *mod, bool loaded)
{
    if (mod->start == dr_get_main_module()->start)
    {
        dr_printf("Main module loaded\n");
        main_module_base = mod->start;
        main_module_end = mod->end;

        // Initialize hash table for offset storage
        offset_hash = g_hash_table_new(g_direct_hash, g_direct_equal);
        if (offset_hash == NULL)
        {
            dr_printf("ERROR: Failed to create hash table\n");
            return;
        }

        // Read offsets from file
        file_t offset_file = dr_open_file(offsets_file, DR_FILE_READ);
        if (offset_file == INVALID_FILE)
        {
            dr_printf("ERROR: Cannot open %s\n", offsets_file);
            assert(false);
        }

        char *buf = (char *)dr_global_alloc(MAX_BYTES_READ);
        assert(buf);
        memset(buf, 0, MAX_BYTES_READ);

        size_t nread = dr_read_file(offset_file, buf, MAX_BYTES_READ - 1);
        assert(nread > 0 && nread < MAX_BYTES_READ - 1);
        buf[nread] = '\0'; // Null-terminate the buffer

        char *line = strtok(buf, "\n");
        while (line != NULL && offset_count < MAX_OFFSETS)
        {
            unsigned long off_i = strtoul(line, NULL, 0);

            // Insert offset into hash table
            g_hash_table_insert(offset_hash, GINT_TO_POINTER((gint)off_i), GINT_TO_POINTER((gint)off_i));

            offset_count++;
            line = strtok(NULL, "\n");
        }

        dr_close_file(offset_file);
        dr_global_free(buf, MAX_BYTES_READ);

        dr_printf("Loaded %d offsets into hash table for tracing\n", offset_count);

        if (!drmgr_register_bb_instrumentation_event(NULL, event_bb_insertion, NULL))
        {
            dr_printf("ERROR: Failed to register basic block event\n");
        }
    }
}

// Module unload event
static void event_module_unload(void *drcontext, const module_data_t *mod)
{
    // Clean up hash table when main module unloads
    if (mod->start == main_module_base && offset_hash != NULL)
    {
        dr_mutex_lock(offset_hash_lock);
        g_hash_table_destroy(offset_hash);
        offset_hash = NULL;
        dr_mutex_unlock(offset_hash_lock);
        dr_printf("Hash table cleaned up\n");
    }
}

// Process exit event
static void event_exit(void)
{
    dr_printf("Process exiting, installed calls: %d\n", installed_calls);

    // Clean up global resources
    if (offset_hash != NULL)
    {
        g_hash_table_destroy(offset_hash);
        offset_hash = NULL;
    }

    if (offset_hash_lock != NULL)
    {
        dr_mutex_destroy(offset_hash_lock);
        offset_hash_lock = NULL;
    }

    drmgr_exit();
    drutil_exit();
    drsym_exit();
    if (threads_lock != NULL)
    {
        dr_mutex_destroy(threads_lock);
        threads_lock = NULL;
    }
}

// Main entry point
DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[])
{
    // Initialize
    dr_set_client_name("Thread-Safe Function Tracer with TLS", "http://dynamorio.org/issues");

    if (!drmgr_init())
    {
        dr_fprintf(STDERR, "Failed to initialize DRMGR\n");
        dr_abort();
    }

    if (!drutil_init())
    {
        dr_fprintf(STDERR, "Failed to initialize DRUTIL\n");
        drmgr_exit();
        dr_abort();
    }

    if (drsym_init(0) != DRSYM_SUCCESS)
    {
        dr_fprintf(STDERR, "Failed to initialize DRSYMS\n");
        drutil_exit();
        drmgr_exit();
        dr_abort();
    }

    // Initialize TLS
    tls_idx = drmgr_register_tls_field();
    if (tls_idx == -1)
    {
        dr_fprintf(STDERR, "Failed to register TLS field\n");
        dr_abort();
    }

    // Initialize mutex for hash table access
    offset_hash_lock = dr_mutex_create();

    // Read configuration from environment
    char *tmp = getenv("DRTOOL_OUTFILE");
    if (!tmp)
    {
        dr_printf("Error reading outfile, defaulting to calltrace.out\n");
        strcpy(outfile, "calltrace.out");
    }
    else
        strcpy(outfile, tmp);

    tmp = getenv("OFFSETS_FILE");
    if (!tmp)
    {
        dr_printf("Error reading offsets file, defaulting to offsets.txt\n");
        strcpy(offsets_file, "offsets.txt");
    }
    else
        strcpy(offsets_file, tmp);

    dr_printf("Offsets file set to %s, output base name: %s\n", offsets_file, outfile);

    // Register events
    drmgr_register_module_load_event(event_module_load);
    drmgr_register_module_unload_event(event_module_unload);
    drmgr_register_thread_init_event(event_thread_init);
    drmgr_register_thread_exit_event(event_thread_exit);
    dr_register_exit_event(event_exit);
    // init mutex on threads id
    threads_lock = dr_mutex_create();

    // wrap execve
    dr_printf("Thread-Safe Function Tracer with TLS initialized\n");
}