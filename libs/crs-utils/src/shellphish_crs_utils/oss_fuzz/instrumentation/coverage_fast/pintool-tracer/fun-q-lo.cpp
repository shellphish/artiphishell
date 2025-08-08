#include <fstream>
#include <cstdlib>
#include <cstddef>
#include <unistd.h>
#include <set>
#include <cassert>
#include <csignal>
#include "pin.H"
#include <iostream>
#include <tuple>
#include <string>
#include <libgen.h>
#include <fcntl.h>

using std::cerr;
using std::endl;
using std::hex;
using std::istream;
using std::ofstream;
using std::string;

#define MAX_STR_LEN 256

char *cur_input = nullptr;
int cur_idx;
char **fake_argv;

char cur_outfile_name[MAX_STR_LEN];

std::ofstream instr_offsets;
std::set<ADDRINT> instr_offsets_set;
unsigned long long installed_hook = 0;
bool offsetsExternallyProvided = false;
bool layout_not_dumped = true;
BUFFER_ID bufId;

TLS_KEY mlog_key;

#define NUM_BUF_PAGES 1

static struct sigaction old_action;

VOID UnregisterSigAbortHandler()
{
    struct sigaction act;
    act.sa_handler = SIG_DFL; // set to default handler
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;

    // Apply it to SIGABRT
    if (sigaction(SIGABRT, &act, &old_action) != 0)
    {
        perror("[PINTOOL] sigaction failed");
    }
    else
    {
        fprintf(stderr, "[PINTOOL] SIGABRT handler reset to default\n");
    }
}

struct CALLS
{
    ADDRINT pc;
};

struct IND
{
    ADDRINT pc;
    ADDRINT target;
};

// define macros for debugging
#define PRINT_DEBUG(...)                                              \
    do                                                                \
    {                                                                 \
        if (KnobDebugMode.Value())                                    \
        {                                                             \
            fprintf(stderr, "[*DEBUG*] %s:%d: ", __FILE__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                             \
        }                                                             \
    } while (0)

std::set<ADDRINT> inlined;
std::set<ADDRINT> offsets;
// KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "output", "execution_trace", "output file");
KNOB<bool> KnobTraceCalls(KNOB_MODE_WRITEONCE, "pintool", "trace_calls", "true", "trace calls to routines in the binary, or trace indirect control flow instructions");
KNOB<bool> KnobTraceInlines(KNOB_MODE_WRITEONCE, "pintool", "trace_inlined", "true", "trace inlined functions calls");
KNOB<std::string> KnobAddressList(KNOB_MODE_WRITEONCE, "pintool", "addresses", "none", "offsets to be hooked");
KNOB<bool> KnobInterceptSignals(KNOB_MODE_WRITEONCE, "pintool", "intercept_signals", "true", "install custom signal handlers");
KNOB<bool> KnobDebugMode(KNOB_MODE_WRITEONCE, "pintool", "debug_mode", "false", "debug the tool");
KNOB<string> KnobInlinesOffsetsPath(KNOB_MODE_WRITEONCE, "pintool", "inlines_path", "none", "path to the inlines offsets file");
KNOB<string> KnobOutput(KNOB_MODE_WRITEONCE, "pintool", "output", ".", "base path where to store the output file");
KNOB<bool> KnobSuppressOuput(KNOB_MODE_WRITEONCE, "pintool", "suppress_stdout_stderr", "false", "suppress output by harness");

ADDRINT BINARY_BASE = 0x0;
ADDRINT BINARY_END = 0xffffffffffffffff;

// ############### CALLBACKS ###############################à

inline bool inTheMainBinary(ADDRINT pc)
{
    return (pc >= BINARY_BASE && pc <= BINARY_END);
}

PIN_FAST_ANALYSIS_CALL VOID log(ADDRINT pc)
{
    if (inTheMainBinary(pc))
    {
        std::ofstream *outputFile = static_cast<std::ofstream *>(PIN_GetThreadData(mlog_key, PIN_ThreadId()));
        *outputFile << "0x" << hex << pc - BINARY_BASE << "\n";
    }
}

PIN_FAST_ANALYSIS_CALL VOID logIndirect(ADDRINT pc, ADDRINT target)
{
    if (inTheMainBinary(pc))
    {
        std::ofstream *outputFile = static_cast<std::ofstream *>(PIN_GetThreadData(mlog_key, PIN_ThreadId()));
        *outputFile << "0x" << hex << pc - BINARY_BASE << ",0x" << hex << target << "\n";
        // *outputFile << "0x" << hex << pc << ",0x" << hex << target << "\n";
    }
}

VOID onError(){
    fprintf(stderr, "\033[0;32m[++++] INPUT %s crashed the harness\n\033[0m", cur_input);
    PIN_ExitApplication(0);
}

// ###########################################################


VOID Mov0raxRet(ADDRINT addr)
{
    asm("mov $0x0, %rax");
    asm("ret");
}

inline bool sanity_check(INS ins)
{
    if (KnobDebugMode.Value())
    {
        ADDRINT offset = INS_Address(ins) - BINARY_BASE;
        if (instr_offsets_set.find(offset) != instr_offsets_set.end())
        {
            return 1;
        }
    }
    return 0;
}

inline bool keepTrack(INS ins)
{
    if (KnobDebugMode.Value())
    {
        instr_offsets << hex << INS_Address(ins) - BINARY_BASE << endl;
        instr_offsets_set.insert(INS_Address(ins) - BINARY_BASE);
    }
    installed_hook++;
    return 0;
}

VOID IND_INST(INS ins)
{
    if (sanity_check(ins))
        return;
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)logIndirect, IARG_ADDRINT, INS_Address(ins), IARG_BRANCH_TARGET_ADDR, IARG_END);
    keepTrack(ins);
}

// instrument call instructions -> This routine assumes you check whether the instruction is a call or not BEFORE calling it (precondition)
VOID CALL_INST(INS ins)
{
    if (sanity_check(ins))
        return;

    if (INS_IsDirectControlFlow(ins)) // DIRECT CALL
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log, IARG_ADDRINT, INS_DirectControlFlowTargetAddress(ins), IARG_END);
    }
    else // INDIRECT CALL
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log, IARG_BRANCH_TARGET_ADDR, IARG_END);
    }

    keepTrack(ins);
}

VOID CALLSITE_INST(INS ins)
{
    if (sanity_check(ins))
        return;

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)log, IARG_ADDRINT, INS_Address(ins), IARG_END);

    keepTrack(ins);
}

// we assume this function will be called ONLY when instrumenting using the APIs of PIN
VOID instrumentCalls(TRACE trace)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            // check if it's a call instruction
            if (INS_IsCall(ins) && !INS_IsRet(ins) && inTheMainBinary(INS_Address(ins)))
            {
                CALL_INST(ins);
            }

            // instrument  inlines
            if (KnobTraceInlines.Value())
            {
                if (inlined.find(INS_Address(ins)) != inlined.end())
                {
                    // for each inlined subprocedure in the current RTN, instrument the very layout_not_dumped instruction of such subprocedure
                    CALLSITE_INST(ins);
                    inlined.erase(INS_Address(ins));
                }
            }
        }
    }
}

VOID parseOffsets()
{
    std::string filename = KnobAddressList.Value();
    PRINT_DEBUG("[+] Reading offsets to hook from file %s\n", filename.c_str());
    std::ifstream in;

    in.open(filename, std::ios::in);
    if (in.is_open())
    {
        std::string line;
        while (std::getline(in, line))
        {
            ADDRINT offset = strtoul(line.c_str(), nullptr, 16);
            ADDRINT inst = BINARY_BASE + offset;
            offsets.insert(inst);
        }
        in.close();
    }
    else
    {
        fprintf(stderr, "[!!] Error opening file %s containing the offsets of the routines to hook. Ping @ubersandro.\n", filename.c_str());
        exit(1);
    }
    PRINT_DEBUG("[+] Offsets list length: %ld\n", offsets.size());
}

VOID parseInlinedRoutinesAddresses()
{
    // read out the offsets of the inlined functions, provided that the user wants to trace function calls
    std::string filename = "./inlined_functions_offsets";

    if (KnobTraceCalls.Value() == true && KnobTraceInlines.Value() == true)
    {
        if (strcmp(KnobInlinesOffsetsPath.Value().c_str(), "none"))
        {
            PRINT_DEBUG("Inlined functions custom offsets path: %s\n", KnobInlinesOffsetsPath.Value().c_str());
            filename = KnobInlinesOffsetsPath.Value();
        }
        else
        {
            PRINT_DEBUG("default inlined functions default offsets path: ./inlined_functions_offsets\n");
        }

        PRINT_DEBUG("Inlined function calls will be traced, reading out their offsets from file %s\n", filename.c_str());
        std::ifstream in;

        in.open(filename, std::ios::in);
        if (in.is_open())
        {
            std::string line;
            while (std::getline(in, line))
            {
                ADDRINT offset = strtoul(line.c_str(), nullptr, 16);
                ADDRINT inst = BINARY_BASE + offset;
                inlined.insert(inst);
            }
            in.close();
            PRINT_DEBUG("Inlined functions to hook are %ld\n", inlined.size());
        }
        else
        {
            fprintf(stderr, "[!!] Error opening file %s containing the offsets of the inlined functions. Ping @ubersandro.\n", filename.c_str());
            exit(1);
        }
    }
    else
    {
        fprintf(stderr, "\033[0;33m[*DEBUG*] Inlined functions will NOT be traced\033[0m\n");
    }
}

VOID instrumentIndirect(TRACE trace)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            if (INS_IsIndirectControlFlow(ins) && !INS_IsRet(ins) && inTheMainBinary(INS_Address(ins)))
            {
                IND_INST(ins);
            }
        }
    }
}

// This function assumes the client lock is held by the caller (Does it even matter? Better safe than sorry though)
int nopOutFunction(IMG img, std::string name)
{
    RTN rtn = RTN_FindByName(img, name.c_str());
    if (RTN_Valid(rtn))
    {
        RTN_Open(rtn);
        RTN_Replace(rtn, AFUNPTR(Mov0raxRet));
        RTN_Close(rtn);
        PRINT_DEBUG("%s was succesfully replaced with a RET.\n", name.c_str());
    }
    else
    {

        fprintf(stderr, "[ERROR] %s is not a valid routine or it's not present in the binary!\n", name.c_str()); // what happens when you call this on a non valid object?
        return 1;
    }
    return 0;
}

// this function assumes that the caller is gonna provide us with IND/CALL offsets
// all the offsets are relative to the main binary base address, they do not include code from shared libraries
VOID hookFromOffsets(TRACE trace)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
        for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
        {
            if (offsets.find(INS_Address(ins)) != offsets.end())
            {
                if (KnobTraceCalls.Value()) // tracing CALLS
                    CALLSITE_INST(ins);     // instrument the CALLSITE, not the CALL instruction
                else
                    IND_INST(ins); // instrument the indirect control flow instruction

                offsets.erase(INS_Address(ins));
            }

            // if tracing calls, and inlines are to be traced, then do this
            if (KnobTraceCalls.Value() && KnobTraceInlines.Value() && inlined.find(INS_Address(ins)) != inlined.end())
            {
                CALLSITE_INST(ins);
                inlined.erase(INS_Address(ins));
            }
        }
    }
}

VOID Trace(TRACE trace, VOID *v)
{
    hookFromOffsets(trace);
}

VOID onT1I(THREADID tid, CONTEXT *ctxt, ADDRINT ip)
{
    PRINT_DEBUG("TID %x: LLVMFuzzerTestOneInput called, call IP 0x%lx\n", tid, ip);
    if (layout_not_dumped)
    {
        // dumpMemoryLayout(); // This could potentially be moved to the main function in the libfuzzer runtimee TODO: look into it
        TRACE_AddInstrumentFunction(Trace, 0);
        layout_not_dumped = false;
    }
    // Figure out how to understand which input you are running
    cur_input = fake_argv[cur_idx];
    cur_idx++;
    memset(cur_outfile_name, 0, MAX_STR_LEN);
    if(!strstr(KnobOutput.Value().c_str(), ".csv")){
        char *basename_input = basename(cur_input);
        sprintf(cur_outfile_name, "%s/%s.out", KnobOutput.Value().c_str(), basename_input);
    }
    else strcpy(cur_outfile_name,KnobOutput.Value().c_str() );
    
    std::ofstream *stale = static_cast<std::ofstream *>(PIN_GetThreadData(mlog_key, tid));
    stale->close();
    delete stale;
    std::ofstream *new_ofile = new std::ofstream(cur_outfile_name, std::ios::out | std::ios::trunc);
    PIN_SetThreadData(mlog_key, new_ofile, tid);
    PRINT_DEBUG("Current input: %s, expect results in %s\n", basename(cur_input), cur_outfile_name);
}

VOID afterT1I(THREADID tid, CONTEXT *ctxt, ADDRINT ip)
{
    PRINT_DEBUG("LLVMFT1I finished on  %s\n", cur_input);
    std::ofstream *stale = static_cast<std::ofstream *>(PIN_GetThreadData(mlog_key, tid));
    stale->flush();
    stale->close();
    delete stale;
    std::ofstream *new_ofile = new std::ofstream("/dev/null", std::ios::out | std::ios::trunc);
    PIN_SetThreadData(mlog_key, new_ofile, tid);
}

VOID cleanUp()
{
    PRINT_DEBUG("Cleaning up...\n");
}

VOID FINI(INT32 code, VOID *v)
{
    cleanUp();
}

VOID onSignal(THREADID tid, INT32 sig, CONTEXT *ctxt, BOOL hasHandler, const EXCEPTION_INFO *pExceptInfo, VOID *v)
{
    fprintf(stderr, "\033[0;32m[++++] INPUT %s crashed the harness\n\033[0m", cur_input);
    FINI(0, 0);
    PIN_ExitApplication(0);
}

VOID Image(IMG img, void *v)
{
    // LOG("[+] IMG LOAD : " + IMG_Name(img) + " | " + hexstr(IMG_LowAddress(img)) + "\n");

    if (IMG_IsMainExecutable(img))
    {
        BINARY_BASE = IMG_LowAddress(img);
        BINARY_END = IMG_HighAddress(img);

        PIN_LockClient();

        // assuming the names are correctly demangled is not good
        if (nopOutFunction(img, "RssThread") && nopOutFunction(img, "_ZN6fuzzerL9RssThreadEPNS_6FuzzerEm"))
        {
            fprintf(stderr, "\033[0;31m[ERROR] Ping @ubersandro, RssThread does not seem to be there.\033[0m\n");
        };

        nopOutFunction(img, "asan_thread_start"); // asan-enabled harnesses

        RTN LLVMFuzzerTestOneInput = RTN_FindByName(img, "_ZN6fuzzer10RunOneTestEPNS_6FuzzerEPKcm"); // TODO: turn this into a knob, add robustness
        ADDRINT LLVMFuzzerTestOneInputAddr = RTN_Address(LLVMFuzzerTestOneInput);
        if (RTN_Valid(LLVMFuzzerTestOneInput))
        {
            PRINT_DEBUG("LLVMFuzzerTestOneInput found @ offset: 0x%lx\n", LLVMFuzzerTestOneInputAddr - BINARY_BASE);

            RTN_Open(LLVMFuzzerTestOneInput);
            RTN_InsertCall(LLVMFuzzerTestOneInput, IPOINT_BEFORE, (AFUNPTR)onT1I, IARG_THREAD_ID, IARG_CONTEXT, IARG_INST_PTR, IARG_END);

            RTN_InsertCall(LLVMFuzzerTestOneInput, IPOINT_AFTER, (AFUNPTR)afterT1I, IARG_THREAD_ID, IARG_END);
            RTN_Close(LLVMFuzzerTestOneInput);
        }
        else
            fprintf(stderr, "[ERROR] LLVMFuzzerTestOneInput was not found in the binary. Are we tracing a libfuzzer-instrumented harness?\n");

        RTN ReportGenericError = RTN_FindByName(img, "ReportGenericError");
        if (RTN_Valid(ReportGenericError))
        {
            PRINT_DEBUG("ReportGenericError found @ offset: 0x%lx\n", RTN_Address(ReportGenericError) - BINARY_BASE);
            RTN_Open(ReportGenericError);
            RTN_InsertCall(ReportGenericError, IPOINT_BEFORE, (AFUNPTR)onError, IARG_END);
            RTN_Close(ReportGenericError);
        }
        else {
            // fprintf(stderr, "[ERROR] ReportGenericError was not found in the binary. Are we tracing a libfuzzer-instrumented harness?\n");
            fprintf(stderr, "[*DEBUG*] ReportGenericError was not found in the binary. Retrying with non-demangled name\n");
            ReportGenericError = RTN_FindByName(img, "_ZN6__asan18ReportGenericErrorEmmmmbmjb");
            if (RTN_Valid(ReportGenericError))
            {
                PRINT_DEBUG("ReportGenericError found @ offset: 0x%lx\n", RTN_Address(ReportGenericError) - BINARY_BASE);
                RTN_Open(ReportGenericError);
                RTN_InsertCall(ReportGenericError, IPOINT_BEFORE, (AFUNPTR)onError, IARG_END);
                RTN_Close(ReportGenericError);
            }
            else
            {
                fprintf(stderr, "[ERROR] ReportGenericError was not found in the binary, not even demangled.\n");
            }
        }
        
        RTN ReportUMR = RTN_FindByName(img, "ReportUMR");
        if (RTN_Valid(ReportUMR))
        {
            PRINT_DEBUG("ReportUMR found @ offset: 0x%lx\n", RTN_Address(ReportUMR) - BINARY_BASE);
            RTN_Open(ReportUMR);
            RTN_InsertCall(ReportUMR, IPOINT_BEFORE, (AFUNPTR)onError, IARG_END);
            RTN_Close(ReportUMR);
        }
        else {
            // fprintf(stderr, "[ERROR] ReportUMR was not found in the binary. Are we tracing a libfuzzer-instrumented harness?\n");
            fprintf(stderr, "[*DEBUG*] ReportUMR was not found in the binary. Retrying with non-demangled name\n");
            ReportUMR = RTN_FindByName(img, "_ZN6__msan9ReportUMREPN11__sanitizer10StackTraceEj");
            if (RTN_Valid(ReportUMR))
            {
                PRINT_DEBUG("ReportUMR found @ offset: 0x%lx\n", RTN_Address(ReportUMR) - BINARY_BASE);
                RTN_Open(ReportUMR);
                RTN_InsertCall(ReportUMR, IPOINT_BEFORE, (AFUNPTR)onError, IARG_END);
                RTN_Close(ReportUMR);
            }
            else
            {
                fprintf(stderr, "[ERROR] ReportUMR was not found in the binary, not even demangled.\n");
            }
        }
        RTN ReportUBSAN = RTN_FindByName(img, "ReportErrorSummary"); 
        if (RTN_Valid(ReportUBSAN))
        {
            PRINT_DEBUG("ReportUBSAN found @ offset: 0x%lx\n", RTN_Address(ReportUBSAN) - BINARY_BASE);
            RTN_Open(ReportUBSAN);
            RTN_InsertCall(ReportUBSAN, IPOINT_BEFORE, (AFUNPTR)onError, IARG_END);
            RTN_Close(ReportUBSAN);
        }
        else {

            ReportUBSAN = RTN_FindByName(img, "_ZN11__sanitizer18ReportErrorSummaryEPKcS1_"); 
            if (RTN_Valid(ReportUBSAN))
            {
                PRINT_DEBUG("ReportUBSAN found @ offset: 0x%lx\n", RTN_Address(ReportUBSAN) - BINARY_BASE);
                RTN_Open(ReportUBSAN);
                RTN_InsertCall(ReportUBSAN, IPOINT_BEFORE, (AFUNPTR)onError, IARG_END);
                RTN_Close(ReportUBSAN);
            }
            else
            {
                fprintf(stderr, "[ERROR] ReportUBSAN was not found in the binary, not even demangled.\n");
            }
        }
        

        PIN_UnlockClient();
        parseInlinedRoutinesAddresses();
        if (offsetsExternallyProvided)
        {
            parseOffsets();
            offsets.erase(LLVMFuzzerTestOneInputAddr);
        }
    }
}

VOID ThreadStart(THREADID tid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
    PRINT_DEBUG("[*] Thread %d started, output in /dev/null\n", tid);
    std::string outputFile = "/dev/null";
    std::ofstream *out = new std::ofstream(outputFile, std::ios::out | std::ios::trunc);
    PIN_SetThreadData(mlog_key, static_cast<void *>(out), tid);
}

VOID ThreadFini(THREADID tid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
    if(KnobDebugMode.Value()) instr_offsets.close();
    std::ofstream *out = static_cast<std::ofstream *>(PIN_GetThreadData(mlog_key, tid));
    if (out)
    {
        out->close();
        delete out;
    }
    PRINT_DEBUG("[+] ThreadFini TID %d\n", tid);
    PIN_SetThreadData(mlog_key, 0, tid);
    fprintf(stderr, "Number of installed hooks: %lld\n", installed_hook);
}

INT32 Usage()
{
    std::cerr << endl
              << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID summary()
{
    PRINT_DEBUG("\033[0;31m[*DEBUG*] Knob values:\n\tCALLS TRACING %d\n\tINLINED ROUTINES %d\n\tOFFSET FILE %s\n\tDEBUG MODE %d\n\tINLINED_OFFSET_FILE %s\n\t\033[0m\n", KnobTraceCalls.Value(), KnobTraceInlines.Value(), KnobAddressList.Value().c_str(), KnobDebugMode.Value(), KnobInlinesOffsetsPath.Value().c_str());
}

VOID oom(long unsigned int size, VOID *v)
{
    std::cerr << "[!!] Out of memory error. Ping @ubersandro." << size << endl;
    PIN_ExitApplication(0);
}

int main(int argc, char *argv[])
{
    PIN_InitSymbols();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }
    fake_argv = argv;
    for (int i = 0; i < argc; i++)
    {
        if (strstr(argv[i], "--"))
        {
            if (strstr(argv[i+2], "-timeout")) // this is a workaround for the timeout option in libfuzzer ex. -timeout=80
            {
                cur_idx = i + 3; // skip the timeout option
            }
            else
            {
                cur_idx = i + 2; // skip the option
            }
        }
        if (strstr(argv[i], "symbolizer"))
        {
            fprintf(stderr, "[+] Symbolizer invoked, crashing\n");
            PIN_ExitApplication(0);
        }
    }

    summary();

    if(KnobSuppressOuput.Value()){
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull != -1) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        else fprintf(stderr, "[ERROR] in output suppression\n"); 
    }

    // this file is used to dump the offsets of the instructions that are instrumented
    if (KnobDebugMode.Value())
        instr_offsets.open("./offsets.dump", std::ios::out | std::ios::trunc);

    // functions offsets to hook might be read from a file
    offsetsExternallyProvided = strcmp(KnobAddressList.Value().c_str(), "none") != 0;
    if (offsetsExternallyProvided)
        PRINT_DEBUG("\033[0;33mOffsets to hook are externally provided\033[0m\n");
    else
        PRINT_DEBUG("\033[0;33mOffsets to hook are NOT externally provided\033[0m\n");

    IMG_AddInstrumentFunction(Image, 0); // instrument functions, parse offsets and inlines

    PIN_AddThreadStartFunction(ThreadStart, 0);

    PIN_AddThreadFiniFunction(ThreadFini, 0);

    PIN_AddOutOfMemoryFunction(oom, 0);

    if (KnobInterceptSignals.Value())
    {
        PIN_InterceptSignal(SIGSEGV, (INTERCEPT_SIGNAL_CALLBACK)onSignal, 0);
        PIN_InterceptSignal(SIGABRT, (INTERCEPT_SIGNAL_CALLBACK)onSignal, 0);
        PIN_InterceptSignal(SIGILL, (INTERCEPT_SIGNAL_CALLBACK)onSignal, 0);
        PIN_InterceptSignal(SIGKILL, (INTERCEPT_SIGNAL_CALLBACK)onSignal, 0);
    }
    else
        PRINT_DEBUG("NOT INTERCEPTING SIGNALS\n");
    
    mlog_key = PIN_CreateThreadDataKey(0); // on startup, associate a unique key to each thread

    PIN_StartProgram();

    return 0;
}
