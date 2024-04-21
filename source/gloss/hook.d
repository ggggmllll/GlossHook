module gloss.hook;

import std.bitmanip;

version(AArch64) {} else version(ARM) {} else static assert(0, "unsupport arch");

extern(C):

struct p_flag
{
    mixin(bitfields!(
        ubyte, "bRead", 1,
        ubyte, "bWrite", 1,
        ubyte, "bExecute", 1,
        ubyte, "bPrivate", 1,
        ubyte, "bShared", 1,
        ubyte, "_align", 3
    ));
}

enum i_set
{
    NONE = 0, 
    THUMB, 
    ARM, 
    ARM64
}

alias gloss_lib = void*;

version(ARM) 
{
    T1 GET_INST_SET(T1)(T1 addr) 
    {
        return addr & 1 ? i_set.THUMB : i_set.ARM;
    }

    struct gloss_reg
    {
        enum e_reg
        {
            R0 = 0, 
            R1, 
            R2, 
            R3, 
            R4, 
            R5, 
            R6, 
            R7, 
            R8, 
            R9, 
            R10,
            R11, 
            FP = R11,
            R12, 
            IP = R12, 
            R13, 
            SP = R13, 
            R14, 
            LR = R14, 
            R15, 
            PC = R15, 
            CPSR 
        }
        union 
        {
                int[17] reg;
                struct _regs 
                { 
                    int r0;
                    int r1; 
                    int r2;
                    int r3;
                    int r4;
                    int r5;
                    int r6; 
                    int r7;
                    int r8;
                    int r9;
                    int r10;
                    int r11;
                    int r12;
                    int sp;
                    int lr;
                    int pc;
                    int cpsr;
                }
                _regs regs;
        }
    }
}
else
{
    struct gloss_reg
    {
        enum e_reg {
			X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, FP = X29,
			Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
			X30, LR = X30, X31, SP = X31, PC, CPSR
		}
        union 
        {
                int[66] reg;
                struct _regs 
                { 
                    ulong x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
				    double q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;
				    ulong lr, sp, pc, cpsr;
                }
                _regs regs;
        }
    }
}

uint GlossGetLibInfo(const(char)* lib_name, int pid, char* lib_path, size_t* lib_mem_len);

gloss_lib GlossOpen(const(char)* lib_name);
int GlossClose(gloss_lib handle, bool is_dlclose);

uint GlossGetLibBias(const(char)* lib_name);
uint GlossGetLibBiasEx(gloss_lib handle);

const(char)* GlossGetLibPath(gloss_lib handle);
bool GlossGetLibPathEx(uint lib_addr, char* path);
size_t GlossGetLibFileSize(const(char)* lib_name);

uint GlossSymbol(gloss_lib handle, const(char)* name, size_t* sym_size);
uint GlossSymbolEx(uint lib_addr, const(char)* name, size_t* sym_size);
bool GlossAddr(uint lib_addr, uint* sym_addr, size_t* sym_size, char* sym_name);

const(char)* GlossGetLibMachine(const(char)* libName);
const(int) GlossGetLibBit(const(char)* libName);

uint GlossGetLibSection(const(char)* libName, const(char)* sec_name, size_t* sec_size);
uint GlossGetLibSegment(const(char)* libName, uint seg_type, size_t* seg_size);

// memory
bool SetMemoryPermission(uint addr, size_t len, p_flag* type);
pragma(inline) bool Unprotect(uint addr, size_t len)
{
    return SetMemoryPermission(addr, len, null);
}

bool GetMemoryPermission(uint addr, p_flag* type, int pid, const(char)* lib_name);
pragma(inline) bool IsAddrExecute(uint addr)
{
    p_flag type;
    GetMemoryPermission(addr, &type, -1, null);
    return cast(bool) type.bExecute;
}

void WriteMemory(void* addr, void* data, size_t size, bool vp);
void* ReadMemory(void* addr, void* data, size_t size, bool vp);
void MemoryFill(void* addr, byte value, size_t size, bool vp);

// inline hook function head
void* GlossHook(void* sym_addr, void* new_func, void** old_func);
void* GlossHookAddr(void* func_addr, void* new_func, void** old_func, bool is_4_byte_hook, i_set mode);

// inline hook branch B/BL/BLX
void* GlossHookBranchB(void* branch_addr, void* new_func, void** old_func, i_set mode);
void* GlossHookBranchBL(void* branch_addr, void* new_func, void** old_func, i_set mode);

version(ARM)
{
    void* GlossHookBranchBLX(void* branch_addr, void* new_func, void** old_func, i_set mode);
}


// inline hook internal any position
alias GlossHookInternalCallback = void function(gloss_reg* regs, void* hook);
void* GlossHookInternal(void* addr, GlossHookInternalCallback new_func, bool is_4_byte_hook, i_set mode);

// inline hook redirect code
void* GlossHookRedirect(void* redirect_addr, void* new_addr, bool is_4_byte_hook, i_set mode);

// got hook
void* GlossGotHook(void* got_addr, void* new_func, void** old_func);

alias _dlopen = void* function(const(char)* filename, int flags);
alias _android_dlopen_ext = void* function(const(char)* filename, int flags, const(void*) extinfo);
alias _do_dlopen_n = void* function(const(char)* name, int flags, const(void*) extinfo, void* caller_addr);
alias _do_dlopen_o = void* function(const(char)* name, int flags, const(void*) extinfo, const(void*) caller_addr);
alias ___loader_dlopen = void* function(const(char)* filename, int flags, const(void*) caller_addr);
alias ___loader_android_dlopen_ext = void* function(const(char)* filename, int flags, const(void*) extinfo, const(void*) caller_addr);
alias _dlsym = void* function(void* handle, const(char)* symbol);
alias _do_dlsym = bool function(void* handle, const(char)* sym_name, const(char)* sym_ver, void* caller_addr, void** symbol);
alias ___loader_dlvsym = void* function(void* handle, const(char)* symbol, const(char)* _version, const(void*) caller_addr);
alias ___loader_dlsym = void* function(void* handle, const(char)* symbol, const(void*) caller_addr);

union GlossLinkerFuncProxy
{
    struct GlossDlopenProxy
    {
        // API Level 23 (Android 6.0) and below
        _dlopen dlopen;
        void** orig_dlopen;
        // API Level 21 - 23 (Android 5.x - 6.0) Only
        _android_dlopen_ext android_dlopen_ext;
        void** orig_android_dlopen_ext;

        // API Level 24 - 25 (Android 7.x)
        _do_dlopen_n do_dlopen_n;
        void** orig_do_dlopen_n;

        // API Level 26 - 27 (Android 8.x)
        _do_dlopen_o do_dlopen_o;
        void** orig_do_dlopen_o;

        // API Level 28 (Android 9.0) and above
        ___loader_dlopen __loader_dlopen;
        ___loader_android_dlopen_ext __loader_android_dlopen_ext;
        void** orig__loader_android_dlopen_ext;
    } 
    GlossDlopenProxy DlopenProxy;

    struct GlossDlsymProxy
    {
        // API Level 23 (Android 6.0) and below
        _dlsym dlsym;
        void** orig_dlsym;

        // API Level 24 - 25 (Android 7.x)
        _do_dlsym do_dlsym;
        void** orig_do_dlsym;

        // API Level 26 (Android 8.0) and above
        ___loader_dlsym __loader_dlsym;
        ___loader_dlvsym __loader_dlvsym;
        void** orig__loader_dlsym;
        void** orig__loader_dlvsym;
    } 
    GlossDlsymProxy DlsymProxy;

    // Other Linker Function
    struct GlossFuncProxy
    {
        void* linker_func;
        void** orig_linker_func;
    } 
    GlossFuncProxy FuncProxy;
}

// dlfuc: dlopen, dlsym, and symbol name
// new_dlfunc: see GlossLinkerFuncProxy
// hook: return hook pointer (__loader_dlopen, __loader_dlsym)
// hook2: return hook2 pointer （__loader_android_dlopen_ext, __loader_dlvsym）
bool GlossLinkerHook(const(char)* dlfunc, GlossLinkerFuncProxy new_dlfunc, void** hook, void** hook2);

// pre inline/got hook
alias GlossHookCallback = void function(void* hook);

void* GlossHookEx(const(char)* lib_name, const(char)* sym_name, void* new_func, void** old_func, GlossHookCallback call_back_func);
void* GlossGotHookEx(const(char)* lib_name, const(char)* sym_name, void* new_func, void** old_func, GlossHookCallback call_back_func);

// pre inline hook .init_array/.init / hook constructor
void* GlossHookConstructor(const(char)* lib_name, void* offset_addr, void* new_func, void** old_func, bool is_4_byte_hook, i_set mode, GlossHookCallback call_back_func);

// Disable/Enable/Delete
void GlossHookDisable(void* hook);
void GlossHookEnable(void* hook);
void GlossHookDelete(void* hook);
void GlossHookDisableAll(void* addr, i_set mode);
void GlossHookEnableAll(void* addr, i_set mode);
void GlossHookDeleteAll(void* addr, i_set mode);

// other func
int GlossHookGetCount(void* hook);
int GlossHookGetTotalCount(void* addr, i_set mode);

void* GlossHookGetPtr(void* addr, i_set mode);
void* GlossHookGetPtrEx(void* addr, int count, i_set mode);
int GlossHookGetStatus(void* hook);
void* GlossHookGetPrev(void* hook);
void* GlossHookGetNext(void* hook);

void GlossHookSetNewFunc(void* hook, void* new_func);

static pragma(inline) void WriteMemory(T1)(uint addr, T1 value, bool vp = true)
{
    WriteMemory(cast(void*) addr, &value, T1.sizeof, vp);
}

static pragma(inline) T1 ReadMemory(T1)(uint addr, bool vp = true)
{
    if (vp) 
        Unprotect(addr, sizeof(T1));
    return *(cast(T1) addr);
}

static pragma(inline) void* GotHook(A, B, C)(A addr, B func, C original)
{
    return GlossGotHook(cast(void*) addr, cast(void*) func, cast(void**) original);
}

static pragma(inline) void* GotHook(A, B)(A addr, B func)
{
    return GlossGotHook(cast(void*) addr, cast(void*) func , null);
}

static pragma(inline) void* InlineHook(A, B, C)(A addr, B func, C original)
{
    return GlossHook(cast(void*) addr, cast(void*) func, cast(void**) original);
}

static pragma(inline) void* InlineHook(A, B)(A addr, B func)
{
    return GlossHook(cast(void*) addr, cast(void*) func , null);
}