#include "GlossHook.h"

#include <stdio.h> //snprintf fopen
#include <string.h> //strcpy strstr
#include <stdlib.h> //strtoul
#include <errno.h>
#include <sys/mman.h> //mprotect

#include "InlineHook.h"
#include "Instruction.h"
#include "GLog.h"
#include "xDL/xdl.h"

uintptr_t GetLibBase(const char* libName, pid_t pid)
{
    uintptr_t address = 0;
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    if (pid < 0)
        strcpy(fname, "/proc/self/maps");
    else
        snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
    FILE* fp = fopen(fname, "rt");
    if (fp != NULL)
    {
        while (fgets(buffer, sizeof(buffer) - 1, fp))
        {
            if (strstr(buffer, libName))
            {
                address = (uintptr_t)strtoul(buffer, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return address;
}

size_t GetLibLength(const char* libName, pid_t pid)
{
    uintptr_t address = 0, end_address = 0;
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    if (pid < 0)
        strcpy(fname, "/proc/self/maps");
    else
        snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
    FILE* fp = fopen(fname, "rt");
    if (fp != NULL)
    {
        while (fgets(buffer, sizeof(buffer) - 1, fp))
        {
            if (strstr(buffer, libName))
            {
                const char* secondPart = strchr(buffer, '-');
                if (!address)
                    end_address = address = (uintptr_t)strtoul(buffer, NULL, 16);
                if (secondPart != NULL)
                    end_address = (uintptr_t)strtoul(secondPart + 1, NULL, 16);
            }
        }
        fclose(fp);
    }
    return end_address - address;
}

lib_h GetLibHandle(const char* libName)
{
    void* xdl_handle = xdl_open(libName, XDL_TRY_FORCE_LOAD);
    if (NULL == xdl_handle) {
        if (NULL != dlopen(libName, RTLD_LAZY))
            xdl_handle = xdl_open(libName, XDL_DEFAULT);
    }
    return xdl_handle;
}

int CloseLib(lib_h handle, bool is_dlclose)
{
    auto dl_handle = xdl_close(handle);
    if (NULL == dl_handle) return -1;
    return is_dlclose ? dlclose(dl_handle) : 0;
}

uintptr_t GetLibBaseFromHandle(lib_h handle)
{
    xdl_info_t info;
    if (xdl_info(handle, XDL_DI_DLINFO, &info) == -1)
        return NULL;
    return (uintptr_t)info.dli_fbase;
}

const char* GetLibFilePath(uintptr_t libAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)libAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_fname;
}

const char* GetLibFilePathFromHandle(lib_h handle)
{
    xdl_info_t info;
    if (xdl_info(handle, XDL_DI_DLINFO, &info) == -1)
        return NULL;
    return info.dli_fname;
}

size_t GetLibFileSize(const char* libName)
{
    size_t size = 0;
    FILE* file = fopen(GetLibFilePathFromHandle(GetLibHandle(libName)), "r");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        size = ftell(file);
        fclose(file);
    }
    return size;
}

uintptr_t GetSymbolAddr(lib_h handle, const char* name)
{
    void* addr = xdl_sym(handle, name, NULL);
    if (NULL == addr)
        addr = xdl_dsym(handle, name, NULL);
    return (uintptr_t)addr;
}

uintptr_t GetSymbolAddrEx(uintptr_t libAddr, const char* name)
{
    auto handle = GetLibHandle(GetLibFilePath(libAddr));
    return NULL != handle ? GetSymbolAddr(handle, name) : NULL;
}

size_t GetSymbolSize(lib_h handle, const char* name)
{
    size_t size = NULL;
    if (NULL == xdl_sym(handle, name, &size))
        xdl_dsym(handle, name, &size);
    return size;
}

size_t GetSymbolSizeEx(uintptr_t SymAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)SymAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_ssize;
}

const char* GetSymbolName(uintptr_t SymAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)SymAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_sname;
}

bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type)
{
    if (addr == NULL || len == 0) return false;

    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    if (type != NULL) {
        prot = PROT_NONE;
        if (type->bRead)
            prot |= PROT_READ;
        if (type->bWrite)
            prot |= PROT_WRITE;
        if (type->bExecute)
            prot |= PROT_EXEC;
        if (type->bPrivate)
            prot |= PROT_NONE;
        if (type->bShared)
            prot = PROT_READ | PROT_WRITE;
    }
    unsigned long PageSize = sysconf(_SC_PAGESIZE);
    const uintptr_t start = PAGE_START(addr, PageSize);
    const uintptr_t end = PAGE_END((addr + len - 1), PageSize);
    int ret = mprotect((void*)start, end - start, prot);
    if (ret == -1)
    {
        GLOGE("Description Failed to set memory permission: %d-%s", errno, strerror(errno));
        return false;
    }
    return true;
}

p_flag* GetMemoryPermission(uintptr_t addr, pid_t pid)
{
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    uintptr_t start_address, end_address;
    p_flag* type = (p_flag*)calloc(1, sizeof(p_flag));
    if (pid < 0)
        strcpy(fname, "/proc/self/maps");
    else
        snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);

    FILE* fp = fopen(fname, "rt");
    if (fp != NULL) {
        while (fgets(buffer, sizeof(buffer) - 1, fp)) {
            if (strstr(buffer, "---p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "r--p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rw-p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bWrite = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "r-xp")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bExecute = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rwxp")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bWrite = true;
                    type->bExecute = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rw-s")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bWrite = true;
                    type->bShared = true;
                    break;
                }
            }
        }
        fclose(fp);
    }
    return type;
}

void WriteMemory(void* addr, void* data, size_t size, bool vp)
{
    Unprotect((uintptr_t)addr, vp ? size : 0);
    memcpy(addr, data, size);
    cacheflush((uintptr_t)addr, (uintptr_t)addr + size, 0);
}

void* ReadMemory(void* addr, void* data, size_t size, bool vp)
{
    Unprotect((uintptr_t)addr, vp ? size : 0);
    memcpy(data, addr, size);
    return data;
}

void MemoryFill(void* addr, uint8_t value, size_t size, bool vp)
{
    Unprotect((uintptr_t)addr, vp ? size : 0);
    memset(addr, value, size);
    cacheflush((uintptr_t)addr, (uintptr_t)addr + size, 0);
}

void GotHook(void* addr, void* func, void** original)
{
    if (addr == NULL || func == NULL) return;
    Unprotect((uintptr_t)addr, sizeof(uintptr_t));
    if (original != NULL)
        *((uintptr_t*)original) = *(uintptr_t*)addr;
    *(uintptr_t*)addr = (uintptr_t)func;
    cacheflush((uintptr_t)addr, (uintptr_t)addr + sizeof(uintptr_t), 0);
}

//inline hook
void* GlossHookSymAddr(void* sym_addr, void* new_func, void** original)
{
    //1.���addr��T����Aģʽ
    if (TEST_BIT0((uintptr_t)sym_addr)) {
        return InlineHookThumb((void*)CLEAR_BIT0((uintptr_t)sym_addr), new_func, original);
    }
    else {
        return InlineHookARM(sym_addr, new_func, original);
    }
    //2.�����Ŵ�С
    //3.�̺���hook
}

void* GlossHookFuncAddr(void* func_addr, void* new_func, void** original, i_set inst_set)
{
  
}

void GlossHookCancel(void* hook)
{
    SetInlineHookState((InlineHookInfo*)hook, DISABLE_HOOK);
}

void GlossHookRecover(void* hook)
{
    SetInlineHookState((InlineHookInfo*)hook, ENABLE_HOOK);
}

void GlossHookDelete(void* hook)
{
    return DeleteInlineHook((InlineHookInfo*)hook);
}

void GlossHookCancelAll(void* addr, i_set inst_set)
{
    InlineHookInfo* hook = GetLastInlineHook(addr, inst_set);
    while (hook != nullptr) {
        SetInlineHookState(hook, DISABLE_HOOK);
        hook = hook->prev;
    }
}

void GlossHookRecoverAll(void* addr, i_set inst_set)
{
    InlineHookInfo* hook = GetLastInlineHook(addr, inst_set);
    while (hook != nullptr) {
        SetInlineHookState(hook, ENABLE_HOOK);
        hook = hook->prev;
    }
}

void GlossHookDeleteAll(void* addr, i_set inst_set)
{
    InlineHookInfo* hook = GetLastInlineHook(addr, inst_set);
    while (hook != nullptr) {
        DeleteInlineHook(hook);
        hook = hook->prev;
    }
}

int GlossHookGetCount(void* hook)
{
    return reinterpret_cast<InlineHookInfo*>(hook)->hook_count;
}

int GlossHookGetTotalCount(void* addr, i_set inst_set)
{
    return GetLastInlineHook(addr, inst_set)->hook_count;
}

void* GlossGetHook(void* addr, int count, i_set inst_set)
{
    InlineHookInfo* info = GetLastInlineHook(addr, inst_set);
    if (info == nullptr) return nullptr;

    while (info->hook_count != count) {
        info = info->prev;
        if (info == nullptr) break;
    }
    return info;
}

void* GlossGetResultAddr(void* orig_addr)
{
    return HookLists.list[orig_addr]->result_addr;
}






