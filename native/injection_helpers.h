#pragma once

#include <windows.h>

/* Map section into process memory */
PVOID map_section_into_process(HANDLE hProcess, HANDLE hSection, DWORD payload_size);

/* Redirect entry point to injected payload */
bool redirect_entry_point(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION& pi);
