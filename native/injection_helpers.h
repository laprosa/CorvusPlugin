#pragma once

#include <windows.h>

/* Map section into process memory.
   pe_buffer is the local copy of the PE used to check relocation support
   when the image cannot be mapped at its preferred base. */
PVOID map_section_into_process(HANDLE hProcess, HANDLE hSection, DWORD payload_size, const BYTE *pe_buffer);

/* Redirect entry point to injected payload */
bool redirect_entry_point(BYTE* loaded_pe, PVOID load_base, PROCESS_INFORMATION& pi);
