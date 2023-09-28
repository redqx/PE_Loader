#include <windows.h>

#include "mmLoader.h"

#pragma region forwardDeclaration
typedef FARPROC(WINAPI* Type_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* Type_GetModuleHandleA)(LPCSTR);
typedef HMODULE(WINAPI* Type_LoadLibraryA)(LPCSTR);
typedef LPVOID(WINAPI* Type_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* Type_VirtualFree)(LPVOID, SIZE_T, DWORD);
typedef BOOL(WINAPI* Type_VirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HGLOBAL(WINAPI* Type_GlobalAlloc)(_In_ UINT, _In_ SIZE_T);
typedef HGLOBAL(WINAPI* Type_GlobalFree)(_In_ HGLOBAL);
typedef BOOL(WINAPI* Type_DllMain)(HMODULE, DWORD, LPVOID);


typedef struct API_PTR_TABLE {
    LPVOID pfn_GetProcAddress;   // GetProcAddress
    LPVOID pfn_GetModuleHandleA; // GetModuleHandleA
    LPVOID pfn_LoadLibraryA;     // LoadLibraryA

    LPVOID pfn_VirtualAlloc;   // VirtualAlloc
    LPVOID pfn_VirtualFree;    // VirtualFree
    LPVOID pfn_VirtualProtect; // VirtualProtect

    LPVOID pfn_GlobalAlloc;
    LPVOID pfn_GlobalFree;
} APIPTR_TABLE, * PAPIPTR_TABLE;

/// <summary>
/// Represents the memory module instance.
/// </summary>
typedef struct __MEMMODULE_S {
    union {
#if _WIN64
        ULONGLONG iBase;
#else
        DWORD iBase;
#endif
        HMODULE hModule;
        LPVOID lpBase;
        PIMAGE_DOS_HEADER pImageDosHeader;
    };                   // MemModule base
    DWORD dwSizeOfImage; // MemModule size
    DWORD dwCRC32;         // MemModule crc32

    PAPIPTR_TABLE pApis; // Pointer to parameters
    BOOL bCallEntry;     // Call module entry
    BOOL bLoadOk;        // MemModule is loaded ok?
    DWORD dwErrorCode;   // Last error code
} MEM_MODULE, * PMEM_MODULE;

BOOL mainWork(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer, BOOL bCallEntry);

FARPROC GetMemModuleProcInternal(PMEM_MODULE pMemModule, LPCSTR lpName);

VOID FreeMemModuleInternal(PMEM_MODULE pMemModule);

FARPROC my_GetProcAddress(HMODULE hModule, LPCSTR lpName);

HMODULE my_GetModuleHandle(LPCWSTR lpName);

PAPIPTR_TABLE get_KeyFunction();

BOOL Is_PEFile(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);

BOOL Mapping_PESections(PMEM_MODULE pMemModule, LPVOID lpPeModuleBuffer);

BOOL RelocateModuleBase(PMEM_MODULE pMemModule);

BOOL Init_ImportTable(PMEM_MODULE pMemModule);

BOOL Set_SectionMemAttribution(PMEM_MODULE pMemModule);

BOOL HandleTlsData(PMEM_MODULE pMemModule);

BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason);

FARPROC GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName);

VOID UnmapMemModule(PMEM_MODULE pMemModule);

UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize);

// Memory functions
int mml_strlenA(const char* psz);

int mml_strcmpA(const char* psza, const char* pszb);

int mml_stricmpW(const wchar_t* pwsza, const wchar_t* pwszb);

wchar_t* mml_strcpyW(wchar_t* pszDest, const wchar_t* pszSrc, unsigned int nMax);

void* mml_memset(void* pv, int c, unsigned int cb);

void* mml_memcpy(void* pvDest, const void* pvSrc, unsigned int cb);

#pragma endregion forwardDeclaration

#pragma region mmLoaderImpl

LPVOID my_Loader(_In_ MMHELPER_METHOD method, _In_ LPVOID lpArg1, _In_ LPVOID lpArg2, _In_ LPVOID lpArg3) {
    switch (method) 
    {
        //�ܽ���
        case MHM_BOOL_LOAD: 
        {
            return (LPVOID)(INT_PTR)run_PE(lpArg1, (BOOL)(lpArg2 != 0), (DWORD*)lpArg3);
            break;
        } 
        case MHM_VOID_FREE:
        {
            FreeMemModule(lpArg1);
            break;
        } 
        case MHM_FARPROC_GETPROC: 
        {
            return (LPVOID)GetMemModuleProc(lpArg1, lpArg2);
            break;
        } 
        default:
            break;
    }

    return 0;
}

BOOL mainWork(PMEM_MODULE pMemModule_Describe, LPVOID lp_PEfile, BOOL bCallEntry) 
{
    if (NULL == pMemModule_Describe || NULL == pMemModule_Describe->pApis || NULL == lp_PEfile)
    {
        return FALSE;
    }

    pMemModule_Describe->dwErrorCode = ERROR_SUCCESS;

    // ���PE�ĺϷ���
    if (FALSE == Is_PEFile(pMemModule_Describe, lp_PEfile)) 
    {
        return FALSE;
    }

    // ��ʼ����ӳ��
    if (FALSE == Mapping_PESections(pMemModule_Describe, lp_PEfile))
        return FALSE;

    // ��ʼ�ض�λ����
    if (FALSE == RelocateModuleBase(pMemModule_Describe)) {
        UnmapMemModule(pMemModule_Describe);
        return FALSE;
    }

    // ��ʼ�����Ĳ���
    if (FALSE == Init_ImportTable(pMemModule_Describe)) 
    {
        UnmapMemModule(pMemModule_Describe);
        return FALSE;
    }

    pMemModule_Describe->dwCRC32 = GetCRC32(0, pMemModule_Describe->lpBase, pMemModule_Describe->dwSizeOfImage);

    // ���ݽ���������,�����ڴ�����,���ڴ汣��
    if (FALSE == Set_SectionMemAttribution(pMemModule_Describe)) 
    {
        UnmapMemModule(pMemModule_Describe);
        return FALSE;
    }

    //����Tls����
    if (FALSE == HandleTlsData(pMemModule_Describe))
    {
        return FALSE;
    }

    //��������entryPoint
    if (bCallEntry)
    {
        //ԭ��������,�Ⲩ���׵�д��dll������...����Ϊʲô����exe/dell�ļ�����
        //exe���ص�main��Ҫ���ݲ���,,,����,,,����,,Ҳ���Ǻܺø�,,����
        if (FALSE == CallModuleEntry(pMemModule_Describe, DLL_PROCESS_ATTACH)) 
        {
            // failed to call entry point,
            // clean resource, return false
            UnmapMemModule(pMemModule_Describe);
            return FALSE;
        }
    }

    return TRUE;
}

HMEMMODULE run_PE(_In_ LPVOID lp_PEFile, _In_ BOOL bCallEntry, _Inout_ DWORD* pdwError) 
{

    PAPIPTR_TABLE pApis = get_KeyFunction();
    if (!pApis) 
    {
        if (pdwError)
        {
            *pdwError = MMEC_INVALID_WIN32_ENV;
        }
        return NULL;
    }

    Type_GlobalAlloc pfn_GlobalAlloc = pApis->pfn_GlobalAlloc;
    PMEM_MODULE pMemModule_Describe = pfn_GlobalAlloc(GPTR, sizeof(MEM_MODULE));
    if (!pMemModule_Describe) 
    {
        if (pdwError)
            *pdwError = MMEC_INVALID_WIN32_ENV;
        return NULL;
    }

    pMemModule_Describe->pApis = pApis;
    pMemModule_Describe->bCallEntry = bCallEntry;
    pMemModule_Describe->bLoadOk = FALSE;
    pMemModule_Describe->dwErrorCode = MMEC_OK;

    if (mainWork(pMemModule_Describe, lp_PEFile, bCallEntry)) 
    {
        if (pdwError)
        {
            *pdwError = 0;
        }
        return (HMEMMODULE)pMemModule_Describe;
    }

    if (pdwError)
    {
        *pdwError = pMemModule_Describe->dwErrorCode;
    }
    Type_GlobalFree pfnGlobalFree = pApis->pfn_GlobalFree;
    pfnGlobalFree(pMemModule_Describe);
    pfnGlobalFree(pApis);//֮ǰ���ٵ�,,�������ͷ���
    return NULL;
}

VOID FreeMemModuleInternal(PMEM_MODULE pMemModule) {
    if (NULL != pMemModule) {
        pMemModule->dwErrorCode = ERROR_SUCCESS;

        if (pMemModule->bCallEntry)
            CallModuleEntry(pMemModule, DLL_PROCESS_DETACH);

        UnmapMemModule(pMemModule);
    }
}

VOID FreeMemModule(_In_ HMEMMODULE MemModuleHandle) 
{
    PMEM_MODULE pMemModule = (PMEM_MODULE)MemModuleHandle;
    FreeMemModuleInternal(pMemModule);
    if (pMemModule) {
        Type_GlobalFree pfnGlobalFree = pMemModule->pApis->pfn_GlobalFree;
        if (pfnGlobalFree) {
            pfnGlobalFree(pMemModule->pApis);
            pfnGlobalFree(pMemModule);
        }
    }
}

FARPROC GetMemModuleProcInternal(PMEM_MODULE pMemModule, LPCSTR lpName) {
    if (NULL != pMemModule && lpName != NULL) {
        // Get the address of the specific function
        pMemModule->dwErrorCode = ERROR_SUCCESS;
        return GetExportedProcAddress(pMemModule, lpName);
    }

    return NULL;
}

FARPROC GetMemModuleProc(_In_ HMEMMODULE MemModuleHandle, _In_ LPCSTR lpName) {
    return GetMemModuleProcInternal((PMEM_MODULE)MemModuleHandle, lpName);
}

/// <summary>
/// Tests the return value and jump to exit label if false.
/// </summary>
#define IfFalseGoExitWithError(x, exp)                                                                                 \
  do {                                                                                                                 \
    if (!(br = (x)) && (exp))                                                                                          \
      goto _Exit;                                                                                                      \
  } while (0)

/// <summary>
/// Tests the return value and jump to exit label if false.
/// </summary>
#define IfFalseGoExit(x)                                                                                               \
  do {                                                                                                                 \
    if (!(br = (x)))                                                                                                   \
      goto _Exit;                                                                                                      \
  } while (0)

 
#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))

//����������
FARPROC my_GetProcAddress(HMODULE hModule, CHAR* lpName) 
{
    if (!hModule || !lpName)
        return NULL;

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return NULL;

    PIMAGE_NT_HEADERS pImageNTHeaders = MakePointer(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
    if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    if (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
        return NULL;

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =MakePointer(
        PIMAGE_EXPORT_DIRECTORY, 
        hModule,
        pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD pNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);

    for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
        if (!mml_strcmpA(lpName, (char*)hModule + pNameTable[i])) {
            PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);
            PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
            DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
            return MakePointer(PVOID, hModule, dwAddressOffset);
        }
    }

    return NULL;
}

//ͨ��PEB/TEB��ȡ�Ѿ����ص�dll�Ļ���ַ
HMODULE my_GetModuleHandle(WCHAR*lpName) 
{
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING;
    typedef UNICODE_STRING* PUNICODE_STRING;
    typedef const UNICODE_STRING* PCUNICODE_STRING;

    typedef struct _LDR_DATA_TABLE_ENTRY 
    {
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
        PVOID BaseAddress;
        PVOID EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
        ULONG Flags;
        SHORT LoadCount;
        SHORT TlsIndex;
        LIST_ENTRY HashTableEntry;
        ULONG TimeDateStamp;
    } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        PVOID SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA, * PPEB_LDR_DATA;

#ifdef _WIN64
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[21];
        PPEB_LDR_DATA Ldr;
        PVOID ProcessParameters;
        BYTE Reserved3[520];
        PVOID PostProcessInitRoutine;
        BYTE Reserved4[136];
        ULONG SessionId;
    } PEB, * PPEB;
#else
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        PVOID Reserved3[2];
        PPEB_LDR_DATA Ldr;
        LPVOID ProcessParameters;
        PVOID Reserved4[3];
        PVOID AtlThunkSListPtr;
        PVOID Reserved5;
        ULONG Reserved6;
        PVOID Reserved7;
        ULONG Reserved8;
        ULONG AtlThunkSListPtr32;
        PVOID Reserved9[45];
        BYTE Reserved10[96];
        LPVOID PostProcessInitRoutine;
        BYTE Reserved11[128];
        PVOID Reserved12[1];
        ULONG SessionId;
    } PEB, * PPEB;
#endif
    // Get the base address of PEB struct
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (pPeb && pPeb->Ldr) {
        PPEB_LDR_DATA pLdr = pPeb->Ldr;

        // And get header of the InLoadOrderModuleList
        PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
        if (pHeaderOfModuleList->Flink != pHeaderOfModuleList) 
        {
            PLDR_DATA_TABLE_ENTRY pEntry = NULL;
            PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;
            do 
            {
                pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
                if (0 == mml_stricmpW(pEntry->BaseDllName.Buffer, lpName)) 
                {
                    return pEntry->BaseAddress;
                    break;
                }
                pEntry = NULL;
                pCur = pCur->Flink;
            } while (pCur != pHeaderOfModuleList);
        }
    }
    return NULL;
}

PAPIPTR_TABLE get_KeyFunction() 
{
    WCHAR wszKernel[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
    HMODULE hKernelModule = my_GetModuleHandle(wszKernel);
    if (!hKernelModule)
    {
        return NULL;
    }

    char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
    Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)my_GetProcAddress(hKernelModule, szGetProcAddress);
    if (!pfnGetProcAddress)
    {
        //���û���õ���ʵ��szGetProcAddress,�����Լ���GetProcAddress
        pfnGetProcAddress = (Type_GetProcAddress)my_GetProcAddress;
    }

    char szGlobalAlloc[] = { 'G', 'l', 'o', 'b', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
    char szGlobalFree[] = { 'G', 'l', 'o', 'b', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
    Type_GlobalAlloc pfnGlobalAlloc = (Type_GlobalAlloc)my_GetProcAddress(hKernelModule, szGlobalAlloc);
    Type_GlobalFree pfnGlobalFree = (Type_GlobalFree)my_GetProcAddress(hKernelModule, szGlobalFree);
    if (!pfnGlobalAlloc || !pfnGlobalFree)
        return NULL;

    PAPIPTR_TABLE pApis = pfnGlobalAlloc(GPTR, sizeof(APIPTR_TABLE));
    if (!pApis)
        return NULL;

    pApis->pfn_GetProcAddress = pfnGetProcAddress;
    pApis->pfn_GlobalAlloc = pfnGlobalAlloc;
    pApis->pfn_GlobalFree = pfnGlobalFree;

    do {
        char szGetModuleHandleA[] = { 'G', 'e', 't', 'M', 'o', 'd', 'u', 'l', 'e', 'H', 'a', 'n', 'd', 'l', 'e', 'A', 0 };
        pApis->pfn_GetModuleHandleA = pfnGetProcAddress(hKernelModule, szGetModuleHandleA);
        if (!pApis->pfn_GetModuleHandleA)
            break;

        char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
        pApis->pfn_LoadLibraryA = pfnGetProcAddress(hKernelModule, szLoadLibraryA);
        if (!pApis->pfn_GetModuleHandleA)
            break;

        char szVirtualAlloc[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0 };
        pApis->pfn_VirtualAlloc = pfnGetProcAddress(hKernelModule, szVirtualAlloc);
        if (!pApis->pfn_GetModuleHandleA)
            break;

        char szVirtualFree[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'F', 'r', 'e', 'e', 0 };
        pApis->pfn_VirtualFree = pfnGetProcAddress(hKernelModule, szVirtualFree);
        if (!pApis->pfn_GetModuleHandleA)
            break;

        char szVirtualProtect[] = { 'V', 'i', 'r', 't', 'u', 'a', 'l', 'P', 'r', 'o', 't', 'e', 'c', 't', 0 };
        pApis->pfn_VirtualProtect = pfnGetProcAddress(hKernelModule, szVirtualProtect);
        if (!pApis->pfn_GetModuleHandleA)
            break;

        return pApis;
    } while (0);//������Ҫд��...��..��ʵ����
    return NULL;
}

//�ж��ǲ���һ���Ϸ���PE�ļ�
BOOL Is_PEFile(PMEM_MODULE pMemModule, LPVOID lp_PEfile) 
{
  
    if (NULL == pMemModule || NULL == pMemModule->pApis)
        return FALSE;

    // Initialize the return value
    BOOL br = FALSE;

    // Get the DOS header
    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)lp_PEfile;

    // Check the MZ signature
    IfFalseGoExit(IMAGE_DOS_SIGNATURE == pImageDosHeader->e_magic);

    // Check PE signature
    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, lp_PEfile, pImageDosHeader->e_lfanew);
    IfFalseGoExit(IMAGE_NT_SIGNATURE == pImageNtHeader->Signature);

#ifdef _WIN64
    // Check the machine type
    if (IMAGE_FILE_MACHINE_AMD64 == pImageNtHeader->FileHeader.Machine) {
        IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR64_MAGIC == pImageNtHeader->OptionalHeader.Magic);
    }
#else
    // Check the machine type
    if (IMAGE_FILE_MACHINE_I386 == pImageNtHeader->FileHeader.Machine) {
        IfFalseGoExit(IMAGE_NT_OPTIONAL_HDR32_MAGIC == pImageNtHeader->OptionalHeader.Magic);
    }
#endif
    else
        br = FALSE;

_Exit:
    // If this is invalid PE file data return error
    if (!br)
        pMemModule->dwErrorCode = MMEC_BAD_PE_FORMAT;
    return br;
}

// ӳ��PE�Ľ���
BOOL Mapping_PESections(PMEM_MODULE pMemModule, LPVOID lp_PEfile) 
{
    // Validate
    if (NULL == pMemModule || NULL == pMemModule->pApis || NULL == lp_PEfile)
    {
        return FALSE;
    }
    Type_VirtualAlloc pfnVirtualAlloc = (Type_VirtualAlloc)(pMemModule->pApis->pfn_VirtualAlloc);
    Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pApis->pfn_VirtualFree);

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(lp_PEfile);
    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);


    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;

    PIMAGE_SECTION_HEADER pImageSectionHeader =MakePointer(
        PIMAGE_SECTION_HEADER, 
        pImageNtHeader, 
        sizeof(IMAGE_NT_HEADERS)
    );

    // Find the last section limit
    DWORD dwImageSizeLimit = 0;
    for (int i = 0; i < nNumberOfSections; ++i) 
    {
        if (0 != pImageSectionHeader[i].VirtualAddress) 
        {
            if (dwImageSizeLimit < (pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData))
            {
                dwImageSizeLimit = pImageSectionHeader[i].VirtualAddress + pImageSectionHeader[i].SizeOfRawData;
            }
        }
    }
    //dwImageSizeLimit����֮��,�����һ��������ĩβֵ
    //Ϊʲô��ֱ��ʹ��sizeofImage?��ȥ�����һ���������յ�
 

 
    LPVOID lpBase = pfnVirtualAlloc(
        (LPVOID)(pImageNtHeader->OptionalHeader.ImageBase), 
        dwImageSizeLimit,//����һ��û�ж���Ĵ�С
        MEM_RESERVE | MEM_COMMIT, 
        PAGE_READWRITE
    );
    if (NULL == lpBase) 
    {
        // ��ָ����ַ����ʧ��,Ȼ���������ĵ�ַ����
        lpBase = pfnVirtualAlloc(
            NULL, 
            dwImageSizeLimit, 
            MEM_RESERVE | MEM_COMMIT, 
            PAGE_READWRITE
        );

        // ����ʧ�ܵ����
        if (NULL == lpBase) {
            pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
            return FALSE;
        }
    }

    // Ϊʲô��Ҫ��ͷ����ѽ,
    LPVOID pDest = pfnVirtualAlloc(
        lpBase, //��֮ǰ��base��,����һ��,�����Ȳ�ʹ��?
        pImageNtHeader->OptionalHeader.SizeOfHeaders,
        MEM_COMMIT, 
        PAGE_READWRITE);

    if (!pDest) {
        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
        return FALSE;
    }

    mml_memcpy(pDest, lp_PEfile, pImageNtHeader->OptionalHeader.SizeOfHeaders);

    // Store the base address of this module.
    pMemModule->lpBase = pDest;
    pMemModule->dwSizeOfImage = pImageNtHeader->OptionalHeader.SizeOfImage;
    pMemModule->bLoadOk = TRUE;

 
    //֮ǰ����Щͷָ�����ļ�...����ָ�����¿��ٵ��ڴ�
    pImageDosHeader = (PIMAGE_DOS_HEADER)pDest;
    pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);
    pImageSectionHeader = MakePointer(PIMAGE_SECTION_HEADER, pImageNtHeader, sizeof(IMAGE_NT_HEADERS));

  
    LPVOID pSectionBase = NULL;
    LPVOID pSectionDataSource = NULL;
    for (int i = 0; i < nNumberOfSections; ++i) 
    {
        if (0 != pImageSectionHeader[i].VirtualAddress) 
        {
            pSectionBase = MakePointer(LPVOID, lpBase, pImageSectionHeader[i].VirtualAddress);

            //������Щ�ս���..������..
            if (0 == pImageSectionHeader[i].SizeOfRawData) //û���ļ�����ӳ��
            {
                DWORD size = 0;

                //���VA_Size����..��ô������,���������,,���ö����?
                if (pImageSectionHeader[i].Misc.VirtualSize > 0)//�ս���
                {
                    size = pImageSectionHeader[i].Misc.VirtualSize;
                    //���SizeͬʱҲҪ�����ڴ�����,�����������ûд��
                }
                else 
                {
                    size = pImageNtHeader->OptionalHeader.SectionAlignment;
                }
                

                //�����2��if-else�Ѿ���size>0��
                if (size > 0) 
                {
                    pDest = pfnVirtualAlloc(pSectionBase, size, MEM_COMMIT, PAGE_READWRITE);
                    if (NULL == pDest) 
                    {
                        pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
                        return FALSE;
                    }
                    mml_memset(pSectionBase, 0, size);//�ѽ�����ʼ��λ0
                }
            }
            else //�����ݵĽ���
            {
                pDest = pfnVirtualAlloc(pSectionBase, pImageSectionHeader[i].SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
                if (NULL == pDest) 
                {
                    pMemModule->dwErrorCode = MMEC_ALLOCATED_MEMORY_FAILED;
                    return FALSE;
                }
                pSectionDataSource = MakePointer(LPVOID, lp_PEfile, pImageSectionHeader[i].PointerToRawData);
                mml_memcpy(pDest, pSectionDataSource, pImageSectionHeader[i].SizeOfRawData);
            }
            pImageSectionHeader[i].Misc.PhysicalAddress = (DWORD)(ULONGLONG)pDest;
        }
    }

    return TRUE;
}

//�ض�λ����
BOOL RelocateModuleBase(PMEM_MODULE pMemModule) 
{
    
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =MakePointer(
        PIMAGE_NT_HEADERS, 
        pMemModule->pImageDosHeader, 
        pMemModule->pImageDosHeader->e_lfanew);

    //��ʵ�Ļ�ַ-ImageBase
    LONGLONG lBaseDelta = ((PBYTE)pMemModule->iBase - (PBYTE)pImageNtHeader->OptionalHeader.ImageBase);

    //�����ַû��,Ҳ�ͷ�����
    if (0 == lBaseDelta)
    {
        return TRUE;
    }

    //���û���ض�λ��,�ͷ�����
    if (0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        ||
        0 == pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
    {
        return TRUE;
    }

    PIMAGE_BASE_RELOCATION pImageBaseRelocation =MakePointer(
        PIMAGE_BASE_RELOCATION, 
        pMemModule->lpBase,
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
    );

    if (NULL == pImageBaseRelocation) 
    {
        pMemModule->dwErrorCode = MMEC_INVALID_RELOCATION_BASE;
        return FALSE;
    }

    //�����������Ϊ0��
    while (0 != (pImageBaseRelocation->VirtualAddress + pImageBaseRelocation->SizeOfBlock))  
    {
        PWORD pRelocationData = MakePointer(
            PWORD, 
            pImageBaseRelocation, 
            sizeof(IMAGE_BASE_RELOCATION)
        );
        int NumberOfRelocationData = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        //�ô���ҲҪ�ض�λ�ĸ���
        for (int i = 0; i < NumberOfRelocationData; i++) 
        {
            if (IMAGE_REL_BASED_HIGHLOW == (pRelocationData[i] >> 12)) //ȡ����־λ,���Ƿ���Ҫ�ض�λ
            {
                PDWORD pAddress =(PDWORD)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                //�ҵ�ʵ�ʵ�ַ,Ȼ�����������
                *pAddress += (DWORD)lBaseDelta;//���϶�Ӧ�Ĳ�ֵ
            }

#ifdef _WIN64
            if (IMAGE_REL_BASED_DIR64 == (pRelocationData[i] >> 12)) 
            {
                PULONGLONG pAddress =(PULONGLONG)(pMemModule->iBase + pImageBaseRelocation->VirtualAddress + (pRelocationData[i] & 0x0FFF));
                *pAddress += lBaseDelta;
            }
#endif
        }
        pImageBaseRelocation = MakePointer(PIMAGE_BASE_RELOCATION, pImageBaseRelocation, pImageBaseRelocation->SizeOfBlock);
    }
    return TRUE;
}

//������ʼ������
BOOL Init_ImportTable(PMEM_MODULE pMemModule) 
{
    if (NULL == pMemModule || NULL == pMemModule->pApis || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    Type_GetModuleHandleA pfnGetModuleHandleA = (Type_GetModuleHandleA)(pMemModule->pApis->pfn_GetModuleHandleA);
    Type_LoadLibraryA pfnLoadLibraryA = (Type_LoadLibraryA)(pMemModule->pApis->pfn_LoadLibraryA);
    Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)(pMemModule->pApis->pfn_GetProcAddress);

    PIMAGE_NT_HEADERS pImageNtHeader =MakePointer(
        PIMAGE_NT_HEADERS, 
        pMemModule->pImageDosHeader,
        pMemModule->pImageDosHeader->e_lfanew);

    //û�е����ֱ�ӷ���
    if (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0 ||
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
        return TRUE;

    //�ҵ������
    PIMAGE_IMPORT_DESCRIPTOR pImageImportDescriptor =MakePointer(
        PIMAGE_IMPORT_DESCRIPTOR, 
        pMemModule->lpBase,
        pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


    //������������,������dll����Ϊ��
    for (; pImageImportDescriptor->Name; pImageImportDescriptor++) //�жϺ�,ֱ����һ����������
    {
        // Get the dependent module name
        PCHAR pDllName = MakePointer(
            PCHAR, 
            pMemModule->lpBase, 
            pImageImportDescriptor->Name);

        // Get the dependent module handle
        HMODULE hMod = pfnGetModuleHandleA(pDllName);//���������dll

        // Load the dependent module
        if (NULL == hMod)//�������û�еĻ�..���������ض�Ӧ��dll
        {
            hMod = pfnLoadLibraryA(pDllName);
        }

        // Failed
        if (NULL == hMod) {
            pMemModule->dwErrorCode = MMEC_IMPORT_MODULE_FAILED;
            return FALSE;//����������޷�����,�Ǿ�ֱ��g
        }
       
        //�����INT������ʹ��,û�о�����IAT����,,,��Ϊ������˫�Ż��ߵ��ŵĽṹ
        PIMAGE_THUNK_DATA p_INT_Thunk = NULL;
        if (pImageImportDescriptor->OriginalFirstThunk)
            p_INT_Thunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->OriginalFirstThunk);
        else
            p_INT_Thunk = MakePointer(PIMAGE_THUNK_DATA, pMemModule->lpBase, pImageImportDescriptor->FirstThunk);

      

        // IAT thunk
        PIMAGE_THUNK_DATA p_IAT_Thunk =MakePointer(
            PIMAGE_THUNK_DATA, 
            pMemModule->lpBase, 
            pImageImportDescriptor->FirstThunk);

        for (; p_INT_Thunk->u1.AddressOfData; p_INT_Thunk++, p_IAT_Thunk++) 
        {
            FARPROC lpFunction = NULL;

            //��ʵ�ַ�Ϊ���Ƶ����ID����,,,
            if (IMAGE_SNAP_BY_ORDINAL(p_INT_Thunk->u1.Ordinal)) 
            {
                lpFunction = pfnGetProcAddress(
                    hMod, 
                    (LPCSTR)IMAGE_ORDINAL(p_INT_Thunk->u1.Ordinal)
                );//ID����
            }
            else 
            {
                PIMAGE_IMPORT_BY_NAME pImageImportByName =MakePointer(
                    PIMAGE_IMPORT_BY_NAME, 
                    pMemModule->lpBase, 
                    p_INT_Thunk->u1.AddressOfData);

                lpFunction = pfnGetProcAddress(
                    hMod, 
                    (LPCSTR) & (pImageImportByName->Name)//���Ƶ���
                );
            }

            // д��IAT��
#ifdef _WIN64
            pIATThunk->u1.Function = (ULONGLONG)lpFunction;
#else
            p_IAT_Thunk->u1.Function = (DWORD)lpFunction;
#endif
        }
    }

    return TRUE;
}


// Ϊ������ȷ�������ڴ�����..���������Ȼ���Ǻܱ�Ҫ,����һ��Ҳ���кô���
BOOL Set_SectionMemAttribution(PMEM_MODULE pMemModule) 
{
    if (NULL == pMemModule || NULL == pMemModule->pApis)
    {
        return FALSE;
    }

    int ProtectionMatrix[2][2][2] = 
    {
        {
            // not executable
            {PAGE_NOACCESS, PAGE_WRITECOPY},
            {PAGE_READONLY, PAGE_READWRITE},
        },
        {
            // executable
            {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
            {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE},
        },
    };

    Type_VirtualProtect pfnVirtualProtect = (Type_VirtualProtect)(pMemModule->pApis->pfn_VirtualProtect);
    Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pApis->pfn_VirtualFree);

    PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)(pMemModule->lpBase);

    ULONGLONG ulBaseHigh = 0;
#ifdef _WIN64
    ulBaseHigh = (pMemModule->iBase & 0xffffffff00000000);
#endif

    PIMAGE_NT_HEADERS pImageNtHeader = MakePointer(PIMAGE_NT_HEADERS, pImageDosHeader, pImageDosHeader->e_lfanew);

    int nNumberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER pImageSectionHeader = MakePointer(
        PIMAGE_SECTION_HEADER, 
        pImageNtHeader, 
        sizeof(IMAGE_NT_HEADERS)
    );

    for (int idxSection = 0; idxSection < nNumberOfSections; idxSection++) {
        DWORD protectFlag = 0;
        DWORD oldProtect = 0;
        BOOL isExecutable = FALSE;
        BOOL isReadable = FALSE;
        BOOL isWritable = FALSE;

        BOOL isNotCache = FALSE;
        ULONGLONG dwSectionBase = (pImageSectionHeader[idxSection].Misc.PhysicalAddress | ulBaseHigh);
        DWORD dwSecionSize = pImageSectionHeader[idxSection].SizeOfRawData;//�����һ���ս���..�Ͳ�������������?�����..
        if (0 == dwSecionSize)
        {
            continue;
        }

        // This section is in this page
        DWORD dwSectionCharacteristics = pImageSectionHeader[idxSection].Characteristics;//�õ���������

        // Discardable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_DISCARDABLE) {
            pfnVirtualFree((LPVOID)dwSectionBase, dwSecionSize, MEM_DECOMMIT);
            continue;
        }

        // Executable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_EXECUTE)
            isExecutable = TRUE;

        // Readable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_READ)
            isReadable = TRUE;

        // Writable
        if (dwSectionCharacteristics & IMAGE_SCN_MEM_WRITE)
            isWritable = TRUE;

        if (dwSectionCharacteristics & IMAGE_SCN_MEM_NOT_CACHED)
            isNotCache = TRUE;

        protectFlag = ProtectionMatrix[isExecutable][isReadable][isWritable];
        if (isNotCache)
        {
            protectFlag |= PAGE_NOCACHE;
        }
        if (!pfnVirtualProtect((LPVOID)dwSectionBase, dwSecionSize, protectFlag, &oldProtect)) {
            pMemModule->dwErrorCode = MMEC_PROTECT_SECTION_FAILED;
            return FALSE;
        }
    }
    return TRUE;
}

//����TLS����
BOOL HandleTlsData(PMEM_MODULE pMemModule) 
{
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    IMAGE_DATA_DIRECTORY imageDirectoryEntryTls = pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    //û��Tls�ͷ��ذ�
    if (imageDirectoryEntryTls.VirtualAddress == 0)
    {
        return TRUE;
    }

    PIMAGE_TLS_DIRECTORY tls = (PIMAGE_TLS_DIRECTORY)(pMemModule->iBase + imageDirectoryEntryTls.VirtualAddress);

    // TO-DO
    // here we need to process the TLS data for all running threads, this is very heavy and danger operation
    // refer to: http://www.nynaeve.net/?p=189
    // ���exe����һ���߳�,������Tls�Ļ�,,���Զ�����?

    // execute tls callback if any
    PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks;
    if (callback) 
    {
        while (*callback) 
        {
            //����Ӧ�����ض�λ�˵�..Ȼ��ֱ�ӵ���
            (*callback)((LPVOID)pMemModule->hModule, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
    return TRUE;
}

/// <summary>
/// Calls the module entry.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="dwReason">The reason of the calling.</param>
/// <returns>True if successful.</returns>
BOOL CallModuleEntry(PMEM_MODULE pMemModule, DWORD dwReason) {
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return FALSE;

    PIMAGE_NT_HEADERS pImageNtHeader =MakePointer(
        PIMAGE_NT_HEADERS, 
        pMemModule->pImageDosHeader,
        pMemModule->pImageDosHeader->e_lfanew
    );

    Type_DllMain pfnModuleEntry = NULL;

    // If there is no entry point return false
    if (0 == pImageNtHeader->OptionalHeader.AddressOfEntryPoint) {
        return FALSE;
    }

    pfnModuleEntry = MakePointer(
        Type_DllMain, 
        pMemModule->lpBase, 
        pImageNtHeader->OptionalHeader.AddressOfEntryPoint);

    if (NULL == pfnModuleEntry) {
        pMemModule->dwErrorCode = MMEC_INVALID_ENTRY_POINT;
        return FALSE;
    }

    return pfnModuleEntry(pMemModule->hModule, dwReason, NULL);
}

/// <summary>
/// Gets the exported function address.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <param name="lpName">The function name.</param>
/// <returns>The address of the function or null.</returns>
FARPROC GetExportedProcAddress(PMEM_MODULE pMemModule, LPCSTR lpName) {
    if (NULL == pMemModule || NULL == pMemModule->pImageDosHeader)
        return NULL;

    PIMAGE_NT_HEADERS pImageNtHeader =
        MakePointer(PIMAGE_NT_HEADERS, pMemModule->pImageDosHeader, pMemModule->pImageDosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
        MakePointer(PIMAGE_EXPORT_DIRECTORY, pMemModule->lpBase,
            pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD pAddressOfNames = MakePointer(PDWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfNames);

    PWORD pAddressOfNameOrdinals = MakePointer(PWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfNameOrdinals);

    PDWORD pAddressOfFunctions = MakePointer(PDWORD, pMemModule->lpBase, pImageExportDirectory->AddressOfFunctions);

    int nNumberOfFunctions = pImageExportDirectory->NumberOfFunctions;
    for (int i = 0; i < nNumberOfFunctions; ++i) {
        DWORD dwAddressOfName = pAddressOfNames[i];

        LPCSTR pFunctionName = MakePointer(LPCSTR, pMemModule->lpBase, dwAddressOfName);

        if (0 == mml_strcmpA(lpName, pFunctionName)) {
            WORD wOrdinal = pAddressOfNameOrdinals[i];
            DWORD dwFunctionOffset = pAddressOfFunctions[wOrdinal];
            FARPROC pfnTargetProc = MakePointer(FARPROC, pMemModule->lpBase, dwFunctionOffset);

            return pfnTargetProc;
        }
    }

    return NULL;
}

/// <summary>
/// Unmaps all the sections.
/// </summary>
/// <param name="pMemModule">The <see cref="MemModule" /> instance.</param>
/// <returns>True if successful.</returns>
VOID UnmapMemModule(PMEM_MODULE pMemModule) {
    if (NULL == pMemModule || NULL == pMemModule->pApis || FALSE == pMemModule->bLoadOk || NULL == pMemModule->lpBase)
        return;

    Type_VirtualFree pfnVirtualFree = (Type_VirtualFree)(pMemModule->pApis->pfn_VirtualFree);

    pfnVirtualFree(pMemModule->lpBase, 0, MEM_RELEASE);

    pMemModule->lpBase = NULL;
    pMemModule->dwCRC32 = 0;
    pMemModule->dwSizeOfImage = 0;
    pMemModule->bLoadOk = FALSE;
}

 
// ����PE�ļ���CRC32ֵ
UINT32 GetCRC32(UINT32 uInit, void* pBuf, UINT32 nBufSize) 
{
#define CRC32_POLY 0x04C10DB7L
    UINT32 crc = 0;
    UINT32 Crc32table[256];
    for (int i = 0; i < 256; i++) 
    {
        crc = (UINT32)(i << 24);
        for (int j = 0; j < 8; j++) 
        {
            if (crc >> 31)
                crc = (crc << 1) ^ CRC32_POLY;
            else
                crc = crc << 1;
        }
        Crc32table[i] = crc;
    }

    crc = uInit;
    UINT32 nCount = nBufSize;
    PUCHAR p = (PUCHAR)pBuf;
    while (nCount--) 
    {
        crc = (crc << 8) ^ Crc32table[(crc >> 24) ^ *p++];
    }

    return crc;
}

/// <summary>
/// Gets the length of the ANSI string.
/// </summary>
/// <param name="psz">The string.</param>
int mml_strlenA(const char* psz) {
    int i = 0;
    for (; *psz; psz++, i++)
        ;
    return i;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int mml_strcmpA(const char* psza, const char* pszb) {
    unsigned char c1 = 0;
    unsigned char c2 = 0;

    do {
        c1 = (unsigned char)*psza++;
        c2 = (unsigned char)*pszb++;
        if (c1 == 0)
            return c1 - c2;
    } while (c1 == c2);

    return c1 - c2;
}

/// <summary>
/// Compares the two strings.
/// </summary>
/// <param name="psza">The first string.</param>
/// <param name="pszb">The second string.</param>
int mml_stricmpW(const wchar_t* pwsza, const wchar_t* pwszb) {
    unsigned short c1 = 0;
    unsigned short c2 = 0;

    do {
        c1 = (unsigned short)*pwsza++;
        if (c1 >= 65 && c1 <= 90) {
            c1 = c1 + 32;
        }

        c2 = (unsigned short)*pwszb++;
        if (c2 > 65 && c2 < 90) {
            c2 = c2 + 32;
        }

        if (c1 == 0)
            return c1 - c2;
    } while (c1 == c2);

    return c1 - c2;
}

/// <summary>
/// Copys the string from source to destination buffer.
/// </summary>
/// <param name="pszDest">The destination string buffer.</param>
/// <param name="pszSrc">The source string.</param>
/// <param name="nMax">Maximum count of the character to copy.</param>
wchar_t* mml_strcpyW(wchar_t* pszDest, const wchar_t* pszSrc, unsigned int nMax) {
    while (nMax--) {
        *pszDest++ = *pszSrc++;
        if (*pszSrc == 0)
            break;
    }
    return pszDest;
}

#pragma optimize("gtpy", off)
/// <summary>
/// Sets the memory with specific value.
/// </summary>
void* mml_memset(void* pv, int c, unsigned int cb) {
    for (unsigned int i = 0; i < cb; i++)
        ((unsigned char*)pv)[i] = (unsigned char)c;
    return pv;
}
#pragma optimize("gtpy", on)

/// <summary>
/// Moves the source memory data to the destination buffer.
/// </summary>
/// <param name="pvDest">The destination buffer.</param>
/// <param name="pvSrc">The source memory buffer.</param>
/// <param name="cb">The count of the bytes to move.</param>
void* mml_memcpy(void* pvDest, const void* pvSrc, unsigned int cb) {
    unsigned char* pb1 = 0;
    unsigned char* pb2 = 0;

    if (pvSrc < pvDest) {
        pb1 = (unsigned char*)pvDest + cb - 1;
        pb2 = (unsigned char*)pvSrc + cb - 1;
        for (; cb; cb--)
            *pb1-- = *pb2--;
    }
    else if (pvSrc > pvDest) {
        pb1 = (unsigned char*)pvDest;
        pb2 = (unsigned char*)pvSrc;
        for (; cb; cb--)
            *pb1++ = *pb2++;
    }
    return pvDest;
}

/// <summary>
/// Mark.
/// </summary>
void mmLoaderCodeEnd() {
    return;
}

#pragma endregion mmLoaderImpl