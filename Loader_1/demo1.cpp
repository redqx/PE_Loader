// demo-mmloader-static.cpp : Defines the entry point for the console application.
//
 
#include <tchar.h>
#include <windows.h>

#include <strsafe.h>

#include "mmLoader.h"

//加载文件到内存,,并自动的释放
class AutoRelease_ModuleBuffer {
public:
    AutoRelease_ModuleBuffer(LPCTSTR szDllPath) : m_pBuffer(NULL), m_hFileMapping(NULL), m_hFile(NULL) 
    {
        m_hFile = ::CreateFile(
            szDllPath, 
            GENERIC_READ, 
            FILE_SHARE_READ,
            NULL, 
            OPEN_EXISTING, 
            NULL, 
            NULL);
        if (INVALID_HANDLE_VALUE == m_hFile || NULL == m_hFile) {
            _tprintf(_T("Failed to open the file: %s\r\n"), szDllPath);
            return;
        }
        DWORD dwFileSize = ::GetFileSize(m_hFile, NULL);
        if (INVALID_FILE_SIZE == dwFileSize || dwFileSize < sizeof(IMAGE_DOS_HEADER)) {
            ::CloseHandle(m_hFile);
            m_hFile = NULL;
            _tprintf(_T("Invalid file size: %d\r\n"), dwFileSize);
            return;
        }

        m_hFileMapping = ::CreateFileMapping(
            m_hFile, 0,
            PAGE_READONLY, 0, 0, 
            NULL);
        if (NULL == m_hFileMapping)
        {
            ::CloseHandle(m_hFile);
            m_hFile = NULL;
            _tprintf(_T("Failed to create file mapping.\r\n"));
            return;
        }

        m_pBuffer = ::MapViewOfFile(
            m_hFileMapping, 
            FILE_MAP_READ, 
            0, 0, 0);
        if (NULL == m_pBuffer) 
        {
            ::CloseHandle(m_hFileMapping);
            ::CloseHandle(m_hFile);
            m_hFileMapping = NULL;
            m_hFile = NULL;
            _tprintf(_T("Failed to map view of the file.\r\n"));
        }
    }

    ~AutoRelease_ModuleBuffer() { 
        Release(); 
    }

    void
        Release() {
        if (m_pBuffer) {
            ::UnmapViewOfFile(m_pBuffer);
            m_pBuffer = NULL;
        }

        if (m_hFileMapping) {
            ::CloseHandle(m_hFileMapping);
            m_hFileMapping = NULL;
        }

        if (m_hFile) {
            ::CloseHandle(m_hFile);
            m_hFile = NULL;
        }
    }

    operator LPVOID()
    { 
        return m_pBuffer; 
    }

private:
    LPVOID m_pBuffer;
    HANDLE m_hFile;
    HANDLE m_hFileMapping;
};

int main() {

    int iRet = -1;

    HMEMMODULE hMemModule = NULL;
    DWORD dwErrorCode = 0;

    TCHAR szDllPath[] = _T("D:\\work\\码云\\我的开发项目\\PE_Loader\\Debug\\demo_exe.exe");
    AutoRelease_ModuleBuffer moduleBuffer(szDllPath);

    hMemModule = (HMEMMODULE)my_Loader(MHM_BOOL_LOAD, moduleBuffer, (LPVOID)TRUE, &dwErrorCode);
    moduleBuffer.Release();


    //如果是加载exe的话,这里不会进入
    //如果是加载dll的函数的话这里可能会进入
    if (hMemModule) 
    {
        _tprintf(_T("Module was loaded successfully. Module Base: 0x%p!\r\n"), (LPVOID)hMemModule);
        LPVOID lpAddr = (LPVOID)my_Loader(MHM_FARPROC_GETPROC, hMemModule, (LPVOID)"demoFunction", (VOID*)TRUE);
        if (lpAddr) {
            _tprintf(_T("Get address of demoFunction successfully. Address: 0x%p!\r\n"), lpAddr);

            // Function pointer type of demoFunction
            typedef BOOL(_stdcall* Type_TargetFunction)(unsigned char*, unsigned int);

            // Call the demoFunction
            Type_TargetFunction pfnFunction = (Type_TargetFunction)lpAddr;

            unsigned char buf[MAX_PATH] = { 0 };

            if (pfnFunction(buf, MAX_PATH)) {
                char p[] = "{f56fee02-16d1-44a3-b191-4d7535f92ca5}";
                iRet = ::memcmp(buf, p, strlen(p));
                if (0 == iRet)
                    _tprintf(_T("Called target function demoFunction successfully with correct return value!\r\n"));
                else
                    _tprintf(_T("Called target function demoFunction successfully, but returned unexpected value!\r\n"));
            }
        }
        else
            _tprintf(_T("Failed to get address of demoFunction from memory module.\r\n"));

        // Free the module
        my_Loader(MHM_VOID_FREE, hMemModule, 0, 0);
    }
    else
        _tprintf(_T("Failed to load the module!\r\n"));

    return iRet;
}