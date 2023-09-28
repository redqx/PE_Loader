#include <Windows.h>
#include <stdio.h>
#pragma comment(linker, "/INCLUDE:__tls_used")


VOID _stdcall TLS_A(PVOID DllHandle, DWORD Reason, PVOID Reserved);
VOID _stdcall TLS_B(PVOID DllHandle, DWORD Reason, PVOID Reserved);
//然后巴拉巴拉注册
#pragma data_seg(".CRT$XLB")
PIMAGE_TLS_CALLBACK p_thread_callback[] = { TLS_B, TLS_A };
#pragma data_seg()

//然后巴拉巴拉
int main()
{
	printf("hello i am main\n");
	return 0;
}
VOID _stdcall TLS_A(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	printf("hello i am TLS A\n");
	return;
}
VOID _stdcall TLS_B(PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
	printf("hello i am TLS B\n");
	return;
}