#include "pch.h"
#include "framework.h"
#include "injectUtil.h"
#include <winternl.h>
#include <TlHelp32.h>
typedef NTSTATUS(NTAPI* pfnNtCreateThreadEx)
(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT LPVOID lpBytesBuffer);


typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT CLIENT_ID* ClientId OPTIONAL);
BOOL SetDebugPrivilege()
{

	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	BOOL bRet = FALSE;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	if (!LookupPrivilegeValue(
		NULL,            
		SE_DEBUG_NAME,  
		&luid))       
	{

		CloseHandle(hToken);
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		CloseHandle(hToken);
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{

		CloseHandle(hToken);
		return FALSE;
	}

	CloseHandle(hToken);
	
	return TRUE;
}
BOOL DLLEjectByRemoteThread(DWORD dwPID, LPCWSTR lpszDLLPath)
{
	HMODULE hKernel32 = NULL;
	HMODULE hNTDLL = NULL;
	FARPROC lpfnFreeLibrary = NULL;
	pfnNtCreateThreadEx fpNtCreateThread = NULL;
	HANDLE hTargetProc = NULL;
	LPVOID dllPathAlloc = NULL;
	BOOL bSuccess = TRUE;
	HANDLE hThread = NULL;

	HANDLE hSnapshot = NULL;
	HMODULE hModule = NULL;
	MODULEENTRY32 me = { sizeof(me) };

	if (wcslen(lpszDLLPath) == 0)
	{
		bSuccess = FALSE;
		goto EXIT;
	}

	if (!PathFileExists(lpszDLLPath))
	{
		bSuccess = FALSE;
		OutputDebugString(_T("Error: DLL File is not exists"));
		goto EXIT;
	}

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	BOOL bFound = FALSE;
	for (BOOL bMore = Module32First(hSnapshot, &me); bMore; bMore = Module32Next(hSnapshot, &me))
	{
	
	
		if (!wcscmp(me.szExePath, lpszDLLPath))
		{
			bFound = TRUE;
			break;
		}
	}
	if (!bFound)
	{
		bSuccess = FALSE;
		OutputDebugString(_T("Error: can't find moudule "));
		goto EXIT;
	}
	hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hTargetProc)
	{
		bSuccess = FALSE;
		OutputDebugString(_T("Error: fail to open Target process "));
		goto EXIT;
	}

	hKernel32 = LoadLibrary(L"Kernel32.dll");
	if (!hKernel32)
	{
		OutputDebugString(_T("Error: LoadLibrary Kernel32.dll "));
		bSuccess = FALSE;
		goto EXIT;
	}
	lpfnFreeLibrary = GetProcAddress(hKernel32, "FreeLibrary");

	if (!lpfnFreeLibrary)
	{
		OutputDebugString(_T("Error: GetProcAddress FreeLibrary "));
		bSuccess = FALSE;
		goto EXIT;

	}

	hThread = CreateRemoteThread(hTargetProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpfnFreeLibrary, me.modBaseAddr, 0, NULL);
	if (!hThread)
	{
		OutputDebugString(_T("Error: CreateRemoteThread fail "));
		DWORD dwError = GetLastError();
	//	dwError = 8;
		if (dwError == 5)
		{
			OutputDebugString(_T("Error: CreateRemoteThread GetLastError 5 "));
			bSuccess = FALSE;
			goto EXIT;
		}

		if (dwError == 8)
		{
			OutputDebugString(_T("Error: CreateRemoteThread GetLastError 8 "));


			hNTDLL = LoadLibrary(L"ntdll.dll");
			if (!hNTDLL)
			{
				bSuccess = FALSE;
				goto EXIT;
			}

	


			fpNtCreateThread = (pfnNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
			if (!fpNtCreateThread)
			{
				bSuccess = FALSE;
				goto EXIT;
			}

			NTSTATUS status = fpNtCreateThread(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProc, (LPTHREAD_START_ROUTINE)lpfnFreeLibrary, me.modBaseAddr, FALSE, NULL, NULL, NULL, NULL);
			if (NT_SUCCESS(status) && hThread != NULL)
			{
				OutputDebugString(_T("success ntCreateThreadEx"));
			}
			else
			{
				bSuccess = FALSE;
				goto EXIT;
			}
		}

	}

	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
	}
	OutputDebugString(_T("success eject"));

EXIT:
	if (hSnapshot)
	{
		CloseHandle(hSnapshot);
	}
	if (dllPathAlloc)
	{
		VirtualFreeEx(hTargetProc, dllPathAlloc, 0, MEM_RELEASE);
	}

	if (hTargetProc)
	{
		CloseHandle(hTargetProc);
	}
	if (hThread)
	{
		CloseHandle(hThread);
	}
	if (hNTDLL)
	{
		FreeLibrary(hNTDLL);
	}
	if (hKernel32)
	{
		FreeLibrary(hKernel32);
	}

	return bSuccess;
}

BOOL DLLInjectByRemoteThread(DWORD dwPID, LPCWSTR lpszDLLPath )
{
	HMODULE hKernel32 = NULL;
	HMODULE hNTDLL = NULL;
	FARPROC lpfnLoadLibrary = NULL;
	pfnNtCreateThreadEx fpNtCreateThread = NULL;
	HANDLE hTargetProc = NULL; 
	LPVOID dllPathAlloc = NULL;
	BOOL bSuccess = TRUE;
	HANDLE hThread = NULL;
	
	if (wcslen(lpszDLLPath) == 0)
	{
		bSuccess = FALSE;
		goto EXIT;
	}

	if (!PathFileExists(lpszDLLPath))
	{
		bSuccess = FALSE;
		OutputDebugString(_T("Error: DLL File is not exists"));
		goto EXIT;
	}

	hTargetProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (!hTargetProc)
	{
		bSuccess = FALSE;
		OutputDebugString(_T("Error: fail to open Target process "));
		goto EXIT;
	}

	dllPathAlloc = VirtualAllocEx(hTargetProc, NULL, sizeof(WCHAR) * MAX_PATH, MEM_COMMIT, PAGE_READWRITE);

	if (dllPathAlloc == NULL)
	{
		OutputDebugString(_T("Error: VirtualAllocEx  "));
		bSuccess = FALSE;
		goto EXIT;
	}

	if (!WriteProcessMemory(hTargetProc, dllPathAlloc, lpszDLLPath, sizeof(WCHAR) * wcslen(lpszDLLPath) +sizeof(WCHAR), NULL))
	{
		OutputDebugString(_T("Error: WriteProcessMemory  "));
		bSuccess = FALSE;
		goto EXIT;
	}

	hKernel32=LoadLibrary(L"Kernel32.dll");
	if (!hKernel32)
	{
		OutputDebugString(_T("Error: LoadLibrary Kernel32.dll "));
		bSuccess = FALSE;
		goto EXIT;
	}
	lpfnLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryW");

	if (!lpfnLoadLibrary)
	{
		OutputDebugString(_T("Error: GetProcAddress LoadLibraryW "));
		bSuccess = FALSE;
		goto EXIT;

	}

	hThread = CreateRemoteThread(hTargetProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpfnLoadLibrary, dllPathAlloc, 0, NULL);
	if (hThread == NULL)
	{
		OutputDebugString(_T("Error: CreateRemoteThread fail "));
		DWORD dwError = GetLastError();
		if (dwError == 5)
		{
			OutputDebugString(_T("Error: CreateRemoteThread GetLastError 5 "));
			bSuccess = FALSE;
			goto EXIT;
		}

		if (dwError == 8)
		{
			OutputDebugString(_T("Error: CreateRemoteThread GetLastError 8 "));
			hNTDLL = LoadLibrary(L"ntdll.dll");
			if (!hNTDLL)
			{
				bSuccess = FALSE;
				goto EXIT;
			}

		
			CLIENT_ID cid;
			pfnRtlCreateUserThread RtlCreateUserThread = (pfnRtlCreateUserThread)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "RtlCreateUserThread");
			if (RtlCreateUserThread)
			{

				NTSTATUS status = 0;
				status = RtlCreateUserThread(hTargetProc, NULL, FALSE, 0, 0, 0, (LPTHREAD_START_ROUTINE)lpfnLoadLibrary, dllPathAlloc, &hThread, &cid);
				if (NT_SUCCESS(status) && hThread != NULL)
				{
					OutputDebugString(_T("success RtlCreateUserThread"));
					
			
				}
				else
				{
					OutputDebugString(_T("fail RtlCreateUserThread"));
					bSuccess = FALSE;
					goto EXIT;
				}
			}
			else
			{
				bSuccess = FALSE;
				goto EXIT;
			}
/*NtCreateThreadEx
			fpNtCreateThread = (pfnNtCreateThreadEx)GetProcAddress(hNTDLL, "NtCreateThreadEx");
			if (!fpNtCreateThread)
			{
				bSuccess = FALSE;
				goto EXIT;
			}

			NTSTATUS status = fpNtCreateThread(&hThread, THREAD_ALL_ACCESS, NULL, hTargetProc, (LPTHREAD_START_ROUTINE)lpfnLoadLibrary, dllPathAlloc, FALSE, NULL, NULL, NULL, NULL);
			if (NT_SUCCESS(status) && hThread != NULL)
			{
				OutputDebugString(_T("success ntCreateThreadEx"));
			}
			else
			{
				bSuccess = FALSE;
				goto EXIT;
			}
			*/
		}
	
	}
	OutputDebugString(_T("success inject"));
	if (hThread)
	{
		WaitForSingleObject(hThread, INFINITE);
	}

EXIT:
	
	if (dllPathAlloc)
	{
		VirtualFreeEx(hTargetProc, dllPathAlloc, 0, MEM_RELEASE);
	}

	if (hTargetProc)
	{
		CloseHandle(hTargetProc);
	}
	if (hThread)
	{
		CloseHandle(hThread);
	}
	if (hNTDLL)
	{
		FreeLibrary(hNTDLL);
	}
	if (hKernel32)
	{
		FreeLibrary(hKernel32);
	}

	return bSuccess;

}