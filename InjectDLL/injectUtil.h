#pragma once


BOOL SetDebugPrivilege();
BOOL DLLInjectByRemoteThread(DWORD dwPID, LPCWSTR lpszDLLPath);
BOOL DLLEjectByRemoteThread(DWORD dwPID, LPCWSTR lpszDLLPath);