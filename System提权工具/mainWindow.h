#pragma once
#include<Windows.h>
#include<TlHelp32.h>
#include<filesystem>
#include<iostream>
#include <shellscalingapi.h>
#pragma comment(lib,"Shcore.lib")
#ifdef _UNICODE
#if defined _M_IX86
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='x86' publicKeyToken='6595b64144ccf1df' language='*'\"")
#elif defined _M_X64
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\"")
#else
#pragma comment(linker,"/manifestdependency:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif
#endif



bool check_file_extensionA(const std::string& path, const std::string& expected_ext) {

	std::filesystem::path file_path(path);


	std::string actual_ext = file_path.extension().string();
	std::transform(actual_ext.begin(), actual_ext.end(), actual_ext.begin(), ::tolower);


	if (!actual_ext.empty() && actual_ext[0] == '.') {
		actual_ext.erase(0, 1);
	}

	
	return actual_ext == expected_ext;
}
bool check_file_extensionW(const std::wstring& path, const std::wstring& expected_ext) {
	
	size_t pos = path.find_last_of(L'.');

	
	if (pos == std::wstring::npos || pos == 0) {
		return false;
	}

	std::wstring actual_ext = path.substr(pos + 1);
	std::transform(actual_ext.begin(), actual_ext.end(), actual_ext.begin(), towlower);


	std::wstring lower_expected_ext(expected_ext);
	std::transform(lower_expected_ext.begin(), lower_expected_ext.end(), lower_expected_ext.begin(), towlower);

	return actual_ext == lower_expected_ext;
}

BOOL EnablePrivilege(LPCTSTR szPrivilege, BOOL fEnable) {
	BOOL fOk = FALSE;
	HANDLE hToken = NULL;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, szPrivilege, &tp.Privileges[0].Luid);
		tp.Privileges->Attributes = fEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
		fOk = (GetLastError() == ERROR_SUCCESS);

		CloseHandle(hToken);
	}
	return fOk;
}


DWORD getPidFromName(LPCWSTR processName) {
	PROCESSENTRY32W processEntry = { 0 };
	processEntry.dwSize = sizeof(PROCESSENTRY32W);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (Process32FirstW(hSnapshot, &processEntry)) {
		do {
			if ((lstrcmpiW(processName, processEntry.szExeFile)) == 0) {
				return processEntry.th32ProcessID;
			}
		} while (Process32NextW(hSnapshot, &processEntry));
	}
	return -1;
}

struct mySTARTUPINFOEXW {
	STARTUPINFOW StartupInfo;
	PVOID lpAttributeList;
};

struct myPROCESS_INFORMATION {
	HANDLE hProcess;
	HANDLE hThread;
	DWORD dwProcessId;
	DWORD dwThreadId;
};

struct mySECURITY_ATTRIBUTES {
	DWORD nLength;
	LPVOID lpSecurityDescriptor;
	BOOL bInheritHandle;
};

VOID CreateSystemFromParent(DWORD parentProcessID, LPCWSTR processname, LPWSTR cmdargs) {

	const DWORD my_EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
	const DWORD my_CREATE_NEW_CONSOLE = 0x00000010;
	const DWORD my_PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

	myPROCESS_INFORMATION pi = { 0 };
	mySTARTUPINFOEXW si = { 0 };
	si.StartupInfo.cb = sizeof(si);

	SIZE_T size = 0;
	InitializeProcThreadAttributeList(NULL, 1, 0, &size);
	si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)new char[size];

	InitializeProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)si.lpAttributeList, 1, 0, &size);

	HANDLE phandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, parentProcessID);

	auto lpValue = new HANDLE();
	*lpValue = phandle;

	UpdateProcThreadAttribute((LPPROC_THREAD_ATTRIBUTE_LIST)si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValue, sizeof(HANDLE), NULL, NULL);

	mySECURITY_ATTRIBUTES saProcess = { 0 };
	saProcess.nLength = sizeof(mySECURITY_ATTRIBUTES);
	saProcess.bInheritHandle = TRUE;

	mySECURITY_ATTRIBUTES saThread = { 0 };
	saThread.nLength = sizeof(mySECURITY_ATTRIBUTES);
	saThread.bInheritHandle = TRUE;

	CreateProcessW(processname,cmdargs, (LPSECURITY_ATTRIBUTES)&saProcess, (LPSECURITY_ATTRIBUTES)&saThread, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, (STARTUPINFOW*)&si, (LPPROCESS_INFORMATION)&pi);

	DeleteProcThreadAttributeList((LPPROC_THREAD_ATTRIBUTE_LIST)si.lpAttributeList);
	CloseHandle(phandle);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	delete[](char*)si.lpAttributeList;
	delete lpValue;
}
VOID CreateTrustedinstallerFromParent(LPCWSTR processname, LPWSTR cmdargs) {

	// Start the TrustedInstaller service
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

	SC_HANDLE schService = OpenService(schSCManager, TEXT("TrustedInstaller"), SERVICE_START);

	StartService(schService, 0, NULL);

	TCHAR szProcessName[MAX_PATH] = TEXT("TrustedInstaller.exe");
	DWORD pid = getPidFromName(szProcessName);

	CreateSystemFromParent(pid, processname, cmdargs);
}

VOID CreateSystemFromToken(LPCWSTR processname, LPWSTR cmdargs) {

	HANDLE hDpToken = NULL;

	DWORD PID_TO_IMPERSONATE = getPidFromName(L"winlogon.exe");//winlogon.exe//lsass.exe

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, true, PID_TO_IMPERSONATE);


	HANDLE hToken = NULL;
	BOOL TokenRet = OpenProcessToken(hProcess,TOKEN_DUPLICATE |TOKEN_ASSIGN_PRIMARY |TOKEN_QUERY, &hToken);

	BOOL impersonateUser = ImpersonateLoggedOnUser(hToken);

	BOOL dpToken = DuplicateTokenEx(hToken,TOKEN_ADJUST_DEFAULT |TOKEN_ADJUST_SESSIONID |TOKEN_QUERY |TOKEN_DUPLICATE |TOKEN_ASSIGN_PRIMARY,NULL,SecurityImpersonation,TokenPrimary,&hDpToken);

	STARTUPINFO startupInfo = { 0 };
	startupInfo.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION ProcessInfo = { 0 };

	BOOL Ret = CreateProcessWithTokenW(hDpToken,LOGON_WITH_PROFILE,processname,cmdargs, 0, NULL, NULL,&startupInfo,&ProcessInfo);

	return;
}
VOID CreateTrustedinstallerFromToken(LPCWSTR processname, LPWSTR cmdargs) {

	HANDLE hDpToken = NULL;
	
	SC_HANDLE schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);

	SC_HANDLE schService = OpenService(schSCManager, L"TrustedInstaller", SERVICE_START);

	StartService(schService, 0, NULL);

	TCHAR szProcessName[MAX_PATH] = L"TrustedInstaller.exe";
	DWORD pid = getPidFromName(szProcessName);
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid);

	HANDLE hToken = NULL;
	BOOL TokenRet = OpenProcessToken(hProcess,TOKEN_DUPLICATE |TOKEN_ASSIGN_PRIMARY |TOKEN_QUERY, &hToken);

	BOOL impersonateUser = ImpersonateLoggedOnUser(hToken);

	BOOL dpToken = DuplicateTokenEx(hToken,TOKEN_ADJUST_DEFAULT |TOKEN_ADJUST_SESSIONID |TOKEN_QUERY |TOKEN_DUPLICATE |TOKEN_ASSIGN_PRIMARY,NULL,SecurityImpersonation,TokenPrimary,&hDpToken);


	STARTUPINFO startupInfo = { 0 };
	startupInfo.cb = sizeof(STARTUPINFO);
	PROCESS_INFORMATION ProcessInfo = { 0 };

	BOOL Ret = CreateProcessWithTokenW(hDpToken,LOGON_WITH_PROFILE,processname,cmdargs, 0, NULL, NULL,&startupInfo,&ProcessInfo);

	return;
}

VOID inline DBGLOG(LPCSTR log) {
	OutputDebugStringA(log);
}

VOID inline DEBLOG(LPCWSTR log) {
	OutputDebugStringW(log);
}