# Tool of fetch windows syscalls

author : [@55-AA](https://twitter.com/5_5_A_A), Sept 23, 2016

##Introduction
 
This IdaPython script fetchs syscall's ID and function name from those Windows dlls with IDA Pro, such as ntdll.dll, user32.dll.

It requires IDA 6.8 and later. For getting function prototypes, A Pdb file is required when the dll is first opened to analyze.

If not a H\_APIs.h, You need generate it from ntgdi_reactos.h, ntuser_reactos.h and ntuser_w2k.h, then use 'Alt+F7' to open this script to run. The H\_APIs.h supply the prototype, when IDA cannot get it.

The last, you can obtain a output file at the script path.

A example of function fetched from IDA is following:

    .text:77D74BF9      _NtUserGetPriorityClipboardFormat@8 proc near
    .text:77D74BF9             mov     eax, 11BDh
    .text:77D74BFE             mov     edx, 7FFE0300h
    .text:77D74C03             call    dword ptr [edx]
    .text:77D74C05             retn    8
    .text:77D74C05      _NtUserGetPriorityClipboardFormat@8 endp

The example of output is following:

    ......
    /*0x116e,03*/BOOL NtUserDeleteMenu(HMENU,UINT,UINT);
    /*0x1211,03*/BOOL NtUserRemoveMenu(HMENU,UINT,UINT);
    /*0x122d,03*/BOOL NtUserSetMenuDefaultItem(HMENU,UINT,UINT);
    /*0x1172,01*/BOOL NtUserDestroyMenu(HMENU);
    /*0x11ef,06*/BOOL NtUserMoveWindow(HWND,INT,INT,INT,INT,BOOL);
    /*0x1158,01*/BOOL NtUserCheckDesktopByThreadId(DWORD);
    ......

The columns meanning above: 

    ID, Paramster count, Function prototype

##Todo
I cannot get prototype and parameter count on x64 PE, so I need a new way. In fact, there are many function, their prototype are identical with x86 ones. 


##References

+ [idapython_docs](https://www.hex-rays.com/products/ida/support/idapython_docs/)
+ idaapi.py