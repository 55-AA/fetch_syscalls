# Tool of fetch windows syscalls

author : [@55-AA](https://twitter.com/5_5_A_A), Sept 23, 2016

##Introduction
 
This IdaPython script fetchs syscall's ID and function name from those Windows dlls with IDA Pro, such as ntdll.dll, user32.dll.

It requires IDA 6.8 and later. For getting function prototypes, A Pdb file is required when the dll is first opened to analyze.

Then you can use 'Alt+F7' to open this script to run.

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
    0x1178, NtUserDragDetect, BOOL, 3, (HWND, POINT)
    0x1179, NtUserDragObject, DWORD, 5, (HWND, HWND, UINT, ULONG_PTR, HCURSOR)
    0x117a, NtUserDrawAnimatedRects, BOOL, 4, (HWND, int, const, const)
    0x117b, NtUserDrawCaption, PVOID, 4, (PVOID, PVOID, PVOID, PVOID)
    ......

The columns meanning above: 

    allID, Func, return Type, arguments count, argument list

##Todo
I cannot get prototype and parameter count on x64 PE, so I need a new way. In fact, there are many function, their prototype are identical with x86 ones. 


##References

+ [idapython_docs](https://www.hex-rays.com/products/ida/support/idapython_docs/)
+ idaapi.py