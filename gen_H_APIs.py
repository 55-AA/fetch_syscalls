#!/usr/bin/python

import re

g_func_dict = {}
g_Unknown = 0
g_Count = 0
g_Duplicate = 0

g_param_format = {
    "char"      : "CHAR",
    "int"       : "INT",
    "void"      : "VOID",
    "_DWORD"    : "DWORD",

    "LPSTR"     : "PSTR",
    "LPCSTR"    : "PCSTR",
    "LPWSTR"    : "PWSTR",
    "LPCWSTR"   : "PCWSTR",

    "LPVOID"    : "PVOID",
    "LPCHAR"    : "PCHAR",
    "LPUCHAR"   : "PUCHAR",
    "LPBYTE"    : "PBYTE",
    "LPWCHAR"   : "PWCHAR",
    "LPSHORT"   : "PSHORT",
    "LPUSHORT"  : "PUSHORT",
    "LPDWORD"   : "PDWORD",
    "LPWORD"    : "PWORD",
    "LPINT"     : "PINT",
    "LPUINT"    : "PUINT",
    "LPLONG"    : "PLONG",
    "LPULONG"   : "PULONG",
    "LPBOOL"    : "PBOOL",

    "PMSG"      : "LPMSG",
    "PSIZE"     : "LPSIZE",
    "PPOINT"    : "LPPOINT",
    "PCURSORINFO" : "LPCURSORINFO",
}

g_param_format2 = {
    "VOID*"     : "PVOID",
    "CHAR*"     : "PCHAR",
    "UCHAR*"    : "PUCHAR",
    "BYTE*"     : "PBYTE",
    "WCHAR*"    : "PWCHAR",
    "SHORT*"    : "PSHORT",
    "USHORT*"   : "PUSHORT",
    "DWORD*"    : "PDWORD",
    "WORD*"     : "PWORD",
    "INT*"      : "PINT",
    "UINT*"     : "PUINT",
    "LONG*"     : "PLONG",
    "ULONG*"    : "PULONG",
    "BOOL*"     : "PBOOL",
    #structure
    "SIZE*"             : "LPSIZE",
    "MSG*"              : "LPMSG",
    "POINT*"            : "LPPOINT",
    "POINTL*"           : "PPOINTL",
    "HKL*"              : "LPHKL",
    "RECT*"             : "LPRECT",
    "PRECT"             : "LPRECT",
    "RECTL*"            : "LPRECTL",
    "COLORREF*"         : "LPCOLORREF",
    "WNDCLASSEXW*"      : "LPWNDCLASSEXW",
    "PAINTSTRUCT*"      : "LPPAINTSTRUCT",
    "WINDOWPLACEMENT*"  : "LPWINDOWPLACEMENT",
    "BLENDFUNCTION*"    : "PBLENDFUNCTION",     #
}

def format_type(T):
    A = T.split('*')
    param = A[0]
    if param in g_param_format.keys():
        param = g_param_format[param]

    if len(A) > 1:
        param += '*'
        if param in g_param_format2.keys():
            param = g_param_format2[param]

    return param

def save_func(func_line):
    global g_Unknown
    global g_Count
    global g_Duplicate

    g_Count += 1
    (NTAPI, func_ret, func_line) = func_line.split(' ', 2)
    assert(NTAPI == "NTAPI")
    func_ret = format_type(func_ret)
    (func_name, func_line) = func_line.split('(', 1)
    func_name = func_name.strip()
    A = func_line.split(')')[0]
    B = A.split(',')

    func_param = ''
    paramN = 0
    for i in B:
        C = i.split()
        is_OUT = 0
        IN_key_skip = ["IN", "CONST", "const", "_In_", "_In_opt_", 'OPTIONAL']
        OUT_key_skip = ["OUT", "_Out_opt_", "_Inout_opt_", "_Inout_", "_Out_", '_Outptr_']

        for j in IN_key_skip:
            if j in C:
                C.remove(j)
        for j in OUT_key_skip:
            if j in C:
                C.remove(j)
                is_OUT = 1

        if not len(C):
            print "ERROR: No parameters"

        argument = ''
        if len(C) > 1:
            argument = C[1]
            if argument[:9] == "dwUnknown" or argument[:7] == "Unknown":
                g_Unknown += 1
                # print "ERROR: Unknown parameters"
                return
        
        param = C[0]
        if param:
            if argument[:1] == '*':
                param = param + '*'
            param = format_type(param)

            if is_OUT:
                param = "OUT " + param
            func_param += ',' + param
            paramN += 1

    func_param = func_param[1:]
    if "VOID" == func_param or "" == func_param :
        func_param = "VOID"
        paramN = 0

    if func_name not in g_func_dict.keys():
        g_func_dict[func_name] = [func_ret, paramN, func_param]
    else:
        g_Duplicate += 1


def process_lines(lines):
    '''
    input e.g.1
    BOOL
    NTAPI
    NtUserDrawAnimatedRects(
        HWND hwnd,
        INT idAni,
        RECT *lprcFrom,
        RECT *lprcTo);
    
    input e.g.2
    W32KAPI
    HWINSTA
    NtUserOpenWindowStation(
        IN POBJECT_ATTRIBUTES pObja,
        IN ACCESS_MASK amRequest);    
    '''
    linesN = len(lines)
    i = 0
    while i < linesN :
        ntapi_lines = lines[i].split()
        i += 1
        func_line = ''
        if "NTAPI" in ntapi_lines:
            ntapi_idx = ntapi_lines.index("NTAPI")
            if ntapi_idx == 0:
                ntapi_lines.insert(1, lines[i - 2])
                for j in ntapi_lines:
                    func_line += j + ' '                
            else:
                continue

        elif "W32KAPI" in ntapi_lines:
            ntapi_idx = ntapi_lines.index("W32KAPI")
            if ntapi_idx == 0:
                ntapi_lines[ntapi_idx] = "NTAPI"
                for j in ntapi_lines:
                    func_line += j + ' '
            else:
                continue
        else:

            continue            

        # search ')'
        j = i + 20
        if j > linesN:
            j = linesN
        while i < j :
            func_line += lines[i] + ' '
            if lines[i].find(')') >= 0 :
                # save_func(func_line)
                try:
                    save_func(func_line)
                except:
                    print "ERROR: [EXCEPT]", func_line
                i += 1
                break
            i += 1

def load_user32_file(h_file):
    f = open(h_file, "r")
    lines = []
    R_APIENTRY = re.compile(r'(.*)(APIENTRY)(.*)')
    R_all = re.compile(r'(.*)(/\*.*\*/)(.*)')
    R_left = re.compile(r'(.*)(/\*.*)')
    R_right = re.compile(r'(.*\*/)(.*)')
    search_end = 0
    for line in f:
        line = line.strip()
        line = R_APIENTRY.sub(r'\1NTAPI\3', line) #"APIENTRY" -> "NTAPI"
        line = R_all.sub(r'\1\3', line) #"111/*222*/333" -> "111333"
        line = line.split("//", 1)[0]   #"111//22222222" -> "111"

        R = R_left.match(line)          #"111/*222"      -> "111"
        if R:
            search_end = 1
            line = R.group(1)
        else:
            if search_end:
                R = R_right.match(line) #"111*/222"      -> "222"
                if R:
                    search_end = 0
                    line = R.group(2)
                else:
                    line = ""           #"/*111*/"      -> ""
        if line:
            lines.append(line)

    f.close()
    return lines


def load_gdi32_file(h_file):
    '''
    input e.g.
    W32KAPI
    HBRUSH
    APIENTRY
    NtGdiCreateSolidBrush(
        _In_ COLORREF cr,
        _In_opt_ HBRUSH hbr);
    '''
    f = open(h_file, "r")
    lines = []
    R_all = re.compile(r'(.*)(/\*.*\*/)(.*)')
    R_left = re.compile(r'(.*)(/\*.*)')
    R_right = re.compile(r'(.*\*/)(.*)')

    R_except = [
        re.compile(r'(.*)(_When_\(.*\)\))(.*)'),
        re.compile(r'(.*)(_Out_writes_.*\) )(.*)'),
        re.compile(r'(.*)(_In_reads_.*\) )(.*)'),
        re.compile(r'(.*)(_Inout_updates_.*\) )(.*)'),
        re.compile(r'(.*)(_At_\(.*\) )(.*)'),
        re.compile(r'(.*)(_Deref_out_range_\(.*\) )(.*)'),
        re.compile(r'(.*)(_In_range_\(.*\) )(.*)'),
        re.compile(r'(.*)(_Outptr_result_buffer_\(.*\) )(.*)'),
        re.compile(r'(.*)(_Post_count_\(.*\) )(.*)'),
        re.compile(r'(.*)(_Post_bytecount_\(.*\) )(.*)'),
    ]

    search_end = 0
    for line in f:
        line = line.strip()        
        if "APIENTRY" == line:
            continue

        for REXP in R_except:
            line = REXP.sub(r'\1\3', line)
        
        line = R_all.sub(r'\1\3', line) #"111/*222*/333" -> "111333"
        line = line.split("//", 1)[0]   #"111//22222222" -> "111"

        R = R_left.match(line)          #"111/*222"      -> "111"
        if R:
            search_end = 1
            line = R.group(1)
        else:
            if search_end:
                R = R_right.match(line) #"111*/222"      -> "222"
                if R:
                    search_end = 0
                    line = R.group(2)
                else:
                    line = ""           #"/*111*/"       -> ""
        if line:
            lines.append(line)

    f.close()
    return lines


process_lines(load_gdi32_file("ntgdi_reactos.h"))
process_lines(load_user32_file("ntuser_reactos.h"))
process_lines(load_user32_file("ntuser_w2k.h"))

f = open("H_APIs.h", "w")
for k,v in g_func_dict.iteritems():
    f.write("%s %s(%s);//%d\n" % (v[0], k, v[2], v[1]))
f.close()

out_str = "Found APIs: %d\n(Valid)%d + (Unknown)%d = (Procss)%d\nDuplicate APIs: %d" % \
    (g_Count, len(g_func_dict), g_Unknown, len(g_func_dict) + g_Unknown, g_Duplicate)
print(out_str)

