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
mov r13,[r13+10h]
add r12,r13
add r15,r13
mov r14d,dword ptr [r15+3ch]
add r14,r15

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