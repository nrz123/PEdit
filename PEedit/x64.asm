.DATA					;数据段	
.CODE					;代码段

InsertCode  PROC			;函数Func_1 

mov rdi,1234567812345678h
mov rsi,1234567812345678h
mov r8 ,1234567812345678h
cploop:
cmp rsi,r8
jz cplout
lodsb
stosb
jmp cploop
cplout:
mov rbx,1234567812345678h	;image+offset 需要重定位
mov rdx,1234567812345678h	;重定位表
mov r8 ,1234567812345678h	;重定位表结尾
mov r10,1234567812345678h	;image 不需要重定位

relocloop:
cmp rdx,r8
jz relocout
                                                                                                                               
xor rax,rax
mov eax,dword ptr [rdx]
xor rcx,rcx
mov ecx,dword ptr [rdx+4]
add rcx,rdx
add rdx,8

rloop:
cmp rdx,rcx
jz relocloop

xor r9,r9
mov r9w,word ptr [rdx]
add rdx,2
cmp r9,0
jz rloop
and r9w,0fffh
add r9,rax
add r9,rbx
mov r11,qword ptr [r9]
sub r11,r10
add r11,rbx
mov qword ptr [r9],r11
jmp rloop

relocout:
mov rax,1234567812345678h	;原函数入口
xor rbx,rbx
jmp rax

ret

InsertCode  ENDP			;函数Func_1结尾

END