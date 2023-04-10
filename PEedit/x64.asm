.data
.code

decode_code proc
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
fun_start:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
mov r8,1234567812345678h
mov rax,1234567812345678h
lea rdx,[fun_end + 2722]
lea rdi,[rdx + r8]
sub rsp,15992
push rsp
push 2
push 3
mov rcx, rsp
push 0
mov r9, rsp
push 0
push rsp
push rax
push rdi
push r9
push r8
push rdx
push rcx
call fun_end
mov rsp, rbp
push rax
call rdi
mov rsp, rbp
pop rdi
pop rsi
pop rbx
pop rbp
ret
fun_end:
decode_code endp

copy_code proc
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
fun_start:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
mov rcx,1234567812345678h
lea rsi,[fun_end]
lea rdi,[rsi + rcx]
mov rdx,rdi
copy_loop:
lodsb
stosb
loop copy_loop
push rdx
call rdx
mov rsp, rbp
pop rdi
pop rsi
pop rbx
pop rbp
ret
fun_end:
copy_code endp

enter_code proc
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
fun_start:
mov edi, 12345678h   ;Èë¿Ú
push rax
call fun_end
pop rax
mov rax, gs:[60h]
add rdi, [rax + 10h]
jmp rdi
fun_end:
enter_code endp

insert_dll proc
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
fun_start:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
jmp main_start
fun_out:
mov rsp, rbp
pop rdi
pop rsi
pop rbx
pop rbp
ret
find_function:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
mov rax, rcx
mov rbx, gs:[60h]
mov rbx, qword ptr [rbx+18h]
mov rbx, qword ptr [rbx+30h]
mov rbx, qword ptr [rbx]
mov rbx, qword ptr [rbx]
mov rbx, qword ptr [rbx+10h]	;kernel32
mov ecx, dword ptr [rbx + 3ch]
mov ecx, dword ptr [rbx + rcx + 88h]
add rcx, rbx
xor rdi, rdi
next_loop:
cmp edi, dword ptr [rcx + 18h]
jnz next_loop_continue
xor rax, rax
jmp fun_out
next_loop_continue:
mov edx, dword ptr [rcx + 20h]
add rdx, rbx
mov esi, dword ptr [rdx + rdi * 4]
add rsi, rbx
xor rdx, rdx
push rcx
hash_loop: 
movsx rcx, byte ptr[rsi]
cmp cl, ch
jz compare_hash
ror rdx, 7
add rdx, rcx
inc rsi
jmp hash_loop
compare_hash:
pop rcx
cmp rax, rdx
jz next_out
inc rdi
jmp next_loop 
next_out:
mov edx, dword ptr [rcx + 24h]
add rdx, rbx
movzx rdi, word ptr [rdx + 2 * rdi]
mov edx, dword ptr [rcx + 1ch]
add rdx, rbx
mov eax, dword ptr [rdx + 4 * rdi]
add rax, rbx
jmp fun_out
repair_import:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
mov rbx, rcx
mov rcx, 2b3def2c9071f059h ;hash of GetProcAddress
call find_function
test rax, rax
jz fun_out
push rax
mov rcx, 0b22b0f2c5a666505h ;hash of LoadLibraryA
call find_function
test rax, rax
jz fun_out
push rax
sub rsp, 20h
mov esi, dword ptr [rbx + 3ch] 
mov esi, dword ptr [rbx + rsi + 90h]
import_loop:
cmp dword ptr [rbx + rsi],0
jz fun_out
mov ecx, dword ptr [rbx + rsi + 0ch]
add rcx, rbx
mov rax, qword ptr [rbp - 10h]
push rcx
call rax
add rsp, 8h
mov rcx, rax
mov edi, dword ptr [rbx + rsi + 10h]
fit_loop:
mov rdx, qword ptr [rbx + rdi]
test rdx, rdx
jz fit_out
mov rax,08000000000000000h
test rdx,rax
jz fit_next
mov edx, edx
mov eax, dword ptr [rcx + 3ch] 
mov eax, dword ptr [rcx + rax + 88h]
mov eax, dword ptr [rcx + rax + 1ch]
add rax, rcx
mov edx, dword ptr [rax + 4 * rdx - 4]
add rdx, rcx
mov qword ptr [rbx + rdi], rdx
jmp fit_continue
fit_next:
add rdx, rbx
add rdx, 2
mov rax, qword ptr [rbp - 8h]
mov qword ptr [rbp - 18h], rcx
push 0
push rcx
push rdx
call rax
add rsp,18h
mov rcx, qword ptr [rbp - 18h]
mov qword ptr [rbx + rdi], rax
fit_continue:
add rdi, 8h
jmp fit_loop
fit_out:
add rsi,14h
jmp import_loop
repair_reloc:
push rbp
push rbx
push rsi
push rdi
mov rbp,rsp
mov rbx,rcx
mov edx, dword ptr [rbx + 3ch]
mov rax, qword ptr [rbx + rdx + 30h]
mov esi, dword ptr [rbx + rdx + 0b0h]
mov edx, dword ptr [rbx + rdx + 0b4h]
add rsi, rbx
add rdx, rsi
reloc_loop:
cmp rsi,rdx
jz fun_out
mov rdi, 8h
reloc_item_loop:
cmp edi, dword ptr [rsi + 4h]
jz reloc_item_loop_out
movzx rcx,word ptr [rsi + rdi]
add edi, 2h
test rcx,rcx
jz reloc_item_loop
and cx, 0fffh
add ecx, dword ptr [rsi]
sub qword ptr [rbx + rcx], rax
add qword ptr [rbx + rcx], rbx
jmp reloc_item_loop
reloc_item_loop_out:
add rsi, rdi
jmp reloc_loop
main_start:
sub rsp, 28h
lea rsi,[fun_end]
mov rcx,rsi
call repair_import
mov rcx,rsi
call repair_reloc
mov eax, dword ptr [rsi + 3ch]
mov eax, dword ptr [rsi + rax + 28h]
add rax, rsi
mov rcx, rsi
mov rdx, 1h
mov r8, 0
push 0
push r8
push rdx
push rcx
call rax
jmp fun_out
fun_end:
insert_dll endp

end