.data
.code

decode_code proc
cmp rdx, 0
jnz point1
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
point1:
cmp rdx, 1
jnz point2
lea rax, [point1_end - point1_start]
mov qword ptr [rcx], rax
lea rax,[point1_start - fun_start]
ret
point2:
cmp rdx, 2
jnz point3
lea rax,[point_src - fun_start + 2]
ret
point3:
cmp rdx, 3
jnz point4
lea rax,[point_dst - fun_start + 2]
ret
point4:
lea rax,[point_enter - fun_start + 2]
ret
fun_start:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
jmp main_start
chkstk:
sub rsp,10h
mov qword ptr [rsp],r10
mov qword ptr [rsp + 8],r11
xor r11,r11
lea r10,[rsp + 18h]
sub r10,rax
cmovb r10,r11
mov r11,qword ptr gs:[10h]
cmp r10,r11
jae cs10+10h
and r10w,0F000h
cs10:
lea r11,[r11 - 1000h]
mov byte ptr [r11],0
cmp r10,r11
jne cs10
mov r10,qword ptr [rsp]
mov r11,qword ptr [rsp+8]
add rsp,10h
ret
main_start:
mov eax,15992
call chkstk
sub rsp, rax
point_src:
mov r8, 1234567812345678h
point_dst:
mov rax, 1234567812345678h
lea rdx, [fun_end + 2722]
lea rdi, [rdx + r8]
point1_start:
jmp decode
point1_end:
lea rdi, [fun_start]
sub rdi, rax
decode:
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
point_enter:
mov rax, 1234567812345678h
add rdi, rax
call rdi
mov rsp, rbp
pop rdi
pop rsi
pop rbx
pop rbp
ret
fun_end:
decode_code endp

enter_code proc
cmp rdx, 0
jnz point1
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
point1:
cmp rdx, 1
jnz point2
lea rax,[point1_start - fun_start + 2]
ret
point2:
lea rax,[point2_start - fun_start + 1]
ret
fun_start:
push rax
lea rax, [fun_end]
point1_start:
mov rcx, 1234567812345678h
add rax, rcx
call rax
lea rax, [fun_start]
point2_start:
mov ecx, 12345678h
sub rax, rcx
call rax
pop rax
fun_end:
enter_code endp

pe_code proc
cmp rdx, 0
jnz point1
lea rax, [fun_end - fun_start]
mov qword ptr [rcx], rax
mov rax,fun_start
ret
point1:
cmp rdx, 1
jnz point2
lea rax, [point1_end - point1_start]
mov qword ptr [rcx], rax
lea rax,[point1_start - fun_start]
ret
point2:
lea rax, [point2_end - point2_start]
mov qword ptr [rcx], rax
lea rax,[point2_start - fun_start]
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
mov esi, dword ptr [rcx + 3ch] 
mov esi, dword ptr [rcx + rsi + 90h]
mov rbx, rdi
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
mov rax,07fffffffffffffffh
and rdx, rax
jmp fit_next_out
fit_next:
add rdx, rbx
add rdx, 2
fit_next_out:
mov rax, qword ptr [rbp - 8h]
mov qword ptr [rbp - 18h], rcx
push 0
push rdx
push rcx
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
mov rbp, rsp
mov rbx, rdx
mov edx, dword ptr [rcx + 3ch]
mov rax, qword ptr [rcx + rdx + 30h]
mov esi, dword ptr [rcx + rdx + 0b0h]
mov edx, dword ptr [rcx + rdx + 0b4h]
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
repair_protect:
push rbp
push rbx
push rsi
push rdi
mov rbp, rsp
mov rbx, rcx
mov rcx, 9b2e41be54366260h
call find_function
test rax, rax
jz fun_out
mov rdi, rax
mov esi, dword ptr [rbx + 3ch]
push rax
mov r9, rsp
push r9
mov r8, 4
push r8
mov edx, dword ptr [rbx + rsi + 114h]
push rdx
mov rcx, rbx
push rcx
call rdi
add rsp, 20h
and byte ptr [rbx + rsi + 12fh], 7fh
pop r8
mov r8d, r8d
push rax
mov r9, rsp
push r9
push r8
mov edx, dword ptr [rbx + rsi + 114h]
push rdx
mov rcx, rbx
push rcx
call rdi
jmp fun_out
main_start:
sub rsp, 28h
lea rsi, [fun_end]
mov ecx, dword ptr [rsi + 3ch]
lea rax, [fun_end - fun_start]
mov edx, dword ptr [rsi + rcx + 38h]
dec rdx
add rax, rdx
not rdx
and rax, rdx
add eax, dword ptr [rsi + rcx + 50h]
mov rdi, rsi
point1_start:
sub rdi, rax
point1_end:
mov rcx, rsi
mov rdx, rdi
call repair_import
mov rcx, rsi
mov rdx, rdi
call repair_reloc
mov rcx, rdi
point2_start:
call repair_protect
point2_end:
mov eax, dword ptr [rsi + 3ch]
mov eax, dword ptr [rsi + rax + 28h]
add rax, rdi
mov rcx, rdi
mov rdx, 1h
mov r8, 0
push 0
push r8
push rdx
push rcx
call rax
jmp fun_out
fun_end:
pe_code endp

end