.386
.model flat, c
.data
.code
assume fs:nothing

decode_code proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
push ebp
push ebx
push esi
push edi
mov ebp, esp
jmp main_start
chkstk:
push ecx
lea ecx, [esp + 4]
sub ecx, eax
sbb eax, eax
not eax
and ecx, eax
mov eax, esp
and eax, not 0fffh
cs10:
cmp ecx, eax
jb  short cs20
mov eax, ecx
pop ecx
xchg esp, eax
mov eax, dword ptr [eax]
mov dword ptr [esp], eax
ret
cs20:
sub eax, 1000h
test dword ptr [eax],eax
jmp short cs10
main_start:
mov eax,15992
call chkstk
mov esi,12345678h
mov eax,12345678h
call $ + 5
pop edx
add edx, 70
lea edi,[edx + 2732 + esi]
jmp decode
lea edi,[edx - 92h]
sub edi, eax
decode:
push esp
push 2
push 0
push 3
mov ecx, esp
push 0
mov ebx, esp
push 0
push esp
push eax
push edi
push ebx
push esi
push edx
add dword ptr [esp], 2732
push ecx
call edx
mov esp, ebp
push eax
add edi, 12345678h
call edi
mov esp, ebp
pop edi
pop esi
pop ebx
pop ebp
ret
fun_end:
decode_code endp

enter_code proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
mov edi, 12345678h   ;Èë¿Ú
call fun_end
call $ + 5
pop eax
sub eax, 0fh
sub eax, edi
call eax
fun_end:
enter_code endp

insert_dll proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
push ebp
push ebx
push esi
push edi
mov ebp, esp
jmp main_start
fun_out:
mov esp, ebp
pop edi
pop esi
pop ebx
pop ebp
ret
find_function:
push ebp
push ebx
push esi
push edi
mov ebp, esp
mov eax, ecx
mov ebx, fs:[30h]
mov ebx, dword ptr [ebx + 0ch]
mov ebx, dword ptr [ebx + 1ch]
mov ebx, dword ptr [ebx]
mov ebx, dword ptr [ebx + 08h]	;kernel32
mov ecx, dword ptr [ebx + 3ch]
mov ecx, dword ptr [ebx + ecx + 78h]
add ecx, ebx
xor edi, edi
next_loop:
cmp edi, dword ptr [ecx + 18h]
jnz next_loop_continue
xor eax, eax
jmp fun_out
next_loop_continue:
mov edx, dword ptr [ecx + 20h]
add edx, ebx
mov esi, dword ptr [edx + edi * 4]
add esi, ebx
xor edx, edx
push ecx
hash_loop:
movsx ecx, byte ptr[esi]
cmp cl, ch
jz compare_hash
ror edx, 7
add edx, ecx
inc esi
jmp hash_loop
compare_hash:
pop ecx
cmp eax, edx
jz next_out
inc edi
jmp next_loop 
next_out:
mov edx, dword ptr [ecx + 24h]
add edx, ebx
movzx edi, word ptr [edx + 2 * edi]
mov edx, dword ptr [ecx + 1ch]
add edx, ebx
mov eax, dword ptr [edx + 4 * edi]
add eax, ebx
jmp fun_out
repair_import:
push ebp
push ebx
push esi
push edi
mov ebp, esp
mov ebx, ecx
mov ecx, 0bbafdf85h ;hash of GetProcAddress
call find_function
test eax, eax
jz fun_out
push eax
mov ecx, 0c917432h ;hash of LoadLibraryA
call find_function
test eax, eax
jz fun_out
push eax
sub esp, 20h
mov eax, dword ptr [ebx + 3ch] 
mov esi, dword ptr [ebx + eax + 80h]
mov ecx, dword ptr [ebx + eax + 50h]
sub ebx, dword ptr [ebx + eax + 38h]
sub ebx, ecx
import_loop:
cmp dword ptr [ebx + esi],0
jz fun_out
mov ecx, dword ptr [ebx + esi + 0ch]
add ecx, ebx
mov eax, dword ptr [ebp - 08h]
push ecx
call eax
mov ecx, eax
mov edi, dword ptr [ebx + esi + 10h]
fit_loop:
mov edx, dword ptr [ebx + edi]
test edx, edx
jz fit_out
test edx, 080000000h
jz fit_next
and edx, 07fffffffh
jmp fit_next_out
fit_next:
add edx, ebx
add edx, 2
fit_next_out:
mov eax, dword ptr [ebp - 4h]
mov dword ptr [ebp - 0ch], ecx
push edx
push ecx
call eax
mov ecx, dword ptr [ebp - 0ch]
mov dword ptr [ebx + edi], eax
fit_continue:
add edi, 4h
jmp fit_loop
fit_out:
add esi,14h
jmp import_loop
repair_reloc:
push ebp
push ebx
push esi
push edi
mov ebp,esp
mov ebx,ecx
mov edx, dword ptr [ebx + 3ch]
mov eax, dword ptr [ebx + edx + 34h]
mov esi, dword ptr [ebx + edx + 0a0h]
mov edx, dword ptr [ebx + edx + 0a4h]
mov ecx, dword ptr [ebx + edx + 50h]
sub ebx, dword ptr [ebx + edx + 38h]
sub ebx, ecx
add esi, ebx
add edx, esi
reloc_loop:
cmp esi,edx
jz fun_out
mov edi, 8h
reloc_item_loop:
cmp edi, dword ptr [esi + 4h]
jz reloc_item_loop_out
movzx ecx,word ptr [esi + edi]
add edi, 2h
test ecx,ecx
jz reloc_item_loop
and cx, 0fffh
add ecx, dword ptr [esi]
sub dword ptr [ebx + ecx], eax
add dword ptr [ebx + ecx], ebx
jmp reloc_item_loop
reloc_item_loop_out:
add esi, edi
jmp reloc_loop
repair_protect:
push ebp
push ebx
push esi
push edi
mov ebp, esp
mov ebx, ecx
mov ecx, 0ef64a41eh
call find_function
test eax, eax
jz fun_out
mov edi, eax
mov eax, dword ptr [ebx + 3ch]
mov ecx, dword ptr [ebx + eax + 50h]
sub ebx, dword ptr [ebx + eax + 38h]
sub ebx, ecx
mov esi, dword ptr [ebx + 3ch]
push eax
push esp
push 4
push dword ptr [ebx + esi + 104h]
push ebx
call edi
and byte ptr [ebx + esi + 11fh], 7fh
pop eax
push eax
push esp
push eax
push dword ptr [ebx + esi + 104h]
push ebx
call edi
jmp fun_out
main_start:
sub esp, 28h
call $ + 5
pop esi
add esi,040h
mov ecx,esi
call repair_import
mov ecx,esi
call repair_reloc
mov ecx,esi
call repair_protect
mov ecx, dword ptr [esi + 3ch]
mov eax, dword ptr [esi + ecx + 28h]
mov edx, dword ptr [esi + ecx + 50h]
sub esi, dword ptr [esi + ecx + 38h]
sub esi, edx
add eax, esi
mov ecx, esi
mov edx, 1h
push 0
push 0
push edx
push ecx
call eax
jmp fun_out
fun_end:
insert_dll endp

end