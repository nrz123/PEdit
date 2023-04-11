.386
.model flat, c			;定义模式
.data
.code

decode_code proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
ret
fun_end:
decode_code endp

copy_code proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
ret
fun_end:
copy_code endp

enter_code proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
fun_end:
enter_code endp

insert_dll proc
lea eax, [fun_end - fun_start]
mov ecx,dword ptr [esp + 4]
mov dword ptr [ecx], eax
mov eax,fun_start
ret
fun_start:
fun_end:
insert_dll endp

end