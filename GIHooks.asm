;--------------------------------------------------------------------------
; Hook Definitions
;--------------------------------------------------------------------------
option casemap :none

.data
ContextValue       dq 0
ContextHookRet     dq 0
SpeedHookRet       dq 0
SpeedSwitchHookRet dq 0 
SpeedHookSwitch    dq 0
SpeedHookCounter   dq 0

SpeedEnableConst   dq 0.0
SpeedDisableConst  dq 1.0


.code
;----------------------------

ToggleSpeedHook PROC, Arg1:QWORD
mov qword ptr[SpeedHookSwitch], rcx
ret
ToggleSpeedHook ENDP

;----------------------------
; Context Hook Definition(s)
;----------------------------
ContextHook PROC
movss xmm0, dword ptr[rcx+0000030Ch]
mov qword ptr[ContextValue], rcx
jmp ContextHookRet
ContextHook ENDP

SetContextHookReturn PROC, Arg1:QWORD
mov qword ptr[ContextHookRet], rcx
ret
SetContextHookReturn ENDP

;----------------------------
; Speed Hook Definition(s)
;----------------------------
SpeedHook PROC
cmp qword ptr[SpeedHookSwitch], 0
je orig_code

cmp rdi, qword ptr[ContextValue]
je adj_my_speed
cmp byte ptr[rdi+00000328h], 01
je adj_etc_speed
mov eax, dword ptr[SpeedDisableConst]
jmp SpeedHookRet
nop
nop
nop

adj_etc_speed:
cmp byte ptr[rdi+00000358h], 00
jne adj_mob_speed
mov eax, dword ptr[SpeedDisableConst]
jmp SpeedHookRet
nop
nop
nop

adj_mob_speed:
inc [SpeedHookCounter]
cmp [SpeedHookCounter], 1000
jge reset_counter
mov eax, dword ptr[SpeedEnableConst]
mov [rdi+0000030Ch], eax
jmp SpeedHookRet
nop
nop
nop

adj_my_speed:
mov eax, dword ptr[SpeedDisableConst]
jmp SpeedHookRet
nop
nop
nop

reset_counter:
mov eax, dword ptr[SpeedDisableConst]
cmp [SpeedHookCounter], 2000
jl orig_code
mov [SpeedHookCounter], 0
jmp orig_code
nop
nop
nop

orig_code:
mov eax, dword ptr[SpeedDisableConst]
jmp SpeedHookRet

SpeedHook ENDP

SetSpeedHookReturn PROC, Arg1:QWORD
mov qword ptr[SpeedHookRet], rcx
ret
SetSpeedHookReturn ENDP

;----------------------------
; Speed Switch Hook Definition(s)
;----------------------------
SpeedSwitchHook PROC
mov edx, [rcx]
cmp qword ptr[SpeedHookSwitch], 0
je orig_code
mov edx, 0

orig_code:
and r10b, r12b
jmp SpeedSwitchHookRet
SpeedSwitchHook ENDP

SetSpeedSwitchHookReturn PROC, Arg1:QWORD
mov qword ptr[SpeedSwitchHookRet], rcx
ret
SetSpeedSwitchHookReturn ENDP

;--------------------------------------------------------------------------
END