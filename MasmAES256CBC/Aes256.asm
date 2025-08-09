OPTION CASEMAP:NONE

PUBLIC  Aes256CBCKeyExpansion
PUBLIC  Aes256CBCEncrypt
PUBLIC  Aes256CBCDecrypt

.CODE

; ------------------------------------------------------------------------
; MACRO

KEY_256_ROUND_A MACRO xmmA:req, xmmB:req, RCON:req, dst:req
        aeskeygenassist xmm2, xmmB, RCON
        pshufd      xmm2, xmm2, 0FFh
        movdqa      xmm3, xmmA
        pslldq      xmm3, 4
        pxor        xmmA, xmm3
        movdqa      xmm3, xmmA
        pslldq      xmm3, 4
        pxor        xmmA, xmm3
        movdqa      xmm3, xmmA
        pslldq      xmm3, 4
        pxor        xmmA, xmm3
        pxor        xmmA, xmm2
        movdqu      [rdx + dst], xmmA
ENDM

; ------------------------------------------------------------------------
; MACRO

KEY_256_ROUND_B MACRO xmmA:req, xmmB:req, dst:req
        aeskeygenassist xmm2, xmmA, 0
        pshufd      xmm2, xmm2, 0AAh
        movdqa      xmm3, xmmB
        pslldq      xmm3, 4
        pxor        xmmB, xmm3
        movdqa      xmm3, xmmB
        pslldq      xmm3, 4
        pxor        xmmB, xmm3
        movdqa      xmm3, xmmB
        pslldq      xmm3, 4
        pxor        xmmB, xmm3
        pxor        xmmB, xmm2
        movdqu      [rdx + dst], xmmB
ENDM


; ------------------------------------------------------------------------
; PROCEDURE

ALIGN 16
Aes256CBCKeyExpansion PROC
        movdqu      xmm0, XMMWORD PTR [rcx]        
        movdqu      xmm1, XMMWORD PTR [rcx+16]     
        movdqu      XMMWORD PTR [rdx     ], xmm0
        movdqu      XMMWORD PTR [rdx+16  ], xmm1

        KEY_256_ROUND_A xmm0, xmm1, 01h,  32
        KEY_256_ROUND_B xmm0, xmm1,       48
        KEY_256_ROUND_A xmm0, xmm1, 02h,  64
        KEY_256_ROUND_B xmm0, xmm1,       80
        KEY_256_ROUND_A xmm0, xmm1, 04h,  96
        KEY_256_ROUND_B xmm0, xmm1,      112
        KEY_256_ROUND_A xmm0, xmm1, 08h, 128
        KEY_256_ROUND_B xmm0, xmm1,      144
        KEY_256_ROUND_A xmm0, xmm1, 10h, 160
        KEY_256_ROUND_B xmm0, xmm1,      176
        KEY_256_ROUND_A xmm0, xmm1, 20h, 192
        KEY_256_ROUND_B xmm0, xmm1,      208
        KEY_256_ROUND_A xmm0, xmm1, 40h, 224
        ret
Aes256CBCKeyExpansion ENDP


; ------------------------------------------------------------------------
; PROCEDURE

ALIGN 16
Aes256CBCEncrypt PROC

        ; Parameters:
        ; RCX       = pPlainText
        ; RDX       = uPlainTextSize  
        ; R8        = pCipherText
        ; R9        = pAesKey
        ; [RSP+40]  = pAesIv
        ; [RSP+48]  = pbEncrypted

        push    rbp
        mov     rbp, rsp
        sub     rsp, 400h                       ; Allocate space for locals

        ; Save non-volatile registers 
        mov     [rsp+8], rbx
        mov     [rsp+16], rsi
        mov     [rsp+24], rdi
        movdqu  XMMWORD PTR [rsp+32], xmm6
        movdqu  XMMWORD PTR [rsp+48], xmm7

        ; Get parameters from stack
        mov     rax, [rbp+48]                   ; pAesIv
        mov     [rsp+64], rax
        mov     rax, [rbp+56]                   ; pbEncrypted
        mov     [rsp+72], rax

        ; Save register parameters
        mov     [rsp+80], rcx                   ; pPlainText
        mov     [rsp+88], rdx                   ; uPlainTextSize
        mov     [rsp+96], r8                    ; pCipherText
        mov     [rsp+104], r9                   ; pAesKey

        ; Parameter validation
        mov     rax, [rsp+72]                   ; pbEncrypted
        test    rax, rax
        jz      ENC_EXIT
        mov     BYTE PTR [rax], 0

        mov     rcx, [rsp+80]                   ; pPlainText
        test    rcx, rcx
        jz      ENC_EXIT

        mov     rcx, [rsp+96]                   ; pCipherText
        test    rcx, rcx
        jz      ENC_EXIT

        mov     rcx, [rsp+104]                  ; pAesKey
        test    rcx, rcx
        jz      ENC_EXIT

        mov     rcx, [rsp+64]                   ; pAesIv
        test    rcx, rcx
        jz      ENC_EXIT

        mov     rdx, [rsp+88]                   ; uPlainTextSize
        test    rdx, rdx
        jz      ENC_EXIT
        mov     rax, rdx
        and     rax, 15
        jnz     ENC_EXIT

        ; Expand key - KeySchedule at rsp+112
        lea     rdx, [rsp+112]                  ; KeySchedule (240 bytes)
        mov     rcx, [rsp+104]                  ; pAesKey
        call    Aes256CBCKeyExpansion

        ; Initialize chain with IV - Chain at rsp+352
        mov     rcx, [rsp+64]                   ; pAesIv
        movdqu  xmm1, XMMWORD PTR [rcx]
        movdqu  XMMWORD PTR [rsp+352], xmm1     ; Chain

        mov     rdx, [rsp+88]                   ; uPlainTextSize
        xor     r10, r10
ENC_LOOP:
        cmp     r10, rdx
        jae     ENC_DONE

        mov     rcx, [rsp+80]                   ; pPlainText
        movdqu  xmm0, XMMWORD PTR [rcx + r10]
        movdqu  xmm1, XMMWORD PTR [rsp+352]     ; Chain
        pxor    xmm0, xmm1
        pxor    xmm0, XMMWORD PTR [rsp+112]     ; KeySchedule[0]

        lea     r11, [rsp+128]                  ; KeySchedule + 16
        mov     ecx, 13
ENC_RND:
        aesenc  xmm0, XMMWORD PTR [r11]
        add     r11, 16
        dec     ecx
        jne     ENC_RND

        aesenclast xmm0, XMMWORD PTR [rsp+112 + 14*16]

        mov     rcx, [rsp+96]                   ; pCipherText
        movdqu  XMMWORD PTR [rcx + r10], xmm0
        movdqu  XMMWORD PTR [rsp+352], xmm0     ; Update Chain

        add     r10, 16
        jmp     ENC_LOOP
ENC_DONE:
        mov     rcx, [rsp+72]                   ; pbEncrypted
        mov     BYTE PTR [rcx], 1
ENC_EXIT:
        ; Restore non-volatile registers
        mov     rbx, [rsp+8]
        mov     rsi, [rsp+16]
        mov     rdi, [rsp+24]
        movdqu  xmm6, XMMWORD PTR [rsp+32]
        movdqu  xmm7, XMMWORD PTR [rsp+48]

        mov     rsp, rbp
        pop     rbp
        ret
Aes256CBCEncrypt ENDP

; ------------------------------------------------------------------------
; PROCEDURE

ALIGN 16
Aes256CBCDecrypt PROC
        
        ; Parameters:
        ; RCX       = pCipherText
        ; RDX       = uCipherTextSize  
        ; R8        = pPlainText
        ; R9        = pAesKey
        ; [RSP+40]  = pAesIv
        ; [RSP+48]  = pbDecrypted

        push    rbp
        mov     rbp, rsp
        sub     rsp, 650h                       ; Allocate space for locals

        ; Save non-volatile registers
        mov     [rsp+8], rbx
        mov     [rsp+16], rsi
        mov     [rsp+24], rdi
        movdqu  XMMWORD PTR [rsp+32], xmm6
        movdqu  XMMWORD PTR [rsp+48], xmm7

        ; Get parameters from stack
        mov     rax, [rbp+48]                   ; pAesIv
        mov     [rsp+64], rax
        mov     rax, [rbp+56]                   ; pbDecrypted
        mov     [rsp+72], rax

        ; Save register parameters
        mov     [rsp+80], rcx                   ; pCipherText
        mov     [rsp+88], rdx                   ; uCipherTextSize
        mov     [rsp+96], r8                    ; pPlainText
        mov     [rsp+104], r9                   ; pAesKey

        ; Parameter validation
        mov     rax, [rsp+72]                   ; pbDecrypted
        test    rax, rax
        jz      DEC_EXIT
        mov     BYTE PTR [rax], 0

        mov     rcx, [rsp+80]                   ; pCipherText
        test    rcx, rcx
        jz      DEC_EXIT

        mov     rcx, [rsp+96]                   ; pPlainText
        test    rcx, rcx
        jz      DEC_EXIT

        mov     rcx, [rsp+104]                  ; pAesKey
        test    rcx, rcx
        jz      DEC_EXIT

        mov     rcx, [rsp+64]                   ; pAesIv
        test    rcx, rcx
        jz      DEC_EXIT

        mov     rdx, [rsp+88]                   ; uCipherTextSize
        test    rdx, rdx
        jz      DEC_EXIT
        mov     rax, rdx
        and     rax, 15
        jnz     DEC_EXIT

        ; Expand encryption key - EncKey at rsp+112
        lea     rdx, [rsp+112]                  ; EncKey (240 bytes)
        mov     rcx, [rsp+104]                  ; pAesKey
        call    Aes256CBCKeyExpansion

        ; Convert to decryption key - DecKey at rsp+352
        movdqu  xmm0, XMMWORD PTR [rsp+112 + 14*16]
        movdqu  XMMWORD PTR [rsp+352], xmm0     ; DecKey[0]
        
        lea     r11, [rsp+112 + 13*16]          ; EncKey + 13*16
        lea     r10, [rsp+368]                  ; DecKey + 16
        mov     ecx, 13

IMC_LOOP:
        movdqu  xmm0, XMMWORD PTR [r11]
        aesimc  xmm0, xmm0
        movdqu  XMMWORD PTR [r10], xmm0
        sub     r11, 16
        add     r10, 16
        dec     ecx
        jne     IMC_LOOP

        movdqu  xmm0, XMMWORD PTR [rsp+112]     ; EncKey[0]
        movdqu  XMMWORD PTR [rsp+352 + 14*16], xmm0

        ; Initialize chain with IV - Chain at rsp+592
        mov     rcx, [rsp+64]                   ; pAesIv
        movdqu  xmm1, XMMWORD PTR [rcx]
        movdqu  XMMWORD PTR [rsp+592], xmm1     ; Chain

        mov     rdx, [rsp+88]                   ; uCipherTextSize
        xor     r10, r10
DEC_LOOP:
        cmp     r10, rdx
        jae     DEC_DONE

        mov     rcx, [rsp+80]                   ; pCipherText
        movdqu  xmm0, XMMWORD PTR [rcx + r10]
        movdqa  xmm7, xmm0                      ; Save for next chain

        pxor    xmm0, XMMWORD PTR [rsp+352]     ; DecKey[0]

        lea     r11, [rsp+368]                  ; DecKey + 16
        mov     ecx, 13
DEC_RND:
        aesdec  xmm0, XMMWORD PTR [r11]
        add     r11, 16
        dec     ecx
        jne     DEC_RND

        aesdeclast xmm0, XMMWORD PTR [rsp+352 + 14*16]

        movdqu  xmm1, XMMWORD PTR [rsp+592]     ; Chain
        pxor    xmm0, xmm1

        mov     rcx, [rsp+96]                   ; pPlainText
        movdqu  XMMWORD PTR [rcx + r10], xmm0
        movdqu  XMMWORD PTR [rsp+592], xmm7     ; Update Chain

        add     r10, 16
        jmp     DEC_LOOP
DEC_DONE:
        mov     rcx, [rsp+72]                   ; pbDecrypted
        mov     BYTE PTR [rcx], 1
DEC_EXIT:
        ; Restore non-volatile registers
        mov     rbx, [rsp+8]
        mov     rsi, [rsp+16]
        mov     rdi, [rsp+24]
        movdqu  xmm6, XMMWORD PTR [rsp+32]
        movdqu  xmm7, XMMWORD PTR [rsp+48]

        mov     rsp, rbp
        pop     rbp
        ret
Aes256CBCDecrypt ENDP

END