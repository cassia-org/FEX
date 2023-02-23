%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM4":  ["0x7FFF7FFF7FFF7FFF", "0x800080007FFF7FFF", "0x7FFF7FFF7FFF7FFF", "0x7FFF7FFF80008000"],
    "XMM5":  ["0x800080007FFF7FFF", "0x7FFF7FFF7FFF7FFF", "0x7FFF7FFF80008000", "0x7FFF7FFF7FFF7FFF"],
    "XMM6":  ["0x71836D874331472D", "0x800080007FFF7FFF", "0x4331472D71836D87", "0x7FFF7FFF80008000"],
    "XMM7":  ["0x800080007FFF7FFF", "0x71836D874331472D", "0x7FFF7FFF80008000", "0x4331472D71836D87"],
    "XMM8":  ["0x7FFF7FFF7FFF7FFF", "0x71836D874331472D", "0x7FFF7FFF7FFF7FFF", "0x4331472D71836D87"],
    "XMM9":  ["0x800080007FFF7FFF", "0x800080007FFF7FFF", "0x7FFF7FFF80008000", "0x7FFF7FFF80008000"],
    "XMM10": ["0x71836D874331472D", "0x800080007FFF7FFF", "0x4331472D71836D87", "0x7FFF7FFF80008000"]
  }
}
%endif

lea rdx, [rel .data]

vmovaps ymm0, [rdx]
vmovaps ymm1, [rdx + 32]
vmovaps ymm2, [rdx + 64]
vmovaps ymm3, [rdx + 96]

vphaddsw ymm4,  ymm0, [rdx + 32]
vphaddsw ymm5,  ymm1, [rdx]

vphaddsw ymm6,  ymm2, [rdx + 32]
vphaddsw ymm7,  ymm3, [rdx + 64]

vphaddsw ymm8,  ymm0, [rdx + 64]
vphaddsw ymm9,  ymm1, [rdx + 96]

vphaddsw ymm10, ymm2, [rdx + 96]

hlt

align 32
.data:
dq 0x4142434445464748
dq 0x5152535455565758
dq 0x5152535455565758
dq 0x4142434445464748

dq 0x7F7F7F7F7F7F7F7F
dq 0x8080808080808080
dq 0x8080808080808080
dq 0x7F7F7F7F7F7F7F7F

dq 0x2119221823172416
dq 0x3941384237433644
dq 0x3941384237433644
dq 0x2119221823172416

dq 0x7F7F7F7F7F7F7F7F
dq 0x8080808080808080
dq 0x8080808080808080
dq 0x7F7F7F7F7F7F7F7F