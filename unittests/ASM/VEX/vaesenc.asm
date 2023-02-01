%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM1": ["0x77637B6F637B6F77", "0x7B6F77636F77637B", "0x0000000000000000", "0x0000000000000000"],
    "XMM2": ["0x889C84909C849088", "0x8490889C90889C84", "0x0000000000000000", "0x0000000000000000"],
    "XMM3": ["0x77637B6E637B6F76", "0x7B6F77626F77637A", "0x0000000000000000", "0x0000000000000000"],
    "XMM4": ["0x889C8490637B6F77", "0x7B6F776290889C84", "0x0000000000000000", "0x0000000000000000"]
  }
}
%endif

lea rdx, [rel .data]

vmovaps ymm0, [rdx + 32 * 4]

vaesenc xmm1, xmm0, [rdx + 32 * 0]
vaesenc xmm2, xmm0, [rdx + 32 * 1]
vaesenc xmm3, xmm0, [rdx + 32 * 2]
vaesenc xmm4, xmm0, [rdx + 32 * 3]

hlt

align 32
.data:
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000
dq 0x0000000000000000

dq 0xFFFFFFFFFFFFFFFF
dq 0xFFFFFFFFFFFFFFFF
dq 0xFFFFFFFFFFFFFFFF
dq 0xFFFFFFFFFFFFFFFF

dq 0x0000000100000001
dq 0x0000000100000001
dq 0x0000000100000001
dq 0x0000000100000001

dq 0xFFFFFFFF00000000
dq 0x00000001FFFFFFFF
dq 0xFFFFFFFF00000000
dq 0x00000001FFFFFFFF

dq 0x0202020202020202
dq 0x0303030303030303
dq 0x0202020202020202
dq 0x0303030303030303