%ifdef CONFIG
{
  "HostFeatures": ["AVX"],
  "RegData": {
    "XMM0":  ["0x0000000100000001", "0x0000000200000002", "0x0000000000000000", "0x0000000000000000"],
    "XMM1":  ["0x0000000400000004", "0x0000000800000008", "0x0000000000000000", "0x0000000000000000"],
    "XMM3":  ["0x0000000100000001", "0x0000000200000002", "0x0000000100000001", "0x0000000200000002"],
    "XMM4":  ["0x0000000400000004", "0x0000000800000008", "0x0000000400000004", "0x0000000800000008"]
  },
  "MemoryRegions": {
    "0x100000000": "4096"
  }
}
%endif

lea rdx, [rel .data]

; Set up MXCSR to truncate
vldmxcsr [rel .mxcsr]

vmovapd ymm0, [rdx + 32 * 2]
vmovapd ymm1, [rdx + 32 * 2]
vmovapd ymm2, [rdx]

vcvtps2dq xmm0, xmm2
vcvtps2dq xmm1, [rdx + 32 * 1]

vcvtps2dq ymm3, ymm2
vcvtps2dq ymm4, [rdx + 32 * 1]

hlt

align 32
.data:
dq 0x3FC000003F800000 ; [1.5, 1.0]
dq 0x4039999A40000000 ; [2.9, 2.0]
dq 0x3FC000003F800000 ; [1.5, 1.0]
dq 0x4039999A40000000 ; [2.9, 2.0]

dq 0x4083333340800000 ; [4.1, 4.0]
dq 0x4108000041000000 ; [8.5, 8.0]
dq 0x4083333340800000 ; [4.1, 4.0]
dq 0x4108000041000000 ; [8.5, 8.0]

dq 0x4142434445464748
dq 0x5152535455565758
dq 0x4142434445464748
dq 0x5152535455565758

.mxcsr:
dq 0x0000000000007F80