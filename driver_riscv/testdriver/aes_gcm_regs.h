#ifndef __AES_GCM_REGS_H__
#define __AES_GCM_REGS_H__

#define AES_GCM_ICTRL           0x100
#define AES_GCM_OREADY          0x104
#define AES_GCM_IIV_0           0x110
#define AES_GCM_IIV_1           0x114
#define AES_GCM_IIV_2           0x118
#define AES_GCM_IIV_VALID       0x11C

#define AES_GCM_IKEY_0          0x120
#define AES_GCM_IKEY_1          0x124
#define AES_GCM_IKEY_2          0x128
#define AES_GCM_IKEY_3          0x12C
#define AES_GCM_IKEY_4          0x130
#define AES_GCM_IKEY_5          0x134
#define AES_GCM_IKEY_6          0x138
#define AES_GCM_IKEY_7          0x13C
#define AES_GCM_IKEY_VALID      0x140
#define AES_GCM_IKEYLEN         0x144

#define AES_GCM_IAAD_0          0x148
#define AES_GCM_IAAD_1          0x14C
#define AES_GCM_IAAD_2          0x150
#define AES_GCM_IAAD_3          0x154
#define AES_GCM_IAAD_VALID      0x158

#define AES_GCM_IBLOCK_0        0x160
#define AES_GCM_IBLOCK_1        0x164
#define AES_GCM_IBLOCK_2        0x168
#define AES_GCM_IBLOCK_3        0x16C
#define AES_GCM_IBLOCK_VALID    0x170

#define AES_GCM_ITAG_0          0x178
#define AES_GCM_ITAG_1          0x17C
#define AES_GCM_ITAG_2          0x180
#define AES_GCM_ITAG_3          0x184
#define AES_GCM_ITAG_VALID      0x188

#define AES_GCM_ORESULT_0       0x18C
#define AES_GCM_ORESULT_1       0x190
#define AES_GCM_ORESULT_2       0x194
#define AES_GCM_ORESULT_3       0x198
#define AES_GCM_ORESULT_VALID   0x19C

#define AES_GCM_OTAG_0          0x1A0
#define AES_GCM_OTAG_1          0x1A4
#define AES_GCM_OTAG_2          0x1A8
#define AES_GCM_OTAG_3          0x1AC
#define AES_GCM_OTAG_VALID      0x1B0

#define AES_GCM_OAUTHENTIC      0x1B4
#define AES_GCM_IRESETN         0x1B8

#endif //__AES_GCM_REGS_H__