/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#ifndef KP_TOOLS_BOOTIMG_H
#define KP_TOOLS_BOOTIMG_H

#include <stddef.h>
#include <stdint.h>

/* ---- generic helpers ---- */
#define ALIGN(x, a) (((x) + (a)-1) & ~((a)-1))

/* ---- boot image constants ---- */
#define BOOT_MAGIC           "ANDROID!"
#define BOOT_MAGIC_SIZE      8
#define BOOT_NAME_SIZE       16
#define BOOT_ARGS_SIZE       512
#define BOOT_EXTRA_ARGS_SIZE 1024
#define PAGE_SIZE_DEFAULT    4096U

/* ---- compression ---- */
#define LZ4_MAGIC      0x184c2102U
#define LZ4_BLOCK_SIZE 0x800000U
#define LZ4HC_CLEVEL   12

/* ---- AVB / DTB ---- */
#define AVB_FOOTER_SIZE 64U
#define DTB_MAGIC       "\xd0\x0d\xfe\xed"

/* ---- Android boot image header (covers v0–v2) ---- */
struct boot_img_hdr {
    uint8_t  magic[BOOT_MAGIC_SIZE];
    uint32_t kernel_size;              /* bytes */
    uint32_t kernel_addr;              /* phys load addr; v3+: ramdisk_size at this offset */
    uint32_t ramdisk_size;             /* bytes */
    uint32_t ramdisk_addr;
    uint32_t second_size;
    uint32_t second_addr;
    uint32_t tags_addr;
    uint32_t page_size;
    uint32_t unused[2];                /* [0] = header_version (v1+), [1] = os_version */
    uint8_t  name[BOOT_NAME_SIZE];
    uint8_t  cmdline[BOOT_ARGS_SIZE];
    uint32_t id[8];                    /* sha1 / sha256 checksum */
    uint8_t  extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
    /* v1+ */
    uint32_t recovery_dtbo_size;
    uint64_t recovery_dtbo_offset;
    uint32_t header_size;
    /* v2+ */
    uint32_t dtb_size;
    uint64_t dtb_addr;
} __attribute__((packed));

/* ---- AVB2 footer (64 bytes, all multi-byte fields big-endian) ---- */
struct avb_footer {
    uint8_t  magic[4];       /* "AVBf" */
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t data_size1;     /* high 32 bits of original_image_size (BE) */
    uint32_t data_size2;     /* low  32 bits of original_image_size (BE) */
    uint64_t vbmeta_offset;  /* offset of VBMeta block within image (BE) */
    uint64_t vbmeta_size;    /* size of VBMeta block (BE) */
    uint8_t  reserved[28];
} __attribute__((packed));

/* ---- Flattened Device Tree header (big-endian) ---- */
struct fdt_header {
    uint32_t magic;            /* 0xd00dfeed */
    uint32_t totalsize;
    uint32_t off_dt_struct;
    uint32_t off_dt_strings;
    uint32_t off_mem_rsvmap;
    uint32_t version;
    uint32_t last_comp_version;
    uint32_t boot_cpuid_phys;
    uint32_t dt_strings_size;
    uint32_t dt_struct_size;
};

/* ---- compression format tag (first 8 magic bytes of kernel image) ---- */
typedef struct {
    uint8_t magic[8];
} compress_head;

/* ---- AVB re-sign parameters ---- */
typedef struct {
    const char *algorithm;       /* e.g. "SHA256_RSA2048" (NULL → hash-only, no RSA) */
    const char *key_path;        /* RSA PEM private key path (NULL → hash-only) */
    const char *partition_name;  /* partition name in VBMeta (NULL → "boot") */
} bootimg_avb_sign_args_t;

/* ---- public API ---- */
int extract_kernel(const char *bootimg_path);

int repack_bootimg(const char *orig_boot_path, const char *new_kernel_path,
                   const char *out_boot_path);

int repack_bootimg_ex(const char *orig_boot_path, const char *new_kernel_path,
                      const char *out_boot_path,
                      const bootimg_avb_sign_args_t *sign_args);

int resign_bootimg_avb(const char *bootimg_path,
                       const bootimg_avb_sign_args_t *sign_args);

int detect_compress_method(compress_head data);
int calculate_sha1(const char *file);
void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);

#endif /* KP_TOOLS_BOOTIMG_H */
