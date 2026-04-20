/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2026 bmax121. All Rights Reserved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include <sys/stat.h>
#include "bootimg.h"
#include "common.h"
#include "lib/lz4/lz4.h"
#include "lib/lz4/lz4frame.h"
#include "lib/lz4/lz4hc.h"
#include "lib/bz2/bzlib.h"
#include "lib/xz/xz.h"
#include "lib/sha/sha256.h"
#include "lib/sha/sha1.h"
#ifdef HAVE_OPENSSL
/*
 * openssl/sha.h (pulled in by pem.h) also typedef-s SHA256_CTX, conflicting
 * with our lib/sha/sha256.h.  Push/pop the macro to shield our definition:
 * OpenSSL ends up creating 'openssl_sha256_ctx_unused_t' instead.
 */
#pragma push_macro("SHA256_CTX")
#define SHA256_CTX openssl_sha256_ctx_unused_t
#include <openssl/evp.h>
#include <openssl/pem.h>
#pragma pop_macro("SHA256_CTX")
#endif

/* ---- byte-swap helpers ---- */

static uint64_t be64_to_host(uint64_t x)
{
    return ((x << 56) & 0xff00000000000000ULL) |
           ((x << 40) & 0x00ff000000000000ULL) |
           ((x << 24) & 0x0000ff0000000000ULL) |
           ((x <<  8) & 0x000000ff00000000ULL) |
           ((x >>  8) & 0x00000000ff000000ULL) |
           ((x >> 24) & 0x0000000000ff0000ULL) |
           ((x >> 40) & 0x000000000000ff00ULL) |
           ((x >> 56) & 0x00000000000000ffULL);
}

static uint32_t be32_to_host(uint32_t x)
{
    return ((x >> 24) & 0x000000FFu) |
           ((x >>  8) & 0x0000FF00u) |
           ((x <<  8) & 0x00FF0000u) |
           ((x << 24) & 0xFF000000u);
}

static uint32_t fdt32_to_cpu(uint32_t val)
{
    return be32_to_host(val);
}

void *memmem(const void *haystack, size_t haystacklen,
             const void *needle, size_t needlelen)
{
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;

    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;

    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(&h[i], n, needlelen) == 0)
            return (void *)&h[i];
    }
    return NULL;
}

/* Returns 1 if id contains a SHA-256 digest, 0 if SHA-1, 2 if indeterminate. */
static int id_is_sha256(const uint32_t id[8])
{
    /* SHA-1: id[0..4] non-zero, id[5..7] = 0 */
    if ((id[0] | id[1] | id[2] | id[3] | id[4] | id[5]) == 0)
        return 1;
    if (id[6] != 0 || id[7] != 0)
        return 2;
    return 0;
}

static int find_dtb_offset(const uint8_t *buf, unsigned int sz)
{
    if (!buf || sz < sizeof(struct fdt_header)) return -1;
    const uint8_t *curr = buf;
    const uint8_t *end  = buf + sz;

    while (curr < end - sizeof(struct fdt_header)) {
        curr = memmem(curr, end - curr, DTB_MAGIC, 4);
        if (curr == NULL) return -1;

        struct fdt_header *fdt_hdr = (struct fdt_header *)curr;
        uint32_t totalsize = fdt32_to_cpu(fdt_hdr->totalsize);
        uint32_t off_dt_struct = fdt32_to_cpu(fdt_hdr->off_dt_struct);
        if (totalsize > (uint32_t)(end - curr) || totalsize <= 0x48) {
            curr += 4;
            continue;
        }

        //  FDT_BEGIN_NODE (0x00000001)
        if (curr + off_dt_struct + 4 <= end) {
            const uint32_t *tag = (const uint32_t *)(curr + off_dt_struct);
            if (fdt32_to_cpu(*tag) == 0x00000001u) {
                return (int)(curr - buf);
            }
        }
        curr += 4;
    }
    return -1;
}

static int write_data_to_file(const char *path, const void *data, size_t size)
{
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    fwrite(data, 1, size, fp);
    fclose(fp);
    chmod(path, 0644);
    return 0;
}

static int compress_gzip(const uint8_t *in_data, size_t in_size, uint8_t **out_data, uint32_t *out_size)
{
    z_stream strm = {0};
    if (deflateInit2(&strm, 9, Z_DEFLATED, 16 + MAX_WBITS, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        return -1;

    uint32_t max_out_size = deflateBound(&strm, in_size);
    *out_data = malloc(max_out_size);
    if (!*out_data) { deflateEnd(&strm); return -1; }

    strm.next_in  = (Bytef *)in_data;
    strm.avail_in  = (uInt)in_size;
    strm.next_out  = *out_data;
    strm.avail_out = max_out_size;

    int ret = deflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        free(*out_data);
        deflateEnd(&strm);
        return -2;
    }

    *out_size = strm.total_out;
    deflateEnd(&strm);
    return 0;
}

static int parse_lz4_header(const compress_head *head, LZ4F_preferences_t *prefs)
{
    uint32_t magic = ((uint32_t)head->magic[0]      ) |
                     ((uint32_t)head->magic[1] <<  8) |
                     ((uint32_t)head->magic[2] << 16) |
                     ((uint32_t)head->magic[3] << 24);
    if (magic != 0x184D2204u)
        return -1;

    LZ4F_preferences_t tmp = LZ4F_INIT_PREFERENCES;
    *prefs = tmp;

    uint8_t flg = head->magic[4];
    prefs->frameInfo.blockMode = (flg & 0x20) ? LZ4F_blockIndependent : LZ4F_blockLinked;
    prefs->frameInfo.blockChecksumFlag   = (flg & 0x10) ? LZ4F_blockChecksumEnabled  : LZ4F_noBlockChecksum;
    prefs->frameInfo.contentChecksumFlag = (flg & 0x08) ? LZ4F_contentChecksumEnabled : LZ4F_noContentChecksum;

    uint8_t bd = head->magic[5];
    uint8_t block_size_id = (bd >> 4) & 0x07u;
    switch (block_size_id) {
        case 4: prefs->frameInfo.blockSizeID = LZ4F_max64KB;  break;
        case 5: prefs->frameInfo.blockSizeID = LZ4F_max256KB; break;
        case 6: prefs->frameInfo.blockSizeID = LZ4F_max1MB;   break;
        case 7: prefs->frameInfo.blockSizeID = LZ4F_max4MB;   break;
        default: return -2;
    }
    
    return 0;
}

int compress_lz4(const uint8_t *in_data, size_t in_size,
                 uint8_t **out_data, uint32_t *out_size,
                 compress_head k_head)
{
    LZ4F_preferences_t prefs;
    int ret = parse_lz4_header(&k_head, &prefs);
    if (ret < 0) {
        return -3; 
    }

    size_t max_out_size = LZ4F_compressFrameBound(in_size, &prefs);
    *out_data = (uint8_t *)malloc(max_out_size);
    if (!*out_data) return -1;

    size_t compressed_size = LZ4F_compressFrame(*out_data, max_out_size,
                                                in_data, in_size, &prefs);
    if (LZ4F_isError(compressed_size)) {
        free(*out_data);
        return -2;
    }

    *out_size = (uint32_t)compressed_size;
    return 0;
}

static int compress_lz4_le(const uint8_t *in_data, size_t in_size,
                            uint8_t **out_data, uint32_t *out_size,
                            compress_head k_head)
{
    size_t max_blocks = (in_size + LZ4_BLOCK_SIZE - 1) / LZ4_BLOCK_SIZE;
    tools_logi("Calculated max blocks: %zu\n", max_blocks);
    size_t max_out = sizeof(uint32_t) +  /* magic */
                     max_blocks * (sizeof(uint32_t) + LZ4_compressBound(LZ4_BLOCK_SIZE));

    uint8_t *out = malloc(max_out);
    if (!out) {
        tools_loge("Failed to allocate memory for LZ4 compression,size: %zu\n",max_out);
        return -2;
    }

    size_t out_off = 0;

    /* write MAGIC */
    uint32_t magic = LZ4_MAGIC;
    memcpy(out + out_off, &magic, sizeof(magic));
    out_off += sizeof(magic);

    size_t in_off = 0;

    while (in_off < in_size) {
        size_t chunk_size = in_size - in_off;
        if (chunk_size > LZ4_BLOCK_SIZE)
            chunk_size = LZ4_BLOCK_SIZE;

        int max_dst = LZ4_compressBound((int)chunk_size);

        int compressed = LZ4_compress_HC(
            (const char *)(in_data + in_off),
            (char *)(out + out_off + sizeof(uint32_t)),
            (int)chunk_size,
            max_dst,
            LZ4HC_CLEVEL
        );

        if (compressed <= 0) {
            tools_loge("LZ4 compression failed for block at offset %zu\n", in_off);
            free(out);
            return -3;
        }

        /* write compressed block size */
        uint32_t csz = (uint32_t)compressed;
        memcpy(out + out_off, &csz, sizeof(csz));
        out_off += sizeof(uint32_t);

        /* advance over compressed data */
        out_off += compressed;
        in_off += chunk_size;
    }

    *out_data = out;
    *out_size = (uint32_t)out_off;
    return 0;
}



static int auto_decompress(const uint8_t *data, size_t size, const char *out_path)
{
    if (size < 4) return -1;
    compress_head k_head;
    memcpy(&k_head, data, sizeof(k_head));
    int method = detect_compress_method(k_head);
    tools_logi("Auto-detect compression method: %d\n", method);

    if (method == 1) { /* GZIP */
        tools_logi("Detected GZIP compressed kernel.\n");
        z_stream strm = {0};
        strm.next_in  = (Bytef *)data;
        strm.avail_in = (uInt)size;
        if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) return -1;
        FILE *gzip_out = fopen(out_path, "wb");
        if (!gzip_out) { inflateEnd(&strm); return -1; }
        uint8_t gz_buf[40960];
        int gret;
        do {
            strm.next_out  = gz_buf;
            strm.avail_out = sizeof(gz_buf);
            gret = inflate(&strm, Z_NO_FLUSH);
            if (gret < 0 && gret != Z_STREAM_END) {
                tools_loge("Gzip inflate failed (err: %d)\n", gret);
                fclose(gzip_out); inflateEnd(&strm);
                return -2;
            }
            fwrite(gz_buf, 1, sizeof(gz_buf) - strm.avail_out, gzip_out);
        } while (gret != Z_STREAM_END);
        fclose(gzip_out);
        chmod(out_path, 0644);
        inflateEnd(&strm);
        tools_logi("Decompressed to %s\n", out_path);
        return 0;
    }

    if (method == 2) { /* LZ4 Frame */
        tools_logi("Detected LZ4 Frame. Decompressing...\n");
        LZ4F_decompressionContext_t dctx;
        LZ4F_createDecompressionContext(&dctx, LZ4F_VERSION);

        size_t dstCapacity = 64u * 1024u * 1024u;
        void *dst = malloc(dstCapacity);
        if (!dst) { LZ4F_freeDecompressionContext(dctx); return -1; }

        size_t consumedSize = size;
        size_t producedSize = dstCapacity;
        size_t ret = LZ4F_decompress(dctx, dst, &producedSize, data, &consumedSize, NULL);

        if (LZ4F_isError(ret)) {
            tools_loge("LZ4 decompression failed: %s\n", LZ4F_getErrorName(ret));
            free(dst);
            LZ4F_freeDecompressionContext(dctx);
            return -1;
        }
        tools_logi("LZ4 Frame decompressed: %zu bytes\n", producedSize);
        write_data_to_file(out_path, (uint8_t *)dst, (uint32_t)producedSize);
        free(dst);
        LZ4F_freeDecompressionContext(dctx);
        return 0;
    }

    if (method == 3) { /* LZ4 Legacy (block-based) */
        tools_logi("Probing LZ4 Legacy (block-based)...\n");

        const uint8_t *p   = (const uint8_t *)data;
        const uint8_t *end = p + size;

        if (size < 4)
            goto not_lz4;

        uint32_t magic_le;
        memcpy(&magic_le, p, 4);
        if (magic_le != LZ4_MAGIC)
            goto not_lz4;

        p += 4;

        size_t out_cap = 64u * 1024u * 1024u;
        uint8_t *out = malloc(out_cap);
        if (!out)
            goto not_lz4;

        size_t out_off = 0;

        uint8_t *block_out = malloc(LZ4_BLOCK_SIZE);
        if (!block_out) {
            free(out);
            goto not_lz4;
        }

        int decoded_any = 0;
        while (1) {
            uint32_t block_size;

            if (p + 4 > end)
                break; 

            memcpy(&block_size, p, 4);
            p += 4;

            if (block_size == 0)
                break;

            if (block_size > (uint32_t)LZ4_compressBound(LZ4_BLOCK_SIZE))
                goto fail;

            if (p + block_size > end)
                goto fail;

            int decoded = LZ4_decompress_safe(
                (const char *)p,
                (char *)block_out,
                (int)block_size,
                LZ4_BLOCK_SIZE
            );

            if (decoded < 0)
                goto fail;

            decoded_any = 1;

            if (out_off + (size_t)decoded > out_cap) {
                size_t new_cap = out_cap * 2;
                while (new_cap < out_off + (size_t)decoded)
                    new_cap *= 2;

                uint8_t *tmp = realloc(out, new_cap);
                if (!tmp)
                    goto fail;

                out = tmp;
                out_cap = new_cap;
            }

            memcpy(out + out_off, block_out, (size_t)decoded);
            out_off += (size_t)decoded;

            p += block_size;
        }


        if (!decoded_any)
            goto fail;

        tools_logi("LZ4 block decompressed: %zu bytes\n", out_off);
        write_data_to_file(out_path, out, (uint32_t)out_off);

        free(block_out);
        free(out);
        return 0;

    fail:
        free(block_out);
        free(out);
    not_lz4:
        tools_logi("Not a valid LZ4 legacy block stream, fallback.\n");
    }

    /* method == 4 (ZSTD) is not yet supported by any known kernel */

    if (method == 5) { /* BZIP2 */
        tools_logi("Detected BZIP2. Decompressing...\n");

        unsigned int dstCapacity = 64u * 1024u * 1024u;
        void *dst = malloc(dstCapacity);
        if (!dst) {
            tools_loge("Failed to allocate memory for BZIP2 decompression\n");
            return -1;
        }

        unsigned int producedSize = dstCapacity;
        unsigned int consumedSize = (unsigned int)size;

        int ret = BZ2_bzBuffToBuffDecompress((char *)dst, &producedSize, (char *)data, consumedSize, 0, 0);

        if (ret != BZ_OK) {
            tools_loge("BZIP2 decompression failed: %d\n", ret);
            free(dst);
            return -1;
        }

        tools_logi("BZIP2 decompressed: %u bytes\n", producedSize);
        write_data_to_file(out_path, (uint8_t *)dst, producedSize);
        free(dst);
        return 0;
    }

    if (method == 6 || method == 7) { /* XZ / LZMA (XZ container) */
        tools_logi("Detected %s. Decompressing...\n", method == 6 ? "XZ" : "LZMA");
        xz_crc32_init();
        struct xz_dec *xz_s = xz_dec_init(XZ_SINGLE, 0);
        if (!xz_s) return -1;
        uint32_t xz_cap = 128u * 1024u * 1024u;
        uint8_t *xz_dst = malloc(xz_cap);
        if (!xz_dst) { xz_dec_end(xz_s); return -1; }
        struct xz_buf xz_b = {
            .in = data, .in_pos = 0, .in_size = size,
            .out = xz_dst, .out_pos = 0, .out_size = xz_cap,
        };
        enum xz_ret xz_r = xz_dec_run(xz_s, &xz_b);
        if (xz_r != XZ_STREAM_END) {
            tools_loge("%s decompression failed: %d\n",
                       method == 6 ? "XZ" : "LZMA", xz_r);
            free(xz_dst); xz_dec_end(xz_s);
            return -1;
        }
        tools_logi("Decompressed: %u bytes\n", (uint32_t)xz_b.out_pos);
        write_data_to_file(out_path, xz_dst, (uint32_t)xz_b.out_pos);
        free(xz_dst); xz_dec_end(xz_s);
        return 0;
    }

    tools_logi("Unknown/raw kernel — saving as-is to %s\n", out_path);
    if (write_data_to_file(out_path, data, size) == 0)
        return 0;
    return -1;
}

int extract_kernel(const char *bootimg_path)
{
    FILE *fp = fopen(bootimg_path, "rb");
    if (!fp) {
        tools_loge("Cannot open %s\n", bootimg_path);
        return -1;
    }

    struct boot_img_hdr hdr;
    fread(&hdr, sizeof(hdr), 1, fp);

    if (memcmp(hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0) {
        tools_loge("Invalid boot image magic\n");
        fclose(fp);
        return -2;
    }

    uint32_t header_ver    = hdr.unused[0];
    uint32_t kernel_offset = (header_ver >= 3 && header_ver <= 10) ? 4096u : hdr.page_size;

    tools_logi("Kernel size: %u, Header version: %u, Offset: %u\n",
               hdr.kernel_size, header_ver, kernel_offset);

    uint8_t *kernel_data = malloc(hdr.kernel_size);
    if (!kernel_data) { fclose(fp); return -3; }

    fseek(fp, (long)kernel_offset, SEEK_SET);
    fread(kernel_data, 1, hdr.kernel_size, fp);
    fclose(fp);

    int res = auto_decompress(kernel_data, hdr.kernel_size, "kernel");

    free(kernel_data);
    return res;
}

int detect_compress_method(compress_head data)
{
    const uint8_t *m = data.magic;

    /* 1 — GZIP / ZOPFLI */
    if (m[0] == 0x1F && (m[1] == 0x8B || m[1] == 0x9E)) return 1;

    /* 2 — LZ4 Frame (04 22 4D 18) or legacy-frame (03 21 4C 18) */
    if ((m[0] == 0x04 && m[1] == 0x22 && m[2] == 0x4D && m[3] == 0x18) ||
        (m[0] == 0x03 && m[1] == 0x21 && m[2] == 0x4C && m[3] == 0x18))
        return 2;

    // LZ4 Legacy (02 21 4C 18)
    if (data.magic[0] == 0x02 && data.magic[1] == 0x21 && 
        data.magic[2] == 0x4C && data.magic[3] == 0x18) return 3;

    /* 3 — ZSTD (28 B5 2F FD) */
    if (m[0] == 0x28 && m[1] == 0xB5 && m[2] == 0x2F && m[3] == 0xFD) return 4;

    /* 4 — BZIP2 (BZh) */
    if (m[0] == 0x42 && m[1] == 0x5A && m[2] == 0x68) return 5;

    /* 5 — XZ (FD 37 7A 58) */
    if (m[0] == 0xFD && m[1] == 0x37 && m[2] == 0x7A && m[3] == 0x58) return 6;

    /* 6 — LZMA legacy (5D 00 00) */
    if (m[0] == 0x5D && m[1] == 0x00 && m[2] == 0x00) return 7;

    return 0; /* raw / unknown */
}

/* ---- repack helpers ---- */

static int repack_bootimg_internal(const char *orig_boot_path,
                                   const char *new_kernel_path,
                                   const char *out_boot_path,
                                   const bootimg_avb_sign_args_t *sign_args)
{
    tools_logi("Starting repack...\n");

    FILE *f_orig = fopen(orig_boot_path, "rb");
    if (!f_orig) return -1;

    struct boot_img_hdr hdr;
    struct avb_footer   avb;
    uint32_t extracted_size = 0;
    fread(&hdr, sizeof(hdr), 1, f_orig);

    if (memcmp(hdr.magic, BOOT_MAGIC, BOOT_MAGIC_SIZE) != 0) {
        tools_logi("Not a valid Android Boot Image.\n");
        fclose(f_orig);
        return -2;
    }

    fseek(f_orig, 0, SEEK_END);
    long total_size = ftell(f_orig);

    fseek(f_orig, total_size - (long)sizeof(avb), SEEK_SET);
    fread(&avb, sizeof(avb), 1, f_orig);

    uint32_t header_ver = hdr.unused[0];
    if (header_ver > 10) { header_ver = 0; extracted_size = hdr.unused[0]; }
    uint32_t page_size = (header_ver >= 3) ? 4096u : hdr.page_size;
    uint32_t fmt_size  = (header_ver >= 3) ? hdr.kernel_addr : hdr.ramdisk_size;

    tools_logi("Header version: %u, Page size: %u, fmt_size: %u\n", header_ver, page_size, fmt_size);

    uint8_t *old_k_full = malloc(hdr.kernel_size);
    fseek(f_orig, (long)page_size, SEEK_SET);
    fread(old_k_full, 1, hdr.kernel_size, f_orig);

    compress_head k_head;
    memcpy(&k_head, old_k_full, sizeof(k_head));
    int method = detect_compress_method(k_head);

    /* Extract DTB appended to kernel (v0/v1/v2 only) */
    uint8_t *extracted_dtb = NULL;
    uint32_t dtb_size = 0;
    if (header_ver < 3) {
        int dtb_off = find_dtb_offset(old_k_full, hdr.kernel_size);
        if (dtb_off > 0) {
            dtb_size = hdr.kernel_size - (uint32_t)dtb_off;
            extracted_dtb = malloc(dtb_size);
            memcpy(extracted_dtb, old_k_full + dtb_off, dtb_size);
            tools_logi("Detected appended DTB. Size: %u\n", dtb_size);
        }
    }
    free(old_k_full);


    FILE *f_new_k = fopen(new_kernel_path, "rb");
    if (!f_new_k) { fclose(f_orig); if(extracted_dtb) free(extracted_dtb); return -3; }
    fseek(f_new_k, 0, SEEK_END);
    uint32_t raw_k_size = ftell(f_new_k);
    fseek(f_new_k, 0, SEEK_SET);
    uint8_t *raw_k_buf = malloc(raw_k_size);
    fread(raw_k_buf, 1, raw_k_size, f_new_k);
    fclose(f_new_k);

    uint8_t *final_k_buf = raw_k_buf;
    uint32_t final_k_size = raw_k_size;
    uint8_t *compressed_buf = NULL;

    if (method == 1) { /* GZIP */
        tools_logi("Compressing new kernel with GZIP...\n");
        if (compress_gzip(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0)
            final_k_buf = compressed_buf;
    }
    if (method == 2) { /* LZ4 Frame */
        tools_logi("Compressing new kernel with LZ4 Frame...\n");
        if (compress_lz4(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size, k_head) == 0)
            final_k_buf = compressed_buf;
    }
    if (method == 3) { /* LZ4 Legacy */
        tools_logi("Compressing new kernel with LZ4 Legacy...\n");
        if (compress_lz4_le(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size, k_head) == 0)
            final_k_buf = compressed_buf;
    }
    if (method == 4) {
        tools_loge("ZSTD kernel compression is not supported yet\n");
        fclose(f_orig);
        free(raw_k_buf);
        if (extracted_dtb) free(extracted_dtb);
        return -1;
    }
    if (method == 5) { /* BZIP2 */
        tools_logi("Compressing new kernel with BZIP2 (level 9)...\n");
        unsigned int max_out = (unsigned int)(raw_k_size * 1.01) + 600;
        uint8_t *bz_buf = (uint8_t *)malloc(max_out);
        if (!bz_buf) { fclose(f_orig); free(raw_k_buf); if (extracted_dtb) free(extracted_dtb); return -1; }
        unsigned int bz_out = max_out;
        int ret = BZ2_bzBuffToBuffCompress((char *)bz_buf, &bz_out,
                                           (char *)raw_k_buf, (unsigned int)raw_k_size,
                                           9, 0, 30);
        if (ret == BZ_OK) {
            compressed_buf = bz_buf;
            final_k_buf    = bz_buf;
            final_k_size   = bz_out;
            tools_logi("BZIP2 compression done. Size: %u bytes\n", final_k_size);
        } else {
            tools_loge("BZIP2 compression failed: %d\n", ret);
            free(bz_buf);
            fclose(f_orig);
            free(raw_k_buf);
            if (extracted_dtb) free(extracted_dtb);
            return -1;
        }
    }
    if (method == 6 || method == 7) { /* XZ/LZMA → fall back to GZIP */
        tools_logi("Original kernel was XZ/LZMA; repacking as GZIP for compatibility...\n");
        if (compress_gzip(raw_k_buf, raw_k_size, &compressed_buf, &final_k_size) == 0) {
            final_k_buf = compressed_buf;
            method = 1;
            tools_logi("Repacked as GZIP. New size: %u bytes\n", final_k_size);
        } else {
            tools_loge("GZIP compression failed\n");
            fclose(f_orig);
            free(raw_k_buf);
            if (extracted_dtb) free(extracted_dtb);
            return -1;
        }
    }
    tools_logi("Final kernel size (after compression): %u bytes\n", final_k_size);
    uint32_t old_k_aligned    = ALIGN(hdr.kernel_size, page_size);
    uint32_t rest_data_offset = page_size + old_k_aligned;
    uint32_t rest_data_size   = ((long)total_size > (long)rest_data_offset)
                                ? ((uint32_t)total_size - rest_data_offset) : 0u;
    hdr.kernel_size = final_k_size + dtb_size;
    uint32_t checksum_aligned = ALIGN(fmt_size, page_size);
    uint8_t *rest_buf_tmp = NULL;
    uint8_t *rest_buf = NULL;
    uint32_t rest_buf_offset  = 0;
    if (rest_data_size > 0) {
        rest_buf_tmp = malloc(rest_data_size);
        fseek(f_orig, (long)rest_data_offset, SEEK_SET);
        fread(rest_buf_tmp, 1, rest_data_size - sizeof(avb), f_orig);
        for (int32_t i = (int32_t)rest_data_size - 1; i >= 0; i--) {
            if (rest_buf_tmp[i] != 0) {
                rest_buf_offset = (uint32_t)(i + 1);
                break;
            }
        }
        if (rest_buf_offset > rest_data_size / 3 * 2) {
            tools_logw("Rest data is large; possible overflow (total=%u used=%u)\n",
                       rest_data_size, rest_buf_offset);
            rest_buf       = rest_buf_tmp;
            rest_data_size = rest_buf_offset + (uint32_t)sizeof(avb);
        } else {
            rest_buf = malloc(rest_buf_offset);
            memcpy(rest_buf, rest_buf_tmp, rest_buf_offset);
            tools_logi("Rest data: total=%u used=%u bytes\n", rest_data_size, rest_buf_offset);
            rest_data_size = rest_buf_offset;
            free(rest_buf_tmp);
        }

    }
    fclose(f_orig);

    uint32_t id_copy[8];
    memcpy(id_copy, hdr.id, sizeof(id_copy));
    uint32_t use_sha256 = id_is_sha256(id_copy);
    int digest_len = (int)(use_sha256 ? SHA256_BLOCK_SIZE : SHA1_DIGEST_SIZE);
    BYTE digest_buf[SHA256_BLOCK_SIZE]; /* large enough for both */
    if (use_sha256 != 1 || header_ver <= 3) {

        if (use_sha256) {
            SHA256_CTX ctx;
            sha256_init(&ctx);
            sha256_update(&ctx, (const BYTE *)final_k_buf, hdr.kernel_size);
            sha256_update(&ctx, (const BYTE *)&hdr.kernel_size, 4);
            sha256_update(&ctx, (const BYTE *)rest_buf, fmt_size);
            sha256_update(&ctx, (const BYTE *)&fmt_size, sizeof(fmt_size));

            sha256_update(&ctx, (const BYTE *)rest_buf + checksum_aligned, hdr.second_size);
            sha256_update(&ctx, (const BYTE *)&hdr.second_size, 4);
            tools_logi("second_size=%u\n", hdr.second_size);
            if (hdr.second_size > 0)
                checksum_aligned += ALIGN(hdr.second_size, page_size);
            if (extracted_size) {
                tools_logi("extracted_size=%u\n", extracted_size);
                sha256_update(&ctx, (const BYTE *)rest_buf + checksum_aligned, page_size);
                sha256_update(&ctx, (const BYTE *)&extracted_size, 4);
                checksum_aligned += ALIGN(extracted_size, page_size);
            }
            if (header_ver == 1 || header_ver == 2) {
                tools_logi("recovery_dtbo_size=%u\n", hdr.recovery_dtbo_size);
                sha256_update(&ctx, (const BYTE *)rest_buf + checksum_aligned, hdr.recovery_dtbo_size);
                sha256_update(&ctx, (const BYTE *)&hdr.recovery_dtbo_size, 4);
                checksum_aligned += ALIGN(hdr.recovery_dtbo_size, page_size);
            }
            if (header_ver == 2) {
                tools_logi("dtb_size=%u\n", hdr.dtb_size);
                sha256_update(&ctx, (const BYTE *)rest_buf + checksum_aligned, hdr.dtb_size);
                sha256_update(&ctx, (const BYTE *)&hdr.dtb_size, 4);
            }

            sha256_final(&ctx, digest_buf);
            memcpy(hdr.id, digest_buf, SHA256_BLOCK_SIZE);
        } else {
            SHA1_CTX sha1_ctx;
            sha1_init(&sha1_ctx);
            sha1_update(&sha1_ctx, (const BYTE *)final_k_buf, hdr.kernel_size);
            sha1_update(&sha1_ctx, (const BYTE *)&hdr.kernel_size, 4);
            sha1_update(&sha1_ctx, (const BYTE *)rest_buf, fmt_size);
            sha1_update(&sha1_ctx, (const BYTE *)&fmt_size, sizeof(fmt_size));

            sha1_update(&sha1_ctx, (const BYTE *)rest_buf + checksum_aligned, hdr.second_size);
            sha1_update(&sha1_ctx, (const BYTE *)&hdr.second_size, 4);
            if (hdr.second_size > 0)
                checksum_aligned += ALIGN(hdr.second_size, page_size);
            tools_logi("second_size=%u, offset=%u\n", hdr.second_size, checksum_aligned + rest_data_offset);
            if (extracted_size) {
                tools_logi("extracted_size=%u, offset=%u\n", extracted_size, checksum_aligned + rest_data_offset);
                sha1_update(&sha1_ctx, (const BYTE *)rest_buf + checksum_aligned, page_size);
                sha1_update(&sha1_ctx, (const BYTE *)&extracted_size, 4);
                checksum_aligned += ALIGN(extracted_size, page_size);
            }

            if (header_ver == 1 || header_ver == 2) {
                tools_logi("recovery_dtbo_size=%u, offset=%u\n", hdr.recovery_dtbo_size, checksum_aligned + rest_data_offset);
                sha1_update(&sha1_ctx, (const BYTE *)rest_buf + checksum_aligned, hdr.recovery_dtbo_size);
                sha1_update(&sha1_ctx, (const BYTE *)&hdr.recovery_dtbo_size, 4);
                checksum_aligned += ALIGN(hdr.recovery_dtbo_size, page_size);
            }
            if (header_ver == 2) {
                tools_logi("dtb_size=%u, dtb_addr=%llu\n", hdr.dtb_size, (unsigned long long)hdr.dtb_addr);
                sha1_update(&sha1_ctx, (const BYTE *)rest_buf + checksum_aligned, hdr.dtb_size);
                sha1_update(&sha1_ctx, (const BYTE *)&hdr.dtb_size, 4);
            }

            sha1_final(&sha1_ctx, digest_buf);
            memcpy(hdr.id, digest_buf, SHA1_DIGEST_SIZE);
        }
    }
    (void)digest_len; /* suppress unused-variable warning */

    FILE *f_out = fopen(out_boot_path, "wb");
    if (!f_out) return -4;

    fwrite(&hdr, sizeof(hdr), 1, f_out);
    fseek(f_out, (long)page_size, SEEK_SET);

    fwrite(final_k_buf, 1, final_k_size, f_out);
    if (extracted_dtb)
        fwrite(extracted_dtb, 1, dtb_size, f_out);
    tools_logi("dtb_size=%u\n", dtb_size);

    uint32_t new_k_total_aligned = ALIGN(hdr.kernel_size, page_size);
    fseek(f_out, (long)(page_size + new_k_total_aligned), SEEK_SET);

    /* AVB footer signature prefix (first 19 bytes, version byte tried 0/1/2) */
    uint8_t avb_sig[] = {
        0x41, 0x56, 0x42, 0x30,  /* "AVB0" */
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00         /* version minor, patched below */
    };


    if (rest_buf) {
        uint8_t *avb_ptr = memmem(rest_buf, rest_data_size, avb_sig, sizeof(avb_sig));

        if (!avb_ptr) {
            avb_sig[18] = 0x01; /* try version 1 */
            avb_ptr = memmem(rest_buf, rest_data_size, avb_sig, sizeof(avb_sig));
        }
        if (!avb_ptr) {
            avb_sig[18] = 0x02; /* try version 2 */
            avb_ptr = memmem(rest_buf, rest_data_size, avb_sig, sizeof(avb_sig));
        }
        if (avb_ptr) {
            uint8_t *last_avb  = NULL;
            uint8_t *search_ptr = avb_ptr;
            while (search_ptr) {
                last_avb = search_ptr;
                tools_logi("Found AVB footer at %p\n", (void *)search_ptr);
                uint32_t offset = (uint32_t)(search_ptr - rest_buf) + (uint32_t)sizeof(avb_sig);
                if (offset >= rest_data_size) break;
                search_ptr = memmem(rest_buf + offset, rest_data_size - offset,
                                    avb_sig, sizeof(avb_sig));
            }
            avb_ptr = last_avb;
        }

        if (avb_ptr) {
            size_t   avb_offset = (size_t)(avb_ptr - rest_buf);
            tools_logi("avb_offset=%zu\n", avb_offset);
            uint32_t image_size = page_size + (uint32_t)avb_offset + new_k_total_aligned;
            avb.data_size1    = be32_to_host(image_size);
            avb.data_size2    = be32_to_host(image_size);
            avb.vbmeta_offset = be64_to_host((uint64_t)(page_size + new_k_total_aligned + avb_offset));
        }
        if ((long)rest_data_size > total_size - (long)page_size - (long)new_k_total_aligned) {
            /* rest data grew; expand total_size to fit */
            total_size = (long)ALIGN(page_size + new_k_total_aligned + rest_data_size, page_size);
            fwrite(rest_buf, 1, (size_t)total_size - page_size - new_k_total_aligned - sizeof(avb), f_out);
            fwrite(&avb, sizeof(avb), 1, f_out);
        } else {
            fwrite(rest_buf, 1, rest_data_size, f_out);
        }
    }

    long current_pos = ftell(f_out);
    if (current_pos < total_size - (long)sizeof(avb)) {
        uint32_t  padding   = (uint32_t)(total_size - current_pos - (long)sizeof(avb));
        uint8_t  *zero_pad  = calloc(1, padding);
        fwrite(zero_pad, 1, padding, f_out);
        free(zero_pad);
        fwrite(&avb, sizeof(avb), 1, f_out);
    }

    fclose(f_out);
    if (compressed_buf) free(compressed_buf);
    if (extracted_dtb)  free(extracted_dtb);
    free(raw_k_buf);
    if (rest_buf) free(rest_buf);

    tools_logi("Repack completed: %s\n", out_boot_path);

    /* Optional AVB re-sign */
    if (sign_args) {
        tools_logi("Performing AVB re-sign on %s\n", out_boot_path);
        return resign_bootimg_avb(out_boot_path, sign_args);
    }
    return 0;
}

/* ---- public API wrappers ---- */

int repack_bootimg(const char *orig_boot_path, const char *new_kernel_path,
                   const char *out_boot_path)
{
    return repack_bootimg_internal(orig_boot_path, new_kernel_path, out_boot_path, NULL);
}

int repack_bootimg_ex(const char *orig_boot_path, const char *new_kernel_path,
                      const char *out_boot_path,
                      const bootimg_avb_sign_args_t *sign_args)
{
    return repack_bootimg_internal(orig_boot_path, new_kernel_path, out_boot_path, sign_args);
}

/* ========================================================================
 * Internal AVBMeta (Android Verified Boot 2.0) structures
 * All multi-byte fields are big-endian on the wire.
 * ======================================================================== */

#define AVB_DESCRIPTOR_TAG_HASH  2ULL

/* VBMeta image header — exactly 256 bytes */
struct avb_vbmeta_header {
    uint8_t  magic[4];
    uint32_t required_libavb_version_major;
    uint32_t required_libavb_version_minor;
    uint64_t authentication_data_block_size;
    uint64_t auxiliary_data_block_size;
    uint32_t algorithm_type;
    uint64_t hash_offset;
    uint64_t hash_size;
    uint64_t signature_offset;
    uint64_t signature_size;
    uint64_t public_key_offset;
    uint64_t public_key_size;
    uint64_t public_key_metadata_offset;
    uint64_t public_key_metadata_size;
    uint64_t descriptor_offset;
    uint64_t descriptor_size;
    uint64_t rollback_index;
    uint32_t flags;
    uint32_t rollback_index_location;
    uint8_t  release_string[48];
    uint8_t  reserved[80];
} __attribute__((packed));

/* Generic descriptor header (16 bytes) */
struct avb_descriptor {
    uint64_t tag;
    uint64_t num_bytes_following;
} __attribute__((packed));

/* Hash descriptor body (follows avb_descriptor header) */
struct avb_hash_descriptor_body {
    uint64_t image_size;
    uint8_t  hash_algorithm[32];  /* "sha256\0..." */
    uint32_t partition_name_len;
    uint32_t salt_len;
    uint32_t digest_len;
    uint32_t flags;
    uint8_t  reserved[60];
    /* variable: partition_name[], salt[], digest[] */
} __attribute__((packed));

enum avb_algorithm_type {
    AVB_ALGORITHM_TYPE_NONE           = 0,
    AVB_ALGORITHM_TYPE_SHA256_RSA2048 = 1,
    AVB_ALGORITHM_TYPE_SHA256_RSA4096 = 2,
    AVB_ALGORITHM_TYPE_SHA256_RSA8192 = 3,
    AVB_ALGORITHM_TYPE_SHA512_RSA2048 = 4,
    AVB_ALGORITHM_TYPE_SHA512_RSA4096 = 5,
    AVB_ALGORITHM_TYPE_SHA512_RSA8192 = 6,
};

/*
 * resign_bootimg_avb — natively re-sign a boot image's VBMeta AVB block.
 *
 * Steps:
 *  1. Read AVBf footer (last 64 bytes of image).
 *  2. Locate and parse the VBMeta block (pointed to by the footer).
 *  3. Find the HashDescriptor for `partition_name` (default "boot").
 *  4. Recompute SHA256(salt || image_data[0:vbmeta_offset]) and update it.
 *  5. Recompute the authentication hash (SHA256 of vbmeta_header + aux_block).
 *  6. If key_path is provided and OpenSSL is available, sign with RSA PKCS#1.
 *  7. Write the updated VBMeta block back in place.
 */
int resign_bootimg_avb(const char *bootimg_path, const bootimg_avb_sign_args_t *sign_args)
{
    if (!bootimg_path || !sign_args) {
        tools_loge("resign_bootimg_avb: bootimg_path and sign_args are required\n");
        return -1;
    }

    /* ---- 1. Open image for in-place update ---- */
    FILE *fp = fopen(bootimg_path, "r+b");
    if (!fp) { tools_loge("Cannot open %s\n", bootimg_path); return -1; }

    fseek(fp, 0, SEEK_END);
    long img_file_size = ftell(fp);
    if (img_file_size < (long)AVB_FOOTER_SIZE) { fclose(fp); return -1; }

    /* ---- 2. Read AVBf footer ---- */
    struct avb_footer footer;
    fseek(fp, img_file_size - (long)AVB_FOOTER_SIZE, SEEK_SET);
    fread(&footer, sizeof(footer), 1, fp);

    if (memcmp(footer.magic, "AVBf", 4) != 0) {
        tools_loge("No AVBf footer found in %s\n", bootimg_path);
        fclose(fp); return -1;
    }

    /* ---- 3. Parse footer (big-endian) ---- */
    uint64_t vbmeta_offset = be64_to_host(footer.vbmeta_offset);
    uint64_t vbmeta_size   = be64_to_host(footer.vbmeta_size);
    tools_logi("AVBf: vbmeta_offset=%llu vbmeta_size=%llu\n",
               (unsigned long long)vbmeta_offset, (unsigned long long)vbmeta_size);

    if (vbmeta_offset + vbmeta_size > (uint64_t)img_file_size ||
        vbmeta_size < sizeof(struct avb_vbmeta_header)) {
        tools_loge("Invalid VBMeta location in footer\n");
        fclose(fp); return -1;
    }

    /* ---- 4. Read VBMeta block ---- */
    uint8_t *vbmeta_buf = malloc((size_t)vbmeta_size);
    if (!vbmeta_buf) { fclose(fp); return -1; }
    fseek(fp, (long)vbmeta_offset, SEEK_SET);
    fread(vbmeta_buf, 1, (size_t)vbmeta_size, fp);

    struct avb_vbmeta_header *vmh = (struct avb_vbmeta_header *)vbmeta_buf;
    if (memcmp(vmh->magic, "AVB0", 4) != 0) {
        tools_loge("Invalid VBMeta magic\n");
        free(vbmeta_buf); fclose(fp); return -1;
    }

    /* ---- 5. Parse VBMeta layout (all BE) ---- */
    uint64_t auth_size  = be64_to_host(vmh->authentication_data_block_size);
    uint64_t aux_size   = be64_to_host(vmh->auxiliary_data_block_size);
    uint64_t desc_off   = be64_to_host(vmh->descriptor_offset);
    uint64_t desc_size  = be64_to_host(vmh->descriptor_size);
    uint32_t algo_type  = be32_to_host(vmh->algorithm_type);

    if (sizeof(struct avb_vbmeta_header) + auth_size + aux_size > vbmeta_size) {
        tools_loge("VBMeta block size mismatch\n");
        free(vbmeta_buf); fclose(fp); return -1;
    }

    uint8_t *auth_block = vbmeta_buf + sizeof(struct avb_vbmeta_header);
    uint8_t *aux_block  = auth_block + auth_size;

    /* ---- 6. Find HashDescriptor for target partition ---- */
    const char *target_part = sign_args->partition_name ? sign_args->partition_name : "boot";
    size_t      target_len  = strlen(target_part);

    uint8_t *dp     = aux_block + desc_off;
    uint8_t *dp_end = aux_block + desc_off + desc_size;

    struct avb_hash_descriptor_body *hash_body  = NULL;
    uint8_t  *hash_salt   = NULL;
    uint8_t  *hash_digest = NULL;
    uint32_t  salt_len    = 0;
    uint32_t  digest_len  = 0;

    while (dp + sizeof(struct avb_descriptor) <= dp_end) {
        struct avb_descriptor *desc = (struct avb_descriptor *)dp;
        uint64_t tag       = be64_to_host(desc->tag);
        uint64_t following = be64_to_host(desc->num_bytes_following);

        if (dp + sizeof(struct avb_descriptor) + following > dp_end) break;

        if (tag == AVB_DESCRIPTOR_TAG_HASH) {
            struct avb_hash_descriptor_body *body =
                (struct avb_hash_descriptor_body *)(dp + sizeof(struct avb_descriptor));
            uint32_t plen = be32_to_host(body->partition_name_len);
            uint32_t slen = be32_to_host(body->salt_len);
            uint32_t dlen = be32_to_host(body->digest_len);
            uint8_t *pnam = (uint8_t *)body + sizeof(struct avb_hash_descriptor_body);

            if (plen == (uint32_t)target_len &&
                memcmp(pnam, target_part, target_len) == 0) {
                hash_body   = body;
                hash_salt   = pnam + plen;
                hash_digest = hash_salt + slen;
                salt_len    = slen;
                digest_len  = dlen;
                tools_logi("Found HashDescriptor for '%s'\n", target_part);
                break;
            }
        }

        /* advance to next descriptor (padded to 8-byte boundary) */
        uint64_t step = ((sizeof(struct avb_descriptor) + following) + 7u) & ~7ULL;
        dp += step;
    }

    if (!hash_body) {
        tools_loge("HashDescriptor for '%s' not found in VBMeta\n", target_part);
        free(vbmeta_buf); fclose(fp); return -1;
    }

    /* ---- 7. Recompute image hash = SHA256(salt || image[0:vbmeta_offset]) ---- */
    hash_body->image_size = be64_to_host(vbmeta_offset);

    SHA256_CTX sha_ctx;
    sha256_init(&sha_ctx);
    if (salt_len > 0)
        sha256_update(&sha_ctx, (const BYTE *)hash_salt, salt_len);

    fseek(fp, 0, SEEK_SET);
    uint8_t *chunk = malloc(65536);
    if (!chunk) { free(vbmeta_buf); fclose(fp); return -1; }

    uint64_t remaining = vbmeta_offset;
    while (remaining > 0) {
        size_t want = (remaining > 65536) ? 65536 : (size_t)remaining;
        size_t got  = fread(chunk, 1, want, fp);
        if (got == 0) break;
        sha256_update(&sha_ctx, (const BYTE *)chunk, got);
        remaining -= got;
    }
    free(chunk);

    BYTE new_digest[SHA256_BLOCK_SIZE];
    sha256_final(&sha_ctx, new_digest);

    uint32_t copy_len = (digest_len < (uint32_t)SHA256_BLOCK_SIZE)
                        ? digest_len : (uint32_t)SHA256_BLOCK_SIZE;
    memcpy(hash_digest, new_digest, copy_len);
    tools_logi("Updated image hash in HashDescriptor\n");

    /* ---- 8. Recompute VBMeta auth hash = SHA256(vmh_header || aux_block) ---- */
    uint64_t auth_hash_off  = be64_to_host(vmh->hash_offset);
    uint64_t auth_hash_size = be64_to_host(vmh->hash_size);

    if (auth_hash_off + auth_hash_size > auth_size) {
        tools_loge("Auth hash offset out of range\n");
        free(vbmeta_buf); fclose(fp); return -1;
    }

    SHA256_CTX auth_sha;
    sha256_init(&auth_sha);
    sha256_update(&auth_sha, (const BYTE *)vmh, sizeof(struct avb_vbmeta_header));
    sha256_update(&auth_sha, (const BYTE *)aux_block, (size_t)aux_size);
    sha256_final(&auth_sha, auth_block + auth_hash_off);
    tools_logi("Recomputed VBMeta authentication hash\n");

    /* ---- 9. RSA signing (requires OpenSSL + PEM private key) ---- */
    uint64_t sig_off   = be64_to_host(vmh->signature_offset);
    uint64_t sig_field = be64_to_host(vmh->signature_size);

    if (sign_args->key_path && algo_type != AVB_ALGORITHM_TYPE_NONE) {
#ifdef HAVE_OPENSSL
        FILE *key_fp = fopen(sign_args->key_path, "r");
        if (!key_fp) {
            tools_loge("Cannot open key file: %s\n", sign_args->key_path);
            free(vbmeta_buf); fclose(fp); return -1;
        }
        EVP_PKEY *pkey = PEM_read_PrivateKey(key_fp, NULL, NULL, NULL);
        fclose(key_fp);
        if (!pkey) {
            tools_loge("Failed to load private key from %s\n", sign_args->key_path);
            free(vbmeta_buf); fclose(fp); return -1;
        }

        /* SHA512 for algorithm types >= 4, SHA256 for 1–3 */
        const EVP_MD *md = (algo_type >= (uint32_t)AVB_ALGORITHM_TYPE_SHA512_RSA2048)
                           ? EVP_sha512() : EVP_sha256();

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey);
        EVP_DigestSignUpdate(mdctx, (const uint8_t *)vmh, sizeof(struct avb_vbmeta_header));
        EVP_DigestSignUpdate(mdctx, aux_block, (size_t)aux_size);

        size_t actual_sig_len = 0;
        EVP_DigestSignFinal(mdctx, NULL, &actual_sig_len);  /* query size */

        if (actual_sig_len > sig_field || sig_off + actual_sig_len > auth_size) {
            tools_loge("RSA signature too large for auth block\n");
            EVP_MD_CTX_free(mdctx); EVP_PKEY_free(pkey);
            free(vbmeta_buf); fclose(fp); return -1;
        }

        memset(auth_block + sig_off, 0, (size_t)sig_field);
        EVP_DigestSignFinal(mdctx, auth_block + sig_off, &actual_sig_len);
        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);
        tools_logi("RSA signature updated (%zu bytes)\n", actual_sig_len);
#else
        tools_logw("OpenSSL not built in — hash updated but RSA signature is stale.\n"
                   "Rebuild with -DOPENSSL_ROOT_DIR=<path> for full signing.\n");
        (void)sig_off; (void)sig_field;
#endif
    } else if (sig_off + sig_field <= auth_size) {
        /* NONE algorithm or no key → zero the signature slot */
        memset(auth_block + sig_off, 0, (size_t)sig_field);
    }

    /* ---- 10. Write updated VBMeta back in place ---- */
    fseek(fp, (long)vbmeta_offset, SEEK_SET);
    fwrite(vbmeta_buf, 1, (size_t)vbmeta_size, fp);
    fclose(fp);
    free(vbmeta_buf);

    tools_logi("AVB re-sign completed: %s\n", bootimg_path);
    return 0;
}

int calculate_sha1(const char *file)
{
    FILE *fp = fopen(file, "rb");
    if (!fp) return -1;

    SHA1_CTX ctx;
    sha1_init(&ctx);

    const size_t BUF_SIZE = 409600;
    uint8_t *buffer = malloc(BUF_SIZE);
    if (!buffer) { fclose(fp); return -1; }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUF_SIZE, fp)) > 0)
        sha1_update(&ctx, buffer, bytes_read);
    fclose(fp);

    uint8_t hash[SHA1_DIGEST_SIZE];
    sha1_final(&ctx, hash);
    free(buffer);

    for (int i = 0; i < SHA1_DIGEST_SIZE; i++)
        printf("%02x", hash[i]);
    return 0;
}
