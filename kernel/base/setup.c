/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 */

#include "setup.h"
#include "../version"

uint64_t setup_find_kallsyms_lookup_name_offset(uint64_t kernel_pa, setup_preset_t *preset)
{
    (void)kernel_pa;
    (void)preset;
    return 0;
}

setup_header_t header __section(.setup.header) = { .magic = KP_MAGIC,
                                                   .kp_version.major = MAJOR,
                                                   .kp_version.minor = MINOR,
                                                   .kp_version.patch = PATCH,
                                                   .config_flags = 0
#ifdef ANDROID
                                                                   | CONFIG_ANDROID
#endif
#ifdef DEBUG
                                                                   | CONFIG_DEBUG
#endif
                                                   ,
                                                   .compile_time = __TIME__ " " __DATE__ };

setup_preset_t setup_preset __section(.setup.preset) = { 0 };

int setup_puff(unsigned char *dest, unsigned long *destlen, const unsigned char *source, unsigned long *sourcelen);

int setup_inflate(void *dest, unsigned long destlen, const void *source, unsigned long sourcelen)
{
    unsigned long out_len = destlen;
    unsigned long in_len = sourcelen;
    int rc = setup_puff(dest, &out_len, source, &in_len);
    if (rc) return rc;
    return out_len == destlen ? 0 : -1;
}

struct
{
    uint8_t fp[STACK_SIZE];
    uint8_t sp[0];
} stack __section(.setup.data) __aligned(16);
