/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2024 bmax121. All Rights Reserved.
 */

#ifndef _KP_SUPERCALL_IOCTL_H_
#define _KP_SUPERCALL_IOCTL_H_

#include <ktypes.h>

typedef int (*kp_ioctl_handler_t)(void *arg);
typedef bool (*kp_perm_check_t)(void);

struct kp_ioctl_cmd_map {
    unsigned int cmd;
    const char *name;
    kp_ioctl_handler_t handler;
    kp_perm_check_t perm_check;
};

int kp_install_fd(void);
void kp_supercalls_init(void);
void kp_supercalls_exit(void);

#endif
