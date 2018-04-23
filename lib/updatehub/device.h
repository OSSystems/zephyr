/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __DEVICE_H__
#define __DEVICE_H__

#include <zephyr.h>
#include <hwinfo.h>

#define DEVICE_ID_SIZE 17

static inline bool updatehub_get_device_identity(char *id)
{
	int i;
	char buf[2];
	u8_t hwinfo_id[DEVICE_ID_SIZE];
	size_t length;

	length = hwinfo_get_device_id(hwinfo_id, sizeof(hwinfo_id));
	if (length <= 0) {
		return false;
	}

	memset(id, 0, DEVICE_ID_SIZE);

	for (i = 0; i < length; i++) {
		snprintk(buf, DEVICE_ID_SIZE, "%02x", hwinfo_id[i]);
		strncat(id, buf, strlen(buf));
	}

	return true;
}

#endif /* __DEVICE_H__ */
