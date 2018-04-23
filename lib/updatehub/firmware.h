/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __FIRMWARE_H__
#define __FIRMWARE_H__

#include <flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>

static inline bool updatehub_get_firmware_version(char *version)
{
	struct mcuboot_img_header header;

	if (boot_read_bank_header(DT_FLASH_AREA_IMAGE_0_ID, &header,
				  BOOT_IMG_VER_STRLEN_MAX) != 0) {
		return false;
	}

	snprintk(version, BOOT_IMG_VER_STRLEN_MAX, "%d.%d.%d",
		 header.h.v1.sem_ver.major,
		 header.h.v1.sem_ver.minor,
		 header.h.v1.sem_ver.revision);

	return true;
}

#endif /* __FIRMWARE_H__ */
