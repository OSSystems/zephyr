/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <updatehub.h>
#include <dfu/mcuboot.h>
#include <misc/printk.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(main);

int main(void)
{
	int ret = -1;

	LOG_INF("UpdateHub sample app started");

	/* The image of application needed be confirmed */
	LOG_INF("Confirming the boot image");
	ret = boot_write_img_confirmed();
	if (ret < 0) {
		LOG_ERR("Error to confirm the image");
	}

#if defined(CONFIG_UPDATEHUB_POLLING)
	LOG_INF("Starting UpdateHub polling mode");
	updatehub_autohandler();
#endif

#if defined(CONFIG_UPDATEHUB_MANUAL)
	LOG_INF("Starting UpdateHub manual mode");

	enum updatehub_response resp;

	switch (updatehub_probe()) {
	case UPDATEHUB_HAS_UPDATE:
		switch (updatehub_update()) {
		case UPDATEHUB_OK:
			ret = 0;
			sys_reboot(SYS_REBOOT_WARM);
			break;

		default:
			LOG_ERR("Error installing update.");
			break;
		}

	case UPDATEHUB_NO_UPDATE:
		LOG_INF("No update found");
		ret = 0;
		break;

	default:
		LOG_ERR("Invalid response");
		break;
	}
#endif

	return ret;
}
