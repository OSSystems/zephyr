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
	int ret = 0;

	#if defined(CONFIG_UPDATEHUB_POLLING)
	LOG_INF("Init sample app UpdateHub Polling");
	updatehub_autohandler();
	#endif


	k_sleep(3000);

	/* The image of application needed be confirmed */
	ret = boot_write_img_confirmed();
	if (ret < 0) {
		LOG_ERR("Error to confirm the image");
	}

	#if defined(CONFIG_UPDATEHUB_MANUAL)
	LOG_INF("Init sample app UpdateHub Manual");

	enum updatehub_response resp;

	resp = updatehub_probe();
	if (resp != UPDATEHUB_HAS_UPDATE) {
		if (resp == UPDATEHUB_NO_UPDATE) {
			LOG_INF("No update");
			return -1;
		}
		LOG_ERR("Error at probe");
		return -1;
	} else   {
		resp = updatehub_update();
		if (resp != UPDATEHUB_OK) {
			LOG_ERR("Error to install");
			return -1;
		}
	}
	#endif

	return 0;
}
