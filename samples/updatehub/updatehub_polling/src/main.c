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

	LOG_INF("Init sample app UpdateHub polling");

	ret = updatehub_init_settings();
	if (ret < 0)
	{
		LOG_ERR("Error to settings");
	}

	updatehub_autohandler();

	k_sleep(3000);

	/* The image of application needed be confirmed */
	ret = boot_write_img_confirmed();
	if (ret < 0)
	{
		LOG_ERR("Error to confirm the image");
	}

	return 0;
}
