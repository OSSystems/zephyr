/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>
#include <updatehub.h>
#include <dfu/mcuboot.h>
#include <logging/log.h>

LOG_MODULE_REGISTER(main);

int main(void)
{
	int ret = 0;
	enum updatehub_response resp;

	LOG_INF("Init sample app UpdateHub manual");

	ret = boot_write_img_confirmed();/* The image of application needed be confirmed */
	if (ret < 0)
	{
		LOG_ERR("Error to confirm the image");
	}

	resp = updatehub_probe();
	if (resp != UPDATEHUB_HAS_UPDATE)
	{
		if (resp == UPDATEHUB_NO_UPDATE)
		{
			LOG_INF("No update");
			return -1;
		}
		LOG_ERR("Error at probe");
		return -1;
	}
	else
	{
		resp = updatehub_update();
		if (resp != UPDATEHUB_OK)
		{
			LOG_ERR("Error to install");
			return -1;
		}
	}

	return 0;
}
