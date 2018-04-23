/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <shell/shell.h>
#include <flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>
#include <updatehub.h>
#include "firmware.h"
#include "device.h"


#if defined(CONFIG_UPDATEHUB_CE_SERVER)
#define UPDATEHUB_SERVER CONFIG_UPDATEHUB_SERVER
#else
#define UPDATEHUB_SERVER "coap.updatehub.io"
#endif

static int cmd_run(const struct shell *shell, size_t argc,
		   char **argv)
{
	int ret = -1;

	shell_fprintf(shell, SHELL_INFO, "Starting UpdateHub run...\n");

	switch (updatehub_probe()) {
	case UPDATEHUB_HAS_UPDATE:
		switch (updatehub_update()) {
		case UPDATEHUB_OK:
			ret = 0;
			break;
		default:
			shell_fprintf(shell, SHELL_ERROR, "Error installing update.\n");
			break;
		}
		break;

	case UPDATEHUB_NO_UPDATE:
		shell_fprintf(shell, SHELL_INFO, "No update found\n");
		ret = 0;
		break;

	default:
		shell_fprintf(shell, SHELL_ERROR, "Invalid response\n");
		break;
	}

	return ret;
}

static int cmd_info(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];
	char device_id[DEVICE_ID_SIZE];

	updatehub_get_firmware_version(firmware_version);
	updatehub_get_device_identity(device_id);


	shell_fprintf(shell, SHELL_NORMAL, "Unique device id: %s\n",
		      device_id);
	shell_fprintf(shell, SHELL_NORMAL, "Firmware Version: %s\n",
		      firmware_version);
	shell_fprintf(shell, SHELL_NORMAL, "Product uid: %s\n",
		      CONFIG_UPDATEHUB_PRODUCT_UID);
	shell_fprintf(shell, SHELL_NORMAL, "UpdateHub Server: %s\n",
		      UPDATEHUB_SERVER);
	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_updatehub, SHELL_CMD(info, NULL, "Dump UpdateHub information",
							cmd_info),
			       SHELL_CMD(run, NULL, "Trigger an UpdateHub update run", cmd_run),
			       SHELL_SUBCMD_SET_END);

SHELL_CMD_REGISTER(updatehub, &sub_updatehub, "UpdateHub commands", NULL);
