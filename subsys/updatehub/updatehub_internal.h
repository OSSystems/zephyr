/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
   @brief This file contains contains structures representing JSON messages exchanged with a UpdateHub
 */

#ifndef __UPDATEHUB_JSON_H__
#define __UPDATEHUB_JSON_H__

enum updatehub_url {
	UPDATEHUB_PROBE = 0,
	UPDATEHUB_DOWNLOAD,
	UPDATEHUB_REPORT,
};

enum updatehub_state {
	UPDATEHUB_STATE_EXEC_DOWLOADING = 0,
	UPDATEHUB_STATE_EXEC_DOWNLOADED,
	UPDATEHUB_STATE_EXEC_INSTALLING,
	UPDATEHUB_STATE_EXEC_INSTALLED,
	UPDATEHUB_STATE_EXEC_REBOOTING,
	UPDATEHUB_STATE_EXEC_ERROR,
};

struct updatehub_probe_recv_objects {
	const char *mode;
	const char *sha256sum;
};

struct updatehub_probe_recv_objects_array {
	struct updatehub_probe_recv_objects objects;
};

struct updatehub_probe_recv_metadata_sh_string {
	struct updatehub_probe_recv_objects_array objects[2];
	size_t objects_len;
	const char *product;
	const char *supported_hardware;
};

struct updatehub_probe_recv_metadata_sh_array {
	struct updatehub_probe_recv_objects_array objects[2];
	size_t objects_len;
	const char *product;
	const char *supported_hardware[5];
	size_t supported_hardware_len;
};

struct updatehub_config_device_identity {
	const char *id;
};

struct updatehub_report {
	const char *product_uid;
	const char *hardware;
	const char *version;
	struct updatehub_config_device_identity device_identity;
	const char *status;
	const char *package_uid;
	const char *error_message;
	const char *previous_state;
};

struct updatehub_probe {
	const char *product_uid;
	const char *hardware;
	const char *version;
	struct updatehub_config_device_identity device_identity;
};

/**
 * @}
 */

#endif /* __UPDATEHUB_JSON_H__ */
