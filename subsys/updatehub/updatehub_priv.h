/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *
 *  @brief This file contains contains structures representing JSON messages
 *  exchanged with a UpdateHub
 */

#ifndef __UPDATEHUB_PRIV_H__
#define __UPDATEHUB_PRIV_H__

enum updatehub_uri_path {
	UPDATEHUB_PROBE = 0,
	UPDATEHUB_REPORT,
	UPDATEHUB_DOWNLOAD,
};

enum updatehub_state {
	UPDATEHUB_STATE_DOWNLOADING = 0,
	UPDATEHUB_STATE_DOWNLOADED,
	UPDATEHUB_STATE_INSTALLING,
	UPDATEHUB_STATE_INSTALLED,
	UPDATEHUB_STATE_REBOOTING,
	UPDATEHUB_STATE_ERROR,
};

struct resp_probe_objects {
	const char *mode;
	const char *sha256sum;
	int size;
};

struct resp_probe_objects_array {
	struct resp_probe_objects objects;
};

struct resp_probe_any_boards {
	struct resp_probe_objects_array objects[2];
	size_t objects_len;
	const char *product;
	const char *supported_hardware;
};

struct resp_probe_some_boards {
	struct resp_probe_objects_array objects[2];
	size_t objects_len;
	const char *product;
	const char *supported_hardware[40];
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

static const struct json_obj_descr recv_probe_objects_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct resp_probe_objects,
			    mode, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct resp_probe_objects,
			    sha256sum, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct resp_probe_objects,
			    size, JSON_TOK_NUMBER),
};

static const struct json_obj_descr recv_probe_objects_descr_array[] =
{
	JSON_OBJ_DESCR_OBJECT(struct resp_probe_objects_array,
			      objects, recv_probe_objects_descr),
};

static const struct json_obj_descr recv_probe_sh_string_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct resp_probe_any_boards,
			    product, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM_NAMED(struct resp_probe_any_boards,
				  "supported-hardware", supported_hardware,
				  JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_ARRAY(struct resp_probe_any_boards,
				   objects, 2, objects_len,
				   recv_probe_objects_descr_array,
				   ARRAY_SIZE(recv_probe_objects_descr_array)),
};

static const struct json_obj_descr recv_probe_sh_array_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct resp_probe_some_boards,
			    product, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_NAMED(struct resp_probe_some_boards,
				   "supported-hardware", supported_hardware, 40,
				   supported_hardware_len, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_ARRAY(struct resp_probe_some_boards,
				   objects, 2, objects_len,
				   recv_probe_objects_descr_array,
				   ARRAY_SIZE(recv_probe_objects_descr_array)),
};

static const struct json_obj_descr device_identity_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct updatehub_config_device_identity,
			    id, JSON_TOK_STRING),
};

static const struct json_obj_descr send_report_descr[] =
{
	JSON_OBJ_DESCR_PRIM_NAMED(struct updatehub_report,
				  "product-uid", product_uid,
				  JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT_NAMED(struct updatehub_report,
				    "device-identity", device_identity,
				    device_identity_descr),
	JSON_OBJ_DESCR_PRIM_NAMED(struct updatehub_report,
				  "error-message", error_message,
				  JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM_NAMED(struct updatehub_report,
				  "previous-state", previous_state,
				  JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct updatehub_report,
			    version, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct updatehub_report,
			    hardware, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM_NAMED(struct updatehub_report,
				  "package-uid", package_uid,
				  JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct updatehub_report,
			    status, JSON_TOK_STRING),
};

static const struct json_obj_descr send_probe_descr[] =
{
	JSON_OBJ_DESCR_PRIM_NAMED(struct updatehub_probe,
				  "product-uid", product_uid,
				  JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT_NAMED(struct updatehub_probe,
				    "device-identity", device_identity,
				    device_identity_descr),
	JSON_OBJ_DESCR_PRIM(struct updatehub_probe,
			    version, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct updatehub_probe,
			    hardware, JSON_TOK_STRING),
};

/**
 * @}
 */

#endif /* __UPDATEHUB_PRIV_H__ */
