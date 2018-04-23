/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define SYS_LOG_DOMAIN "UpdateHub"
#define SYS_LOG_LEVEL CONFIG_UPDATEHUB_SYS_LOG_LEVEL
#include <logging/sys_log.h>

#include <zephyr.h>

#include <net/net_app.h>
#include <net/net_event.h>
#include <net/net_mgmt.h>
#include <net/http.h>
#include <json.h>
#include <flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>
#include <tinycrypt/sha256.h>

#include <dfu/updatehub.h>
#include "updatehub_internal.h"
#include "device_identity.h"

#define HTTP_NETWORK_TIMEOUT  K_SECONDS(CONFIG_HTTP_CLIENT_NETWORK_TIMEOUT)
#define TCP_RECV_BUFFER_SIZE 2048
#define MAX_URL_SIZE 300
#define SEND_BUFFER_SIZE 430

#define UPDATEHUB_SIGNATURE_SIZE 1024
#define UPDATEHUB_DECODE_BASE64_SIZE 512
#define UPDATEHUB_SHA256_SIZE 32

#define UPDATEHUB_SERVER "10.5.3.14"    /* api.updatehub.io */
#define UPDATEHUB_PORT 8000             /* 80 */

struct updatehub_http_client {
	struct http_ctx http_ctx;
	struct http_request request;
	u8_t tcp_buffer[TCP_RECV_BUFFER_SIZE];
	u8_t url[MAX_URL_SIZE];
	u8_t send_buffer[SEND_BUFFER_SIZE];
	size_t http_content_size;
	size_t downloaded_size;
	int download_status;
};

struct updatehub_context {
	struct flash_img_context flash_img_ctx;
	struct updatehub_http_client http_client;
	struct k_delayed_work work;
	struct k_sem *sem;
};

struct response_metadata {
	char *data;
	size_t len;
};

struct probe_storage {
	char package_uid[65];
	char sha256sum_image[64];
};

static const struct json_obj_descr recv_probe_objects_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct updatehub_probe_recv_objects,
			    mode, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct updatehub_probe_recv_objects,
			    sha256sum, JSON_TOK_STRING),
};

static const struct json_obj_descr recv_probe_objects_descr_array[] =
{
	JSON_OBJ_DESCR_OBJECT(struct updatehub_probe_recv_objects_array,
			      objects, recv_probe_objects_descr),
};

static const struct json_obj_descr recv_probe_sh_string_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct updatehub_probe_recv_metadata_sh_string,
			    product, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM_NAMED(struct updatehub_probe_recv_metadata_sh_string,
				  "supported-hardware", supported_hardware, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_ARRAY(struct updatehub_probe_recv_metadata_sh_string,
				   objects, 2, objects_len, recv_probe_objects_descr_array,
				   ARRAY_SIZE(recv_probe_objects_descr_array)),
};

static const struct json_obj_descr recv_probe_sh_array_descr[] =
{
	JSON_OBJ_DESCR_PRIM(struct updatehub_probe_recv_metadata_sh_array,
			    product, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_NAMED(struct updatehub_probe_recv_metadata_sh_array,
				   "supported-hardware", supported_hardware, 5,
				   supported_hardware_len, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY_ARRAY(struct updatehub_probe_recv_metadata_sh_array,
				   objects, 2, objects_len, recv_probe_objects_descr_array,
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

struct device *flash_dev;
static struct updatehub_context updatehub_context;
struct k_sem updatehub_sem;
struct probe_storage probe_storage;
struct tc_sha256_state_struct sha256sum;


static const char *url(enum updatehub_url url)
{
	switch (url) {
	case UPDATEHUB_PROBE:
		return "upgrades";
	case UPDATEHUB_DOWNLOAD:
		return "products";
	case UPDATEHUB_REPORT:
		return "report";
	default:
		return NULL;
	}
}

static const char *state_execution(enum updatehub_state state)
{
	switch (state) {
	case UPDATEHUB_STATE_EXEC_DOWLOADING:
		return "downloading";
	case UPDATEHUB_STATE_EXEC_DOWNLOADED:
		return "downloaded";
	case UPDATEHUB_STATE_EXEC_INSTALLING:
		return "installing";
	case UPDATEHUB_STATE_EXEC_INSTALLED:
		return "installed";
	case UPDATEHUB_STATE_EXEC_REBOOTING:
		return "rebooting";
	case UPDATEHUB_STATE_EXEC_ERROR:
		return "error";
	default:
		return NULL;
	}
}

static char *updatehub_response(enum updatehub_response response)
{
	switch (response) {
	case UPDATEHUB_NETWORKING_ERROR:
		return "Networking error";
	case UPDATEHUB_SIGNATURE_ERROR:
		return "Check signature error";
	case UPDATEHUB_INCOMPATIBLE_HARDWARE:
		return "Hardware not supported";
	case UPDATEHUB_METADATA_ERROR:
		return "Metadata error";
	case UPDATEHUB_DOWNLOAD_ERROR:
		return "Download image error";
	case UPDATEHUB_INSTALL_ERROR:
		return "Instalation error";
	case UPDATEHUB_FLASH_INIT_ERROR:
		return "Error on flash memory";
	default:
		return NULL;
	}
}

static void work_submit_queue(struct k_delayed_work *work)
{
	k_delayed_work_submit(&updatehub_context.work,
			      K_MINUTES(CONFIG_UPDATEHUB_POLL_INTERVAL));
}

static int init_flash(void)
{
	int ret = 0;

	flash_dev = device_get_binding(FLASH_DEV_NAME);
	ret = boot_erase_img_bank(FLASH_AREA_IMAGE_1_OFFSET);

	return ret;
}

static int init_http_client(struct updatehub_context *ctx)
{
	int ret;

	ret = http_client_init(&ctx->http_client.http_ctx,
			       UPDATEHUB_SERVER,
			       UPDATEHUB_PORT, NULL,
			       HTTP_NETWORK_TIMEOUT);
	if (ret < 0) {
		SYS_LOG_ERR("Failed to init http ctx, err %d", ret);
		return ret;
	}
	return ret;
}

static void metadata_hash_get(struct response_metadata *metadata)
{
	int i;
	char buffer[2];
	unsigned char metadata_hash[UPDATEHUB_SHA256_SIZE];

	memset(metadata_hash, 0, UPDATEHUB_SHA256_SIZE);

	tc_sha256_init(&sha256sum);
	tc_sha256_update(&sha256sum, metadata->data, metadata->len);
	tc_sha256_final(metadata_hash, &sha256sum);

	probe_storage.package_uid[0] = '\0';
	/* Stores the hash on package_uid for sends by server */
	for (i = 0; i < UPDATEHUB_SHA256_SIZE; i++) {
		snprintk(buffer, UPDATEHUB_SHA256_SIZE, "%02x", metadata_hash[i]);
		strcat(&probe_storage.package_uid[i], buffer);
	}
	probe_storage.package_uid[65] = '\0';
}

static char *firmware_version_get(void)
{
	int ret;
	char *buffer;
	struct mcuboot_img_header image;

	buffer = k_malloc(BOOT_IMG_VER_STRLEN_MAX);

	ret = boot_read_bank_header(FLASH_AREA_IMAGE_0_OFFSET, &image, BOOT_IMG_VER_STRLEN_MAX);
	if (ret != 0) {
		return NULL;
	}
	snprintk(buffer, BOOT_IMG_VER_STRLEN_MAX, "%x.%x.%x.%x",
		 image.h.v1.sem_ver.major,
		 image.h.v1.sem_ver.minor,
		 image.h.v1.sem_ver.revision,
		 image.h.v1.sem_ver.build_num);

	return buffer;
}

static int is_compatible_hardware(struct updatehub_probe_recv_metadata_sh_array *metadata_sh_array)
{
	int i;
	int ret = -1;

	for (i = 0; i < metadata_sh_array->supported_hardware_len; i++) {
		if (strcmp(metadata_sh_array->supported_hardware[i], CONFIG_BOARD) == 0) {
			ret = 0;
			break;
		}
	}

	return ret;
}

static void build_http_request(struct updatehub_context *ctx, enum http_method method)
{
	/* Builds http_request Probe, Report and Install Update */
	memset(&ctx->http_client.request, 0, sizeof(ctx->http_client.request));
	ctx->http_client.request.url =  ctx->http_client.url;
	ctx->http_client.request.protocol = " " HTTP_PROTOCOL;
	ctx->http_client.request.header_fields = "Api-Content-Type: application/vnd.updatehub-v1+json\r\nConnection: close\r\n";
	if (method == HTTP_POST) {
		ctx->http_client.request.method = method;
		ctx->http_client.request.content_type_value = "application/json";
		ctx->http_client.request.payload = ctx->http_client.send_buffer;
		ctx->http_client.request.payload_size = strlen(ctx->http_client.send_buffer);
	} else {
		ctx->http_client.request.method = method;
	}
}

static void install_update_cb(struct http_ctx *http,
			      u8_t *data, size_t data_len,
			      size_t buffer_len,
			      enum http_final_call final_data,
			      void *user)
{
	int ret = 0, i;
	char buffer[2];
	u8_t *body_data = NULL;
	u8_t image_hash[UPDATEHUB_SHA256_SIZE];
	size_t body_len = 0;
	char sha256sum_image_dowloaded[65];
	struct updatehub_context *ctx = user;

	if (ctx->http_client.http_content_size == 0) {
		if (http->http.rsp.body_found == 0) {
			ctx->http_client.download_status = -UPDATEHUB_DOWNLOAD_ERROR;
			goto error;
		}
		body_data = http->http.rsp.body_start;
		body_len = buffer_len;
		body_len -= (http->http.rsp.body_start - http->http.rsp.response_buf);
		ctx->http_client.http_content_size = http->http.rsp.content_length;

		SYS_LOG_INF("Image Size: %d", ctx->http_client.http_content_size );
	}

	if (body_data == NULL) {
		body_data = http->http.rsp.response_buf;
		body_len = buffer_len;
	}

	tc_sha256_update(&sha256sum, body_data, body_len);

	ret = flash_img_buffered_write(&ctx->flash_img_ctx,
				       body_data, body_len,
				       final_data == HTTP_DATA_FINAL);
	if (ret < 0) {
		SYS_LOG_ERR("Error to write on the flash %d", ret);
		ctx->http_client.download_status = -UPDATEHUB_INSTALL_ERROR;
		goto error;
	}

	ctx->http_client.downloaded_size = ctx->http_client.downloaded_size
					   + body_len;

	if (final_data == HTTP_DATA_FINAL) {
		ctx->http_client.download_status = 1;

		tc_sha256_final(image_hash, &sha256sum);

		sha256sum_image_dowloaded[0] = '\0';

		/* Stores the hash on ctx->sha256sum_image_dowloaded */
		for (i = 0; i < UPDATEHUB_SHA256_SIZE; i++) {
			snprintk(buffer, UPDATEHUB_SHA256_SIZE, "%02x", image_hash[i]);
			strcat(&sha256sum_image_dowloaded[i], buffer);
		}

		sha256sum_image_dowloaded[65] = '\0';

		/*
		 * Comparison between the sha256sum sent by
		 * the package and the sha256sum of the image
		 */
		if (strcmp(sha256sum_image_dowloaded,
			   probe_storage.sha256sum_image) != 0) {
			SYS_LOG_ERR("SHA256SUM isn't the same:\n"
				    "Image:'%s'\n Received:'%s'",
				    sha256sum_image_dowloaded,
				    probe_storage.sha256sum_image);
			ctx->http_client.download_status = -UPDATEHUB_DOWNLOAD_ERROR;
			goto error;
		}

		k_sem_give(ctx->sem);
	}

	return;

error:
	k_sem_give(ctx->sem);
}

static enum updatehub_response _install_update(struct updatehub_context *ctx)
{
	int ret = 0;
	enum updatehub_response response;

	tc_sha256_init(&sha256sum);

	ret = init_flash();
	if (ret != 0) {
		SYS_LOG_ERR("Failed to init flash and erase second slot %d", ret);
		return UPDATEHUB_FLASH_INIT_ERROR;
	}

	flash_img_init(&ctx->flash_img_ctx, flash_dev);
	memset(ctx->http_client.tcp_buffer, 0, TCP_RECV_BUFFER_SIZE);

	k_sem_init(ctx->sem, 0, 1);

	snprintk(ctx->http_client.url, MAX_URL_SIZE,
		 "http://%s:%d/%s/%s/packages/%s/objects/%s", UPDATEHUB_SERVER,
		 UPDATEHUB_PORT, url(UPDATEHUB_DOWNLOAD),
		 CONFIG_UPDATEHUB_PRODUCT_UID, probe_storage.package_uid,
		 probe_storage.sha256sum_image);

	/* Builds the http_request download*/
	build_http_request(ctx, HTTP_GET);

	ret = init_http_client(ctx);
	if (ret < 0) {
		response = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	ret = http_client_send_req(&ctx->http_client.http_ctx,
				   &ctx->http_client.request,
				   install_update_cb,
				   ctx->http_client.tcp_buffer,
				   TCP_RECV_BUFFER_SIZE, ctx,
				   HTTP_NETWORK_TIMEOUT);
	if (ret < 0 && ret != -EINPROGRESS) {
		SYS_LOG_ERR("Failed to send request install update buffer, err %d", ret);
		response = UPDATEHUB_NETWORKING_ERROR;

		http_release(&ctx->http_client.http_ctx);
		http_close(&ctx->http_client.http_ctx);

		goto cleanup;
	}
	/* Clean up context and close the connection */
	http_release(&ctx->http_client.http_ctx);
	http_close(&ctx->http_client.http_ctx);

	if (ctx->http_client.download_status < 0) {
		if (ctx->http_client.download_status == -UPDATEHUB_DOWNLOAD_ERROR) {
			response = UPDATEHUB_DOWNLOAD_ERROR;
			goto cleanup;
		}
		if (ctx->http_client.download_status == -UPDATEHUB_INSTALL_ERROR) {
			SYS_LOG_ERR("Unable to install process");
			response = UPDATEHUB_INSTALL_ERROR;
			goto cleanup;
		}
	}

	if (ctx->http_client.downloaded_size != ctx->http_client.http_content_size) {
		SYS_LOG_ERR("Downloaded image size mismatch!\n"
			    "Downloaded: %zu\nExpecting: %zu\n",
			    ctx->http_client.downloaded_size,
			    ctx->http_client.http_content_size);
		response = UPDATEHUB_DOWNLOAD_ERROR;
		goto cleanup;
	}

	SYS_LOG_INF("Downloaded bytes %zu", ctx->http_client.downloaded_size);

	response = UPDATEHUB_OK;

/* Resets the variable's control */
cleanup:
	ctx->http_client.downloaded_size = 0;
	ctx->http_client.http_content_size = 0;
	return response;
}

static int query(struct updatehub_context *ctx,
		 struct response_metadata *metadata)
{
	int ret = 0;

	memset(ctx->http_client.tcp_buffer, 0, TCP_RECV_BUFFER_SIZE);

	ret = init_http_client(ctx);
	if (ret < 0) {
		goto cleanup;
	}

	ret = http_client_send_req(&ctx->http_client.http_ctx,
				   &ctx->http_client.request, NULL,
				   ctx->http_client.tcp_buffer,
				   TCP_RECV_BUFFER_SIZE,
				   NULL, HTTP_NETWORK_TIMEOUT);
	if (ret < 0) {
		SYS_LOG_ERR("Failed to send request query buffer, err %d", ret);
		goto cleanup;
	}

	if (ctx->http_client.http_ctx.http.parser.status_code == 404) {
		SYS_LOG_INF("Hardware already updated");
		ret = 1;
		goto cleanup;
	}

	if (ctx->http_client.http_ctx.http.rsp.data_len == 0) {
		SYS_LOG_ERR("No received data: %zu)",
			    ctx->http_client.http_ctx.http.rsp.data_len);
		ret = -1;
		goto cleanup;
	}

	if (metadata) {
		metadata->data = ctx->http_client.http_ctx.http.rsp.body_start;
		metadata->len = strlen(ctx->http_client.http_ctx.http.rsp.response_buf);
		metadata->len -= ctx->http_client.http_ctx.http.rsp.body_start -
				 ctx->http_client.http_ctx.http.rsp.response_buf;
		metadata->data[metadata->len] = '\0';
		SYS_LOG_INF("'%s'", metadata->data);
	}

/* clean up http_context and close the connection */
cleanup:
	http_release(&ctx->http_client.http_ctx);
	http_close(&ctx->http_client.http_ctx);
	return ret;
}

static int report_state(struct updatehub_context *ctx,
			enum updatehub_state execution,
			enum updatehub_response response)
{
	int ret = 0;
	char *device_id = device_identity_get();
	char *firmware_version = firmware_version_get();
	const char *exec = state_execution(execution);

	struct updatehub_report report;

	/* Builds json to send on report */
	memset(&report, 0, sizeof(report));
	report.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	report.device_identity.id = device_id;
	report.version = firmware_version;
	report.hardware = CONFIG_BOARD;
	report.status = exec;
	report.package_uid = probe_storage.package_uid;
	report.previous_state = "";

	switch (response) {
	case UPDATEHUB_INSTALL_ERROR:
		report.previous_state = state_execution(UPDATEHUB_STATE_EXEC_INSTALLING);
	case UPDATEHUB_DOWNLOAD_ERROR:
		report.previous_state = state_execution(UPDATEHUB_STATE_EXEC_DOWLOADING);
	default:
		NULL;
	}

	if (strcmp(report.previous_state, "") != 0) {
		report.error_message = updatehub_response(response);
	} else {
		report.error_message = "";
	}

	ret = json_obj_encode_buf(send_report_descr,
				  ARRAY_SIZE(send_report_descr),
				  &report,
				  ctx->http_client.send_buffer,
				  SEND_BUFFER_SIZE - 1);
	if (ret < 0) {
		SYS_LOG_ERR("Can't encode metadata to send on report %d", ret);
		goto error;
	}

	/* Builds report url */
	snprintk(ctx->http_client.url, MAX_URL_SIZE,
		 "http://%s:%d/%s", UPDATEHUB_SERVER,
		 UPDATEHUB_PORT, url(UPDATEHUB_REPORT));

	build_http_request(ctx, HTTP_POST);

	ret = query(ctx, NULL);

error:
	k_free(device_id);
	k_free(firmware_version);
	return ret;
}

static enum updatehub_response probe(struct updatehub_context *ctx,
				     struct updatehub_probe_recv_metadata_sh_array *metadata_sh_array,
				     struct updatehub_probe_recv_metadata_sh_string *metadata_sh_string)
{
	int ret = 0;
	enum updatehub_response response;
	char *cpy_metadata_buffer = k_malloc(SEND_BUFFER_SIZE);
	char *device_id = device_identity_get();
	char *firmware_version = firmware_version_get();

	struct updatehub_probe probe_send;
	struct response_metadata metadata = { NULL, 0 };

	/* Builds jsons to send on probe */
	memset(&probe_send, 0, sizeof(probe_send));
	probe_send.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	probe_send.device_identity.id = device_id;
	probe_send.version = firmware_version;
	probe_send.hardware = CONFIG_BOARD;

	ret = json_obj_encode_buf(send_probe_descr,
				  ARRAY_SIZE(send_probe_descr),
				  &probe_send,
				  ctx->http_client.send_buffer,
				  SEND_BUFFER_SIZE - 1);
	if (ret < 0) {
		SYS_LOG_ERR("Can't encode metadata to send on probe %d", ret);
		response = UPDATEHUB_METADATA_ERROR;
		goto cleanup;
	}

	/* Builds probe url */
	snprintk(ctx->http_client.url, MAX_URL_SIZE,
		 "http://%s:%d/%s",
		 UPDATEHUB_SERVER, UPDATEHUB_PORT,
		 url(UPDATEHUB_PROBE));

	build_http_request(ctx, HTTP_POST);

	ret = query(ctx, &metadata);
	if (ret < 0) {
		response = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}
	if (ret > 0) {
		response = UPDATEHUB_NO_UPDATE;
		goto cleanup;
	}

	strncpy(cpy_metadata_buffer, metadata.data, metadata.len);

	metadata_hash_get(&metadata);

	ret = json_obj_parse(metadata.data, metadata.len,
			     recv_probe_sh_array_descr,
			     sizeof(recv_probe_sh_array_descr),
			     metadata_sh_array);
	if (ret < 0) {
		ret = json_obj_parse(cpy_metadata_buffer, strlen(cpy_metadata_buffer),
				     recv_probe_sh_string_descr,
				     sizeof(recv_probe_sh_string_descr),
				     metadata_sh_string);
		if (ret < 0) {
			SYS_LOG_ERR("JSON parse error %d", ret);
			response = UPDATEHUB_METADATA_ERROR;
			goto cleanup;
		}

		memcpy(probe_storage.sha256sum_image, metadata_sh_string->objects[0].objects.sha256sum,
		       strlen(metadata_sh_string->objects[0].objects.sha256sum));

	} else {

		ret = is_compatible_hardware(metadata_sh_array);
		if (ret < 0) {
			SYS_LOG_ERR("Error this hardware don't support the update");
			response = UPDATEHUB_INCOMPATIBLE_HARDWARE;
			goto cleanup;
		}

		memcpy(probe_storage.sha256sum_image, metadata_sh_array->objects[0].objects.sha256sum,
		       strlen(metadata_sh_array->objects[0].objects.sha256sum));
	}

	response = UPDATEHUB_OK;

cleanup:
	k_free(device_id);
	k_free(firmware_version);
	k_free(cpy_metadata_buffer);
	return response;
}

static void _run(struct updatehub_context *ctx)
{
	int ret = 0;
	enum updatehub_response response;
	struct updatehub_probe_recv_metadata_sh_array metadata_sh_array;
	struct updatehub_probe_recv_metadata_sh_string metadata_sh_string;

	response = probe(ctx, &metadata_sh_array, &metadata_sh_string);
	if (response != UPDATEHUB_OK) {
		goto error;
	}
	if (response == UPDATEHUB_NO_UPDATE) {
		SYS_LOG_DBG("Hardware already updated");
		goto updated;
	}

	report_state(ctx, UPDATEHUB_STATE_EXEC_DOWLOADING, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting downloading state");
		goto error;
	}

	report_state(ctx, UPDATEHUB_STATE_EXEC_INSTALLING, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting installing state");
		goto error;
	}

	response = _install_update(ctx);
	if (response != UPDATEHUB_OK) {
		goto error;
	}

	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_DOWNLOADED, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting downloaded state");
		goto error;
	}

	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_INSTALLED, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting installed state");
		goto error;
	}

	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_REBOOTING, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting rebooting state");
		goto error;
	}

	SYS_LOG_INF("Image flashed successfuly, rebooting now\n");

	sys_reboot(0);

error:
	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_ERROR, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting error state");
	}

updated:
	return;
}

static void worker(struct k_delayed_work *work)
{
	struct updatehub_context *ctx = CONTAINER_OF(work, struct updatehub_context, work);

	_run(ctx);

	work_submit_queue(&updatehub_context.work);
}

void updatehub_start()
{
/* initialization the device identity,
 * updatehub context, worker and semaphore.
 */
	device_identity_init(flash_dev);

	k_sem_init(&updatehub_sem, 0, 1);

	memset(&probe_storage, 0, sizeof(probe_storage));
	memset(&updatehub_context, 0, sizeof(updatehub_context));

	k_delayed_work_init(&updatehub_context.work, worker);
	work_submit_queue(&updatehub_context.work);

	updatehub_context.sem = &updatehub_sem;
}

enum updatehub_response updatehub_probe()
{
	enum updatehub_response response = UPDATEHUB_OK;
	struct updatehub_context *ctx;
	struct updatehub_probe_recv_metadata_sh_array metadata_sh_array;
	struct updatehub_probe_recv_metadata_sh_string metadata_sh_string;

	device_identity_init(flash_dev);

	memset(&probe_storage, 0, sizeof(probe_storage));
	memset(&updatehub_context, 0, sizeof(updatehub_context));
	k_sem_init(&updatehub_sem, 0, 1);
	updatehub_context.sem = &updatehub_sem;

	ctx = &updatehub_context;

	response = probe(ctx, &metadata_sh_array, &metadata_sh_string);
	if (response != UPDATEHUB_OK && response != UPDATEHUB_NO_UPDATE) {
		SYS_LOG_ERR("ERROR");
		return response;
	}

	return response;
}

enum updatehub_response updatehub_update()
{
	int ret = 0;
	struct updatehub_context *ctx;
	enum updatehub_response response = UPDATEHUB_OK;

	memset(&updatehub_context, 0, sizeof(updatehub_context));
	k_sem_init(&updatehub_sem, 0, 1);
	updatehub_context.sem = &updatehub_sem;

	ctx = &updatehub_context;

	report_state(ctx, UPDATEHUB_STATE_EXEC_DOWLOADING, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting downloading state");
		goto error;
	}

	report_state(ctx, UPDATEHUB_STATE_EXEC_INSTALLING, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting installing state");
		goto error;
	}

	response = _install_update(ctx);
	if (response != UPDATEHUB_OK) {
		goto error;
	}
	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_DOWNLOADED, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting downloaded state");
		goto error;
	}

	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_INSTALLED, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting installed state");
		goto error;
	}

	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_REBOOTING, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting rebooting state");

		goto error;
	}

	SYS_LOG_INF("Image flashed successfuly, rebooting now\n");

	sys_reboot(0);

	return response;

error:
	ret = report_state(ctx, UPDATEHUB_STATE_EXEC_ERROR, response);
	if (ret < 0) {
		SYS_LOG_ERR("Can't reporting error state");
	}
	return response;
}
