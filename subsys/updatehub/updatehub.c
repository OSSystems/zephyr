/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>

#include <logging/log.h>

#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_mgmt.h>
#include <net/net_ip.h>
#include <net/udp.h>
#include <net/coap.h>
#include <misc/printk.h>
#include <json.h>
#include <flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>
#include <tinycrypt/sha256.h>

#include <updatehub.h>
#include "updatehub_priv.h"
#include "device_identity.h"

#define LOG_LEVEL CONFIG_UPDATEHUB_LOG_LEVEL
LOG_MODULE_REGISTER(UpdateHub);

#define NETWORK_TIMEOUT K_SECONDS(10)
#define MAX_PATH_SIZE 255
#define MAX_PAYLOAD_SIZE 430
#define SHA256SUM_STRING_SIZE 65
#define MAX_FRAG_SIZE 129
#define COAP_MAX_RETRY 3

#define API_UPDATEHUB "10.5.3.234" /* TODO: replace by the right URL */
#define API_DOWNLOAD_UPDATEHUB ""

struct updatehub_coap {
	struct net_context *net_ctx;
	struct coap_block_context block;
	enum updatehub_response code_status;
	u8_t uri_path[MAX_PATH_SIZE];
	u8_t payload[MAX_PAYLOAD_SIZE];
	int downloaded_size;
};

struct probe_storage {
	char package_uid[SHA256SUM_STRING_SIZE];
	char sha256sum_image[SHA256SUM_STRING_SIZE];
	int image_size;
	bool confirmed_image;
};

struct updatehub_coap coap;
struct k_sem updatehub_sem;
static struct probe_storage probe_storage;
struct device *flash_dev;
struct flash_img_context flash_img_ctx;
struct tc_sha256_state_struct sha256sum;

static struct sockaddr_in peer_api_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(5683)
};

static struct sockaddr_in peer_download_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(5683)
};

static const char *uri_path(enum updatehub_uri_path type)
{
	switch (type) {
	case UPDATEHUB_PROBE:
		return "upgrades";
	case UPDATEHUB_REPORT:
		return "report";
	case UPDATEHUB_DOWNLOAD:
		return "products";
	default:
		return NULL;
	}
}

static const char *state_execution(enum updatehub_state state)
{
	switch (state) {
	case UPDATEHUB_STATE_DOWNLOADING:
		return "downloading";
	case UPDATEHUB_STATE_DOWNLOADED:
		return "downloaded";
	case UPDATEHUB_STATE_INSTALLING:
		return "installing";
	case UPDATEHUB_STATE_INSTALLED:
		return "installed";
	case UPDATEHUB_STATE_REBOOTING:
		return "rebooting";
	case UPDATEHUB_STATE_ERROR:
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
	case UPDATEHUB_INCOMPATIBLE_HARDWARE:
		return "Hardware incompatible";
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
	if (probe_storage.confirmed_image == false) {
		k_delayed_work_submit(work,
				      K_SECONDS(1));
	} else {
		k_delayed_work_submit(work,
				      K_MINUTES(CONFIG_UPDATEHUB_POLL_INTERVAL));
	}
}

static int metadata_hash_get(char *metadata)
{
	int ret = 0, i;
	char buffer[2];
	unsigned char metadata_hash[TC_SHA256_DIGEST_SIZE];

	ret = tc_sha256_init(&sha256sum);
	if (ret == 0) {
		LOG_ERR("Could not start sha256sum");
		goto error;
	}

	ret = tc_sha256_update(&sha256sum, metadata, strlen(metadata));
	if (ret == 0) {
		LOG_ERR("Could not update sha256sum");
		goto error;
	}

	ret = tc_sha256_final(metadata_hash, &sha256sum);
	if (ret == 0) {
		LOG_ERR("Could not finish sha256sum");
		goto error;
	}

	memset(probe_storage.package_uid, 0, SHA256SUM_STRING_SIZE);
	for (i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
		snprintk(buffer, TC_SHA256_DIGEST_SIZE, "%02x", metadata_hash[i]);
		strcat(&probe_storage.package_uid[i], buffer);
	}

error:
	return ret;
}

static int firmware_version_get(char *firmware_version)
{
	int ret = -1;
	struct mcuboot_img_header image_header;

	ret = boot_read_bank_header(FLASH_AREA_IMAGE_0_OFFSET,
				    &image_header, BOOT_IMG_VER_STRLEN_MAX);
	if (ret != 0) {
		LOG_ERR("Could not read the bank header");
		return ret;
	}

	snprintk(firmware_version,
		 BOOT_IMG_VER_STRLEN_MAX,
		 "%d.%d.%d.%d",
		 image_header.h.v1.sem_ver.major,
		 image_header.h.v1.sem_ver.minor,
		 image_header.h.v1.sem_ver.revision,
		 image_header.h.v1.sem_ver.build_num);

	return ret;
}

static int is_compatible_hardware(struct
				  resp_probe_some_boards *metadata_some_boards)
{
	int i;
	int ret = -1;

	for (i = 0; i < metadata_some_boards->supported_hardware_len; i++) {
		if (strcmp(metadata_some_boards->supported_hardware[i],
			   CONFIG_BOARD) == 0) {
			ret = 0;
			break;
		}
	}

	return ret;
}

static void install_update_cb(struct net_context *ctx,
			      struct net_pkt *pkt,
			      int status, void *user)
{
	int ret = -1;
	int i;
	struct coap_packet response_packet;
	struct net_buf *frag;
	u16_t offset_data;
	u16_t len;

	ret = coap_packet_parse(&response_packet, pkt, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	frag = coap_packet_get_payload(&response_packet,
				       &offset_data, &len);
	if ((!frag && len == 0xffff) || len == 0) {
		LOG_ERR("Invalid payload");
		coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		ret = -1;
		goto end;
	}

	while (frag) {
		coap.downloaded_size = coap.downloaded_size +
				       (frag->len - offset_data);

		ret = tc_sha256_update(&sha256sum, frag->data +
				       offset_data,
				       frag->len - offset_data);
		if (ret < 1) {
			LOG_ERR("Could not update sha256sum");
			coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}

		ret = flash_img_buffered_write(&flash_img_ctx,
					       frag->data + offset_data,
					       frag->len - offset_data,
					       coap.downloaded_size == coap.block.total_size);
		if (ret < 0) {
			LOG_ERR("Error to write on the flash");
			coap.code_status = UPDATEHUB_INSTALL_ERROR;
			goto end;
		}

		offset_data = 0;
		frag = frag->frags;
	}

	if (coap_next_block(&response_packet, &coap.block) == 0) {
		LOG_ERR("Could not get the next");
		coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (coap.downloaded_size == coap.block.total_size) {
		char buffer[2];
		char sha256sum_image_dowloaded[SHA256SUM_STRING_SIZE];
		uint8_t image_hash[TC_SHA256_DIGEST_SIZE];

		ret = tc_sha256_final(image_hash, &sha256sum);
		if (ret < 1) {
			LOG_ERR("Could not finish sha256sum");
			coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}

		memset(&sha256sum_image_dowloaded, 0, SHA256SUM_STRING_SIZE);
		for (i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
			snprintk(buffer, TC_SHA256_DIGEST_SIZE, "%02x", image_hash[i]);
			strcat(&sha256sum_image_dowloaded[i], buffer);
		}

		if (strcmp(sha256sum_image_dowloaded,
			   probe_storage.sha256sum_image) != 0) {
			LOG_ERR("SHA256SUM image is not the same");
			LOG_INF("Downloaded Image:'%s'"
				"Image:'%s'",
				log_strdup(sha256sum_image_dowloaded),
				log_strdup(probe_storage.sha256sum_image));
			coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}
	}

	coap.code_status = UPDATEHUB_OK;

end:
	net_pkt_unref(pkt);
	k_sem_give(&updatehub_sem);
}

void probe_cb(struct net_context *ctx, struct net_pkt *pkt,
	      int status, void *metadata)
{
	int ret = -1;
	struct coap_packet response_packet;
	struct net_buf *frag;
	u16_t offset_data;
	u16_t len;

	char frag_buffer[MAX_FRAG_SIZE];
	char *metadata_buffer = metadata;

	ret = coap_packet_parse(&response_packet, pkt, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (COAP_RESPONSE_CODE_NOT_FOUND ==
	    coap_header_get_code(&response_packet)) {
		LOG_INF("No update avaiable");
		coap.code_status = UPDATEHUB_NO_UPDATE;
		ret = -1;
		goto end;
	}

	frag = coap_packet_get_payload(&response_packet,
				       &offset_data, &len);
	if ((!frag && len == 0xffff) || len == 0) {
		LOG_ERR("Invalid payload");
		coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		ret = -1;
		goto end;
	}

	while (frag) {
		memset(&frag_buffer, 0, MAX_FRAG_SIZE);
		memcpy(&frag_buffer, frag->data + offset_data,
		       frag->len - offset_data);
		offset_data = 0;
		frag = frag->frags;
		strcat(metadata_buffer, frag_buffer);
	}

	LOG_INF("Metadata received '%s'", log_strdup(metadata_buffer));

	coap.code_status = UPDATEHUB_OK;

end:
	net_pkt_unref(pkt);
	k_sem_give(&updatehub_sem);
}

static int connect(struct sockaddr_in server_addr, char *server)
{
	int ret = -1;

	ret = net_addr_pton(AF_INET, server, &server_addr.sin_addr);
	if (ret < 0) {
		LOG_ERR("Invalid peer IPv4 address");
		goto error;
	}

	ret = net_context_get(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &coap.net_ctx);
	if (ret < 0) {
		LOG_ERR("Could not get an UDP context");
		goto error;
	}

	ret = net_context_connect(coap.net_ctx,
				  (struct sockaddr *)&server_addr,
				  sizeof(server_addr), NULL, K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Could not connect to UpdateHub server");
		goto error;
	}

error:
	return ret;
}

static int send_request(enum coap_msgtype msgtype,
			enum coap_method method,
			enum updatehub_uri_path type)
{
	int ret = -1;
	struct coap_packet request_packet;
	struct net_pkt *pkt;
	struct net_buf *frag;
	u8_t *api_header = "Api-Content-Type: application/vnd.updatehub-v1+json";

	pkt = net_pkt_get_tx(coap.net_ctx, K_FOREVER);
	frag = net_pkt_get_data(coap.net_ctx, K_FOREVER);
	net_pkt_frag_add(pkt, frag);

	ret = coap_packet_init(&request_packet, pkt, 1,
			       msgtype, 8, coap_next_token(),
			       method, coap_next_id());
	if (ret < 0) {
		LOG_ERR("Could not init packet");
		goto error;
	}

	switch (method) {
	case COAP_METHOD_GET:
		snprintk(coap.uri_path, MAX_PATH_SIZE,
			 "%s/%s/packages/%s/objects/%s", uri_path(type),
			 CONFIG_UPDATEHUB_PRODUCT_UID, probe_storage.package_uid,
			 probe_storage.sha256sum_image);

		ret = coap_packet_append_option(&request_packet,
						COAP_OPTION_URI_PATH,
						coap.uri_path, strlen(coap.uri_path));
		if (ret < 0) {
			LOG_ERR("Unable add option to request path");
			goto error;
		}

		ret = coap_append_block2_option(&request_packet, &coap.block);
		if (ret < 0) {
			LOG_ERR("Unable coap append block2");
			goto error;
		}

		ret = coap_packet_append_option(&request_packet, 2048,
						api_header, strlen(api_header));
		if (ret < 0) {
			LOG_ERR("Unable add option to add updatehub header");
			goto error;
		}
		break;

	case COAP_METHOD_POST:
		ret = coap_packet_append_option(&request_packet,
						COAP_OPTION_URI_PATH,
						uri_path(type), strlen(uri_path(type)));
		if (ret < 0) {
			LOG_ERR("Unable add option to request path");
			goto error;
		}

		uint8_t content_json_format = 50;

		ret = coap_packet_append_option(&request_packet,
						COAP_OPTION_CONTENT_FORMAT,
						&content_json_format,
						sizeof(content_json_format));
		if (ret < 0) {
			LOG_ERR("Unable add option to request format");
			goto error;
		}

		ret = coap_packet_append_option(&request_packet, 2048,
						api_header, strlen(api_header));
		if (ret < 0) {
			LOG_ERR("Unable add option to add updatehub header");
			goto error;
		}

		ret = coap_packet_append_payload_marker(&request_packet);
		if (ret < 0) {
			LOG_ERR("Unable to append payload marker");
			goto error;
		}

		ret = coap_packet_append_payload(&request_packet, &coap.payload,
						 strlen(coap.payload));
		if (ret < 0) {
			LOG_ERR("Not able to append payload");
			goto error;
		}
		break;

	default:
		LOG_ERR("Invalid method");
		ret = -1;
		goto error;
	}

	ret = net_context_send(pkt, NULL, K_NO_WAIT, NULL, NULL);
	if (ret < 0) {
		LOG_ERR("Error sending the packet");
	}

error:
	return ret;
}

static enum updatehub_response install_update()
{
	int ret = -1;
	int verification_download = 0;
	int attempts_download = 0;

	coap.downloaded_size = 0;

	flash_dev = device_get_binding(FLASH_DEV_NAME);

	ret = boot_erase_img_bank(FLASH_AREA_IMAGE_1_OFFSET);
	if (ret != 0) {
		LOG_ERR("Failed to init flash and erase second slot");
		coap.code_status = UPDATEHUB_FLASH_INIT_ERROR;
		goto error;
	}

	ret = tc_sha256_init(&sha256sum);
	if (ret < 1) {
		LOG_ERR("Could not start sha256sum");
		coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto error;
	}

	ret = connect(peer_download_addr, API_UPDATEHUB);
	if (ret < 0) {
		coap.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	ret = net_context_recv(coap.net_ctx, install_update_cb,
			       K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Could not set receive callback");
		coap.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	ret = coap_block_transfer_init(&coap.block,
				       COAP_BLOCK_1024,
				       probe_storage.image_size);
	if (ret < 0) {
		LOG_ERR("Unable init block transfer");
		coap.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	flash_img_init(&flash_img_ctx, flash_dev);

	while (coap.downloaded_size != coap.block.total_size) {
		k_sem_init(&updatehub_sem, 0, 1);

		verification_download = coap.downloaded_size;

		ret = send_request(COAP_TYPE_CON, COAP_METHOD_GET,
				   UPDATEHUB_DOWNLOAD);
		if (ret < 0) {
			coap.code_status = UPDATEHUB_NETWORKING_ERROR;
			goto cleanup;
		}

		k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

		if (coap.code_status != UPDATEHUB_OK) {
			goto cleanup;
		}

		if (verification_download == coap.downloaded_size) {
			if (attempts_download == COAP_MAX_RETRY) {
				LOG_ERR("Could not get the packet");
				coap.code_status = UPDATEHUB_DOWNLOAD_ERROR;
				goto cleanup;
			}
			attempts_download++;
		}
	}

cleanup:
	ret = net_context_put(coap.net_ctx);
	if (ret < 0) {
		LOG_ERR("Error to close the networking");
	}

error:
	memset(&probe_storage, 0, sizeof(probe_storage));
	coap.downloaded_size = 0;
	return coap.code_status;
}

static int report(enum updatehub_state execution,
		  enum updatehub_response response)
{
	int ret = -1;
	char *device_id = device_identity_get();
	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];
	const char *exec = state_execution(execution);
	struct updatehub_report report;

	ret = firmware_version_get(firmware_version);
	if (ret < 0) {
		goto error;
	}

	memset(&report, 0, sizeof(report));
	report.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	report.device_identity.id = device_id;
	report.version = firmware_version;
	report.hardware = CONFIG_BOARD;
	report.status = exec;
	report.package_uid = probe_storage.package_uid;

	switch (response) {
	case UPDATEHUB_INSTALL_ERROR:
		report.previous_state =
			state_execution(UPDATEHUB_STATE_INSTALLING);
		break;
	case UPDATEHUB_DOWNLOAD_ERROR:
		report.previous_state =
			state_execution(UPDATEHUB_STATE_DOWNLOADING);
		break;
	default:
		report.previous_state = "";
	}

	if (strcmp(report.previous_state, "") != 0) {
		report.error_message = updatehub_response(response);
	} else {
		report.error_message = "";
	}

	memset(&coap.payload, 0, MAX_PAYLOAD_SIZE);
	ret = json_obj_encode_buf(send_report_descr,
				  ARRAY_SIZE(send_report_descr),
				  &report, coap.payload,
				  MAX_PAYLOAD_SIZE - 1);
	if (ret < 0) {
		LOG_ERR("Could not encode metadata");
		goto error;
	}

	ret = connect(peer_api_addr, API_UPDATEHUB);
	if (ret < 0) {
		goto error;
	}

	ret = send_request(COAP_TYPE_NON_CON, COAP_METHOD_POST,
			   UPDATEHUB_REPORT);
	if (ret < 0) {
		LOG_ERR("Error to send %s report", state_execution(execution));
	}

	k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

	ret = net_context_put(coap.net_ctx);
	if (ret < 0) {
		LOG_ERR("Error to close the networking");
	}
error:
	k_free(device_id);
	return ret;
}

static enum updatehub_response probe()
{
	int ret = -1;
	struct resp_probe_some_boards metadata_some_boards;
	struct resp_probe_any_boards metadata_any_boards;
	struct updatehub_probe probe_send;
	char *device_id = device_identity_get();
	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];
	char *metadata = k_malloc(MAX_PAYLOAD_SIZE);
	char *metadata_copy = k_malloc(MAX_PAYLOAD_SIZE);

	probe_storage.confirmed_image = boot_is_img_confirmed();
	if (probe_storage.confirmed_image == false) {
		LOG_ERR("The current image is not confirmed");
		coap.code_status = UPDATEHUB_UNCONFIRMED_IMAGE;
		goto error;
	}

	ret = firmware_version_get(firmware_version);
	if (ret < 0) {
		coap.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	memset(&probe_send, 0, sizeof(probe_send));
	probe_send.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	probe_send.device_identity.id = device_id;
	probe_send.version = firmware_version;
	probe_send.hardware = CONFIG_BOARD;

	memset(&coap.payload, 0, MAX_PAYLOAD_SIZE);
	ret = json_obj_encode_buf(send_probe_descr,
				  ARRAY_SIZE(send_probe_descr),
				  &probe_send, coap.payload,
				  MAX_PAYLOAD_SIZE - 1);
	if (ret < 0) {
		LOG_ERR("Could not encode metadata");
		coap.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	ret = connect(peer_api_addr, API_UPDATEHUB);
	if (ret < 0) {
		coap.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	memset(metadata, 0, MAX_PAYLOAD_SIZE);
	ret = net_context_recv(coap.net_ctx, probe_cb,
			       K_NO_WAIT, metadata);
	if (ret < 0) {
		LOG_ERR("Could not set receive callback");
		coap.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	k_sem_init(&updatehub_sem, 0, 1);

	ret = send_request(COAP_TYPE_CON, COAP_METHOD_POST,
			   UPDATEHUB_PROBE);
	if (ret < 0) {
		coap.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

	if (coap.code_status != UPDATEHUB_OK) {
		goto cleanup;
	}

	ret = metadata_hash_get(metadata);
	if (ret == 0) {
		coap.code_status = UPDATEHUB_METADATA_ERROR;
		goto cleanup;
	}

	memcpy(metadata_copy, metadata, strlen(metadata));
	ret = json_obj_parse(metadata, strlen(metadata),
			     recv_probe_sh_array_descr,
			     sizeof(recv_probe_sh_array_descr),
			     &metadata_some_boards);
	if (ret < 0) {
		ret = json_obj_parse(metadata_copy, strlen(metadata_copy),
				     recv_probe_sh_string_descr,
				     sizeof(recv_probe_sh_string_descr),
				     &metadata_any_boards);
		if (ret < 0) {
			LOG_ERR("Could not parse json");
			coap.code_status = UPDATEHUB_METADATA_ERROR;
			goto cleanup;
		}

		memcpy(probe_storage.sha256sum_image,
		       metadata_any_boards.objects[1].objects.sha256sum,
		       strlen(metadata_any_boards.objects[1].objects.sha256sum));
		probe_storage.image_size =
			metadata_any_boards.objects[1].objects.size;
	} else {
		ret = is_compatible_hardware(&metadata_some_boards);
		if (ret < 0) {
			LOG_ERR("Incompatible hardware");
			coap.code_status = UPDATEHUB_INCOMPATIBLE_HARDWARE;
			goto cleanup;
		}

		memcpy(probe_storage.sha256sum_image,
		       metadata_some_boards.objects[1].objects.sha256sum,
		       strlen(metadata_some_boards.objects[1].objects.sha256sum));
		probe_storage.image_size =
			metadata_some_boards.objects[1].objects.size;
	}

	coap.code_status = UPDATEHUB_HAS_UPDATE;

cleanup:
	ret = net_context_put(coap.net_ctx);
	if (ret < 0) {
		LOG_ERR("Error to close the networking");
	}
error:
	k_free(metadata);
	k_free(metadata_copy);
	k_free(device_id);
	return coap.code_status;
}

void run(struct k_delayed_work *work)
{
	int ret = -1;
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	memset(&probe_storage, 0, sizeof(probe_storage));

	response = probe();
	if (response == UPDATEHUB_NO_UPDATE ||
	    response == UPDATEHUB_UNCONFIRMED_IMAGE) {
		goto submit_queue;
	}
	if (response != UPDATEHUB_HAS_UPDATE) {
		goto error;
	}

	ret = report(UPDATEHUB_STATE_DOWNLOADING, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting downloading state");
		goto error;
	}

	ret = report(UPDATEHUB_STATE_INSTALLING, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting installing state");
		goto error;
	}

	response = install_update();
	if (response != UPDATEHUB_OK) {
		goto error;
	}

	ret = report(UPDATEHUB_STATE_DOWNLOADED, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting downloaded state");
		goto error;
	}

	ret = report(UPDATEHUB_STATE_INSTALLED, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting installed state");
		goto error;
	}

	ret = report(UPDATEHUB_STATE_REBOOTING, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting rebooting state");
		goto error;
	}

	LOG_INF("Image flashed successfuly, rebooting now");

	sys_reboot(0);

error:
	ret = report(UPDATEHUB_STATE_ERROR, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting error state");
	}

submit_queue:
	work_submit_queue(work);
}

void updatehub_autohandler()
{
	static struct k_delayed_work work;

	device_identity_init(flash_dev);

	k_sem_init(&updatehub_sem, 0, 1);

	k_delayed_work_init(&work, run);

	work_submit_queue(&work);
}

enum updatehub_response updatehub_probe()
{
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	device_identity_init(flash_dev);

	memset(&probe_storage, 0, sizeof(probe_storage));

	response = probe();

	return response;
}

enum updatehub_response updatehub_update()
{
	int ret = -1;
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	ret = report(UPDATEHUB_STATE_DOWNLOADING, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting downloading state");
		goto error;
	}

	ret = report(UPDATEHUB_STATE_INSTALLING, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting installing state");
		goto error;
	}

	response = install_update();
	if (response != UPDATEHUB_OK) {
		goto error;
	}

	ret = report(UPDATEHUB_STATE_DOWNLOADED, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting downloaded state");
		goto error;
	}

	ret = report(UPDATEHUB_STATE_INSTALLED, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting installed state");
		goto error;
	}

	ret = report(UPDATEHUB_STATE_REBOOTING, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting rebooting state");

		goto error;
	}

	LOG_INF("Image flashed successfuly, rebooting now");

	sys_reboot(0);

error:
	ret = report(UPDATEHUB_STATE_ERROR, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting error state");
	}
	return response;
}
