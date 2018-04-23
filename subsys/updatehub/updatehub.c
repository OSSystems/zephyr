/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr.h>

#include <logging/log.h>
#include <net/udp.h>
#include <net/coap.h>
#include <net/dns_resolve.h>
#include <flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>
#include <tinycrypt/sha256.h>
#include <nvs/nvs.h>
#include <shell/shell.h>
#include <json.h>

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
#define ADDRESS_ID 1
#define MAX_IP_SIZE 30

static struct updatehub_context {
	struct net_context *net_ctx;
	struct coap_block_context block;
	enum updatehub_response code_status;
	u8_t uri_path[MAX_PATH_SIZE];
	u8_t payload[MAX_PAYLOAD_SIZE];
	int downloaded_size;
	char *overwrite_ip;
} upadatehub_ctx;

static struct probe_info {
	char package_uid[SHA256SUM_STRING_SIZE];
	char sha256sum_image[SHA256SUM_STRING_SIZE];
	int image_size;
} _probe;

struct k_sem updatehub_sem;
struct device *flash_dev;
struct flash_img_context flash_ctx;
struct tc_sha256_state_struct sha256sum;

static struct sockaddr_in peer_updatehub_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(5683)
};

/* TODO: Set the right port of download server */
static struct sockaddr_in peer_download_addr = {
	.sin_family = AF_INET,
	.sin_port = htons(5683)
};

static struct nvs_fs fs = {
	.sector_size = 64,
	.sector_count = 3,
	.offset = FLASH_AREA_STORAGE_OFFSET,
};

static char *updatehub_response(enum updatehub_response response)
{
	switch (response) {
	case UPDATEHUB_NETWORKING_ERROR:
		return "Fail to connect to the UpdateHub server";
	case UPDATEHUB_INCOMPATIBLE_HARDWARE:
		return "Incompatible hardware";
	case UPDATEHUB_METADATA_ERROR:
		return "Fail to parse or to encode the metadata";
	case UPDATEHUB_DOWNLOAD_ERROR:
		return "Fail while downloading the update package";
	case UPDATEHUB_INSTALL_ERROR:
		return "Fail while installing the update package";
	case UPDATEHUB_FLASH_INIT_ERROR:
		return "Fail to initilialize the flash";
	case UPDATEHUB_NO_UPDATE:
		return "No update available";
	default:
		return NULL;
	}
}

#if defined (CONFIG_UPDATEHUB_LOG)
static void wait_on_log_flushed(void)
{
	while (log_buffered_cnt()) {
		k_sleep(5);
	}
}
#endif

static void work_submit_queue(struct k_delayed_work *work)
{
	if (!boot_is_img_confirmed()) {
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

	unsigned char metadata_hash[TC_SHA256_DIGEST_SIZE];

	ret = tc_sha256_final(metadata_hash, &sha256sum);
	if (ret == 0) {
		LOG_ERR("Could not finish sha256sum");
		goto error;
	}

	char buffer[2];

	memset(_probe.package_uid, 0, SHA256SUM_STRING_SIZE);
	for (i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
		snprintk(buffer, TC_SHA256_DIGEST_SIZE, "%02x", metadata_hash[i]);
		strcat(&_probe.package_uid[i], buffer);
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

static int
is_compatible_hardware(struct resp_probe_some_boards *metadata_some_boards)
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

static void dns_cb(enum dns_resolve_status status,
	    struct dns_addrinfo *info,
	    void *user_ip)
{
	switch (status) {
	case DNS_EAI_CANCELED:
		LOG_ERR("DNS query was canceled");
		goto error;
	case DNS_EAI_FAIL:
		LOG_ERR("DNS resolve failed");
		goto error;
	case DNS_EAI_NODATA:
		LOG_ERR("Cannot resolve address");
		goto error;
	case DNS_EAI_ALLDONE:
		break;
	case DNS_EAI_INPROGRESS:
		break;
	default:
		LOG_ERR("DNS resolving error (%d)", status);
		goto error;
	}

	if (!info) {
		goto error;
	}

	char hr_addr[NET_IPV6_ADDR_LEN];
	char *hr_family;
	void *addr;
	char *buffer;
	char *ip = user_ip;

	if (info->ai_family == AF_INET) {
		hr_family = "IPv4";
		addr = &net_sin(&info->ai_addr)->sin_addr;
	} else {
		LOG_ERR("Invalid IP address family %d", info->ai_family);
		goto error;
	}

	buffer = net_addr_ntop(info->ai_family, addr,
			       hr_addr, sizeof(hr_addr));
	memcpy(ip, buffer, strlen(buffer));

error:
	k_sem_give(&updatehub_sem);
}

static int connect(struct sockaddr_in server_addr, char *updatehub_server)
{
	int ret = -1;
	char *query = updatehub_server;

	if (upadatehub_ctx.overwrite_ip) {
		query = upadatehub_ctx.overwrite_ip;
	}

	/* Starts the semaphore to wait for the DNS callback */
	k_sem_init(&updatehub_sem, 0, 1);

	char ip[MAX_IP_SIZE];
	u16_t dns_id;

	memset(&ip, 0, MAX_IP_SIZE);
	ret = dns_get_addr_info(query,
				DNS_QUERY_TYPE_A,
				&dns_id, dns_cb,
				&ip,
				NETWORK_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Could not resolve dns");
		goto error;
	}

	k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

	ret = net_addr_pton(AF_INET, ip,
			    &server_addr.sin_addr);
	if (ret < 0) {
		LOG_ERR("Invalid peer IPv4 address");
		goto error;
	}

	ret = net_context_get(AF_INET, SOCK_DGRAM,
			      IPPROTO_UDP, &upadatehub_ctx.net_ctx);
	if (ret < 0) {
		LOG_ERR("Could not get an UDP context");
		goto error;
	}

	ret = net_context_connect(upadatehub_ctx.net_ctx,
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

	pkt = net_pkt_get_tx(upadatehub_ctx.net_ctx, K_FOREVER);
	frag = net_pkt_get_data(upadatehub_ctx.net_ctx, K_FOREVER);
	net_pkt_frag_add(pkt, frag);

	ret = coap_packet_init(&request_packet, pkt, 1,
			       msgtype, 8, coap_next_token(),
			       method, coap_next_id());
	if (ret < 0) {
		LOG_ERR("Could not init packet");
		goto error;
	}

	u8_t *api_header = "Api-Content-Type: application/vnd.updatehub-v1+json";

	switch (method) {
	case COAP_METHOD_GET:
		snprintk(upadatehub_ctx.uri_path, MAX_PATH_SIZE,
			 "%s/%s/packages/%s/objects/%s", uri_path(type),
			 CONFIG_UPDATEHUB_PRODUCT_UID, _probe.package_uid,
			 _probe.sha256sum_image);

		ret = coap_packet_append_option(&request_packet,
						COAP_OPTION_URI_PATH,
						upadatehub_ctx.uri_path,
						strlen(upadatehub_ctx.uri_path));
		if (ret < 0) {
			LOG_ERR("Unable add option to request path");
			goto error;
		}

		ret = coap_append_block2_option(&request_packet,
						&upadatehub_ctx.block);
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

		ret = coap_packet_append_payload(&request_packet,
						 &upadatehub_ctx.payload,
						 strlen(upadatehub_ctx.payload));
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

static int search_overwrite_ip()
{
	int ret = -1;

	ret = nvs_init(&fs, FLASH_DEV_NAME);
	if (ret) {
		LOG_ERR("Flash Init failed\n");
		upadatehub_ctx.code_status = UPDATEHUB_FLASH_INIT_ERROR;
		return ret;
	}

	char buf[MAX_IP_SIZE];

	ret = nvs_read(&fs, ADDRESS_ID, &buf, sizeof(buf));
	if (ret > 0) {
		LOG_INF("Id: %d, Address: %s\n", ADDRESS_ID, buf);
		upadatehub_ctx.overwrite_ip = buf;
		nvs_delete(&fs, ADDRESS_ID);
	}

	return 0;
}

static void clean_overwrite_ip()
{
	upadatehub_ctx.overwrite_ip = NULL;
}

#if defined (CONFIG_UPDATEHUB_SHELL)
static int storage_overwrite_ip()
{
	int ret;

	ret = nvs_init(&fs, FLASH_DEV_NAME);
	if (ret) {
		LOG_ERR("Flash Init failed\n");
		upadatehub_ctx.code_status = UPDATEHUB_FLASH_INIT_ERROR;
		return ret;
	}
	LOG_INF("No address found, adding %s at id %d\n",
		upadatehub_ctx.overwrite_ip, ADDRESS_ID);
	nvs_write(&fs, ADDRESS_ID, upadatehub_ctx.overwrite_ip,
		  strlen(upadatehub_ctx.overwrite_ip) + 1);
}
#endif

static void install_update_cb(struct net_context *net_ctx,
			      struct net_pkt *pkt,
			      int status, void *user)
{
	int ret = -1;
	int i;
	struct coap_packet response_packet;

	ret = coap_packet_parse(&response_packet, pkt, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	struct net_buf *frag;
	u16_t offset_data;
	u16_t len;

	frag = coap_packet_get_payload(&response_packet,
				       &offset_data, &len);
	if ((!frag && len == 0xffff) || len == 0) {
		LOG_ERR("Invalid payload");
		upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		ret = -1;
		goto end;
	}

	while (frag) {
		upadatehub_ctx.downloaded_size = upadatehub_ctx.downloaded_size +
						 (frag->len - offset_data);

		ret = tc_sha256_update(&sha256sum, frag->data +
				       offset_data,
				       frag->len - offset_data);
		if (ret < 1) {
			LOG_ERR("Could not update sha256sum");
			upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}

		ret = flash_img_buffered_write(&flash_ctx,
					       frag->data + offset_data,
					       frag->len - offset_data,
					       upadatehub_ctx.downloaded_size ==
					       upadatehub_ctx.block.total_size);
		if (ret < 0) {
			LOG_ERR("Error to write on the flash");
			upadatehub_ctx.code_status = UPDATEHUB_INSTALL_ERROR;
			goto end;
		}

		offset_data = 0;
		frag = frag->frags;
	}

	if (coap_next_block(&response_packet, &upadatehub_ctx.block) == 0) {
		LOG_ERR("Could not get the next");
		upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (upadatehub_ctx.downloaded_size ==
	    upadatehub_ctx.block.total_size) {
		char buffer[2];
		char sha256sum_image_dowloaded[SHA256SUM_STRING_SIZE];
		uint8_t image_hash[TC_SHA256_DIGEST_SIZE];

		ret = tc_sha256_final(image_hash, &sha256sum);
		if (ret < 1) {
			LOG_ERR("Could not finish sha256sum");
			upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}

		memset(&sha256sum_image_dowloaded, 0, SHA256SUM_STRING_SIZE);
		for (i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
			snprintk(buffer, TC_SHA256_DIGEST_SIZE, "%02x", image_hash[i]);
			strcat(&sha256sum_image_dowloaded[i], buffer);
		}

		if (strcmp(sha256sum_image_dowloaded,
			   _probe.sha256sum_image) != 0) {
			LOG_ERR("SHA256SUM of image and downloaded"
				"image are not the same");
			upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}
	}

	upadatehub_ctx.code_status = UPDATEHUB_OK;

end:
	net_pkt_unref(pkt);
	k_sem_give(&updatehub_sem);
}

static enum updatehub_response install_update()
{
	int ret = -1;

	flash_dev = device_get_binding(FLASH_DEV_NAME);

	ret = boot_erase_img_bank(FLASH_AREA_IMAGE_1_OFFSET);
	if (ret != 0) {
		LOG_ERR("Failed to init flash and erase second slot");
		upadatehub_ctx.code_status = UPDATEHUB_FLASH_INIT_ERROR;
		goto error;
	}

	ret = connect(peer_download_addr,
		      CONFIG_UPDATEHUB_DOWNLOAD_SERVER);
	if (ret < 0) {
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	ret = tc_sha256_init(&sha256sum);
	if (ret < 1) {
		LOG_ERR("Could not start sha256sum");
		upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto error;
	}

	ret = net_context_recv(upadatehub_ctx.net_ctx, install_update_cb,
			       K_NO_WAIT, NULL);
	if (ret < 0) {
		LOG_ERR("Could not set receive callback");
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	ret = coap_block_transfer_init(&upadatehub_ctx.block,
				       COAP_BLOCK_1024,
				       _probe.image_size);
	if (ret < 0) {
		LOG_ERR("Unable init block transfer");
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	flash_img_init(&flash_ctx, flash_dev);

	upadatehub_ctx.downloaded_size = 0;
	int verification_download = 0;
	int attempts_download = 0;

	while (upadatehub_ctx.downloaded_size !=
	       upadatehub_ctx.block.total_size) {
		/* Starts the semaphore to wait for the install callback */
		k_sem_init(&updatehub_sem, 0, 1);

		verification_download = upadatehub_ctx.downloaded_size;

		ret = send_request(COAP_TYPE_CON, COAP_METHOD_GET,
				   UPDATEHUB_DOWNLOAD);
		if (ret < 0) {
			upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
			goto cleanup;
		}

		k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

		if (upadatehub_ctx.code_status != UPDATEHUB_OK) {
			goto cleanup;
		}

		if (verification_download == upadatehub_ctx.downloaded_size) {
			if (attempts_download == COAP_MAX_RETRY) {
				LOG_ERR("Could not get the packet");
				upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
				goto cleanup;
			}
			attempts_download++;
		}
	}

cleanup:
	ret = net_context_put(upadatehub_ctx.net_ctx);
	if (ret < 0) {
		LOG_ERR("Error to close the networking");
	}
error:
	memset(&_probe, 0, sizeof(_probe));
	upadatehub_ctx.downloaded_size = 0;
	return upadatehub_ctx.code_status;
}

static int report(enum updatehub_state execution,
		  enum updatehub_response response)
{
	int ret = -1;
	char *device_id = device_identity_get();
	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];

	ret = firmware_version_get(firmware_version);
	if (ret < 0) {
		goto error;
	}

	struct report report;
	const char *exec = state_execution(execution);

	memset(&report, 0, sizeof(report));
	report.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	report.device_identity.id = device_id;
	report.version = firmware_version;
	report.hardware = CONFIG_BOARD;
	report.status = exec;
	report.package_uid = _probe.package_uid;

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

	memset(&upadatehub_ctx.payload, 0, MAX_PAYLOAD_SIZE);
	ret = json_obj_encode_buf(send_report_descr,
				  ARRAY_SIZE(send_report_descr),
				  &report, upadatehub_ctx.payload,
				  MAX_PAYLOAD_SIZE - 1);
	if (ret < 0) {
		LOG_ERR("Could not encode metadata");
		goto error;
	}

	ret = connect(peer_updatehub_addr, CONFIG_UPDATEHUB_SERVER);
	if (ret < 0) {
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	ret = send_request(COAP_TYPE_NON_CON, COAP_METHOD_POST,
			   UPDATEHUB_REPORT);
	if (ret < 0) {
		LOG_ERR("Error to send %s report", state_execution(execution));
	}

	/* waiting to send a reporting status */
	k_sem_take(&updatehub_sem, 500);

	ret = net_context_put(upadatehub_ctx.net_ctx);
	if (ret < 0) {
		LOG_ERR("Error to close the networking");
	}
error:
	k_free(device_id);
	return ret;
}

static void probe_cb(struct net_context *net_ctx, struct net_pkt *pkt,
	      int status, void *metadata)
{
	int ret = -1;
	struct coap_packet response_packet;

	ret = coap_packet_parse(&response_packet, pkt, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (COAP_RESPONSE_CODE_NOT_FOUND ==
	    coap_header_get_code(&response_packet)) {
		LOG_INF("No update avaiable");
		upadatehub_ctx.code_status = UPDATEHUB_NO_UPDATE;
		ret = -1;
		goto end;
	}

	struct net_buf *frag;
	u16_t offset_data;
	u16_t len;

	frag = coap_packet_get_payload(&response_packet,
				       &offset_data, &len);
	if ((!frag && len == 0xffff) || len == 0) {
		LOG_ERR("Invalid payload");
		upadatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		ret = -1;
		goto end;
	}

	char frag_buffer[MAX_FRAG_SIZE];
	char *metadata_buffer = metadata;

	while (frag) {
		memset(&frag_buffer, 0, MAX_FRAG_SIZE);
		memcpy(&frag_buffer, frag->data + offset_data,
		       frag->len - offset_data);
		offset_data = 0;
		frag = frag->frags;
		strcat(metadata_buffer, frag_buffer);
	}

	upadatehub_ctx.code_status = UPDATEHUB_OK;
	LOG_INF("Probe metadata received");

end:
	net_pkt_unref(pkt);
	k_sem_give(&updatehub_sem);
}

static enum updatehub_response probe()
{
	int ret = -1;

	char *metadata = k_malloc(MAX_PAYLOAD_SIZE);
	char *metadata_copy = k_malloc(MAX_PAYLOAD_SIZE);
	char *device_id = device_identity_get();

	if (!boot_is_img_confirmed()) {
		LOG_ERR("The current image is not confirmed");
		upadatehub_ctx.code_status = UPDATEHUB_UNCONFIRMED_IMAGE;
		goto error;
	}

	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];

	ret = firmware_version_get(firmware_version);
	if (ret < 0) {
		upadatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	struct probe probe_send;

	memset(&probe_send, 0, sizeof(probe_send));
	probe_send.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	probe_send.device_identity.id = device_id;
	probe_send.version = firmware_version;
	probe_send.hardware = CONFIG_BOARD;

	memset(&upadatehub_ctx.payload, 0, MAX_PAYLOAD_SIZE);
	ret = json_obj_encode_buf(send_probe_descr,
				  ARRAY_SIZE(send_probe_descr),
				  &probe_send, upadatehub_ctx.payload,
				  MAX_PAYLOAD_SIZE - 1);
	if (ret < 0) {
		LOG_ERR("Could not encode metadata");
		upadatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	ret = search_overwrite_ip();
	if (ret < 0) {
		goto error;
	}

	ret = connect(peer_updatehub_addr, CONFIG_UPDATEHUB_SERVER);
	if (ret < 0) {
		LOG_ERR("Could not connect");
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	memset(metadata, 0, MAX_PAYLOAD_SIZE);
	ret = net_context_recv(upadatehub_ctx.net_ctx, probe_cb,
			       K_NO_WAIT, metadata);
	if (ret < 0) {
		LOG_ERR("Could not set receive callback");
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	/* Starts the semaphore to wait for the probe callback */
	k_sem_init(&updatehub_sem, 0, 1);

	ret = send_request(COAP_TYPE_CON, COAP_METHOD_POST,
			   UPDATEHUB_PROBE);
	if (ret < 0) {
		upadatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

	if (upadatehub_ctx.code_status != UPDATEHUB_OK) {
		goto cleanup;
	}

	ret = metadata_hash_get(metadata);
	if (ret == 0) {
		upadatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto cleanup;
	}

	struct resp_probe_some_boards metadata_some_boards;
	struct resp_probe_any_boards metadata_any_boards;

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
			upadatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
			goto cleanup;
		}

		memcpy(_probe.sha256sum_image,
		       metadata_any_boards.objects[1].objects.sha256sum,
		       strlen(metadata_any_boards.objects[1].objects.sha256sum));
		_probe.image_size =
			metadata_any_boards.objects[1].objects.size;
	} else {
		ret = is_compatible_hardware(&metadata_some_boards);
		if (ret < 0) {
			LOG_ERR("Incompatible hardware");
			upadatehub_ctx.code_status = UPDATEHUB_INCOMPATIBLE_HARDWARE;
			goto cleanup;
		}

		memcpy(_probe.sha256sum_image,
		       metadata_some_boards.objects[1].objects.sha256sum,
		       strlen(metadata_some_boards.objects[1].objects.sha256sum));
		_probe.image_size =
			metadata_some_boards.objects[1].objects.size;
	}

	upadatehub_ctx.code_status = UPDATEHUB_HAS_UPDATE;

cleanup:
	ret = net_context_put(upadatehub_ctx.net_ctx);
	if (ret < 0) {
		LOG_ERR("Error to close the networking");
	}

error:
	k_free(metadata);
	k_free(metadata_copy);
	k_free(device_id);
	return upadatehub_ctx.code_status;
}



enum updatehub_response updatehub_probe()
{
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	device_identity_init(flash_dev);

	memset(&_probe, 0, sizeof(_probe));

	response = probe();
	if (response != UPDATEHUB_HAS_UPDATE) {
		clean_overwrite_ip();
	}

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

	#if defined (CONFIG_UPDATEHUB_LOG)
	wait_on_log_flushed();
	#endif

	#if defined (CONFIG_UPDATEHUB_SHELL)
	if (upadatehub_ctx.overwrite_ip) {
		ret = storage_overwrite_ip();
		if (ret < 0) {
			goto error;
		}
	}
	#endif

	sys_reboot(0);

error:
	#if defined (CONFIG_UPDATEHUB_SHELL)
	clean_overwrite_ip();
	#endif

	ret = report(UPDATEHUB_STATE_ERROR, response);
	if (ret < 0) {
		LOG_ERR("Could not reporting error state");
	}
	return response;
}

static void autohandler(struct k_delayed_work *work)
{
	int ret = -1;
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	memset(&_probe, 0, sizeof(_probe));

	response = updatehub_probe();
	if (response == UPDATEHUB_NO_UPDATE ||
	    response == UPDATEHUB_UNCONFIRMED_IMAGE) {
		goto submit_queue;
	}
	if (response != UPDATEHUB_HAS_UPDATE) {
		goto error;
	}

	response = updatehub_update();
	if (response != UPDATEHUB_OK) {
		goto error;
	}

	LOG_INF("Image flashed successfuly, rebooting now");

	#if defined (CONFIG_UPDATEHUB_LOG)
	wait_on_log_flushed();
	#endif

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

	k_sem_init(&updatehub_sem, 0, 1);

	k_delayed_work_init(&work, autohandler);

	work_submit_queue(&work);
}

#if defined (CONFIG_UPDATEHUB_SHELL)
static void cmd_updatehub_probe(const struct shell *shell,
				size_t argc, char **argv)
{
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	switch (argc) {
	case 1:
		break;
	case 2:
		upadatehub_ctx.overwrite_ip = argv[1];
		break;
	default:
		shell_fprintf(shell, SHELL_ERROR,
			      "Bad parameter count\n");
		return;
	}

	shell_fprintf(shell, SHELL_INFO,
		      "Starting UpdateHub Probe...\n");

	response = updatehub_probe();
	if (response == UPDATEHUB_NO_UPDATE ||
	    response == UPDATEHUB_UNCONFIRMED_IMAGE) {
		return;
	}
	if (response != UPDATEHUB_HAS_UPDATE) {
		return;
	}

	response = updatehub_update();
	if (response != UPDATEHUB_OK) {
		return;
	}

}

static void cmd_info(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];

	firmware_version_get(firmware_version);

	shell_fprintf(shell, SHELL_NORMAL,
		      "Firmware Version: %s\n", firmware_version);
	shell_fprintf(shell, SHELL_NORMAL,
		      "Product uid: %s\n", CONFIG_UPDATEHUB_PRODUCT_UID);
	shell_fprintf(shell, SHELL_NORMAL,
		      "UpdateHub Server: %s\n", CONFIG_UPDATEHUB_SERVER);
	shell_fprintf(shell, SHELL_NORMAL,
		      "Download UpdateHub Server: %s\n",
		      CONFIG_UPDATEHUB_DOWNLOAD_SERVER);
}

SHELL_CREATE_STATIC_SUBCMD_SET(sub_updatehub){
	/* Alphabetically sorted. */
	SHELL_CMD(info, NULL,
		  "Info about configuration of UpdateHub's zephyr", cmd_info),
	SHELL_CMD(probe, NULL,
		  "Probe for Updatehub",
		  cmd_updatehub_probe),
	SHELL_SUBCMD_SET_END /* Array terminated. */
};

SHELL_CMD_REGISTER(updatehub, &sub_updatehub, "UpdateHub menu", NULL);
#endif
