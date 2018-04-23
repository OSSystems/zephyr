/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
#undef LOG_LEVEL
#define LOG_LEVEL CONFIG_UPDATEHUB_LOG_LEVEL
LOG_MODULE_REGISTER(updatehub);

#include <zephyr.h>

#include <logging/log_ctrl.h>
#include <net/socket.h>
#include <net/net_mgmt.h>
#include <net/net_ip.h>
#include <net/udp.h>
#include <net/coap.h>
#include <net/dns_resolve.h>
#include <flash.h>
#include <dfu/mcuboot.h>
#include <dfu/flash_img.h>
#include <misc/reboot.h>
#include <tinycrypt/sha256.h>
#include <shell/shell.h>
#include <json.h>
#include <hwinfo.h>

#include <updatehub.h>
#include "updatehub_priv.h"

#define NETWORK_TIMEOUT K_SECONDS(2)
#define MAX_PATH_SIZE 255
#define MAX_PAYLOAD_SIZE 485
#define MAX_DOWNLOAD_DATA 1100
#define SHA256SUM_STRING_SIZE 65
#define COAP_MAX_RETRY 3
#define DEVICE_ID 18
#define MAX_IP_SIZE 30

#if defined(CONFIG_UPDATEHUB_CE_SERVER)
#define UPDATEHUB_SERVER CONFIG_UPDATEHUB_SERVER
#else
#define UPDATEHUB_SERVER "coap.updatehub.io"
#endif

static struct updatehub_context {
	struct net_context *net_ctx;
	struct coap_block_context block;
	enum updatehub_response code_status;
	u8_t uri_path[MAX_PATH_SIZE];
	u8_t payload[MAX_PAYLOAD_SIZE];
	int downloaded_size;
} updatehub_ctx;

static struct probe_info {
	char package_uid[SHA256SUM_STRING_SIZE];
	char sha256sum_image[SHA256SUM_STRING_SIZE];
	int image_size;
} _probe;

struct k_sem updatehub_sem;
struct flash_img_context flash_ctx;
struct tc_sha256_state_struct sha256sum;
static int sock;
struct pollfd fds[1];
static int nfds;

static struct sockaddr_in peer_updatehub_addr = { .sin_family = AF_INET,
						  .sin_port = htons(5683) };

static void wait_fds(void)
{
	if (poll(fds, nfds, NETWORK_TIMEOUT) < 0) {
		NET_ERR("Error in poll");
	}
}

static void prepare_fds(void)
{
	fds[nfds].fd = sock;
	fds[nfds].events = 1;
	nfds++;
}

static void work_submit_queue(struct k_delayed_work *work)
{
	if (!boot_is_img_confirmed()) {
		k_delayed_work_submit(work, K_SECONDS(1));
	} else {
		k_delayed_work_submit(
			work, K_MINUTES(CONFIG_UPDATEHUB_POLL_INTERVAL));
	}
}

static int metadata_hash_get(char *metadata)
{
	int ret = 0;

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
	for (int i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
		snprintk(buffer, TC_SHA256_DIGEST_SIZE, "%02x",
			 metadata_hash[i]);
		strcat(&_probe.package_uid[i], buffer);
	}

error:
	return ret;
}

static int firmware_version_get(char *firmware_version)
{
	int ret = -1;
	struct mcuboot_img_header image_header;

	ret = boot_read_bank_header(DT_FLASH_AREA_IMAGE_0_ID, &image_header,
				    BOOT_IMG_VER_STRLEN_MAX);
	if (ret != 0) {
		LOG_ERR("Could not read the bank header");
		return ret;
	}

	snprintk(firmware_version, BOOT_IMG_VER_STRLEN_MAX, "%d.%d.%d",
		 image_header.h.v1.sem_ver.major,
		 image_header.h.v1.sem_ver.minor,
		 image_header.h.v1.sem_ver.revision);

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

static void dns_cb(enum dns_resolve_status status, struct dns_addrinfo *info,
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
		LOG_ERR("DNS resolving error");
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
		LOG_ERR("Invalid IP address family");
		goto error;
	}

	buffer = net_addr_ntop(info->ai_family, addr, hr_addr, sizeof(hr_addr));
	memcpy(ip, buffer, strlen(buffer));

error:
	k_sem_give(&updatehub_sem);
}

static int start_coap_client(void)
{
	int ret = -1;

	/* Starts the semaphore to wait for the DNS callback */
	k_sem_init(&updatehub_sem, 0, 1);

	char ip[MAX_IP_SIZE];
	u16_t dns_id;

	memset(&ip, 0, MAX_IP_SIZE);
	ret = dns_get_addr_info(UPDATEHUB_SERVER, DNS_QUERY_TYPE_A, &dns_id,
				dns_cb, &ip, NETWORK_TIMEOUT);
	if (ret < 0) {
		LOG_ERR("Could not resolve dns");
		goto error;
	}

	k_sem_take(&updatehub_sem, NETWORK_TIMEOUT);

	if (net_addr_pton(AF_INET, ip, &peer_updatehub_addr.sin_addr)) {
		LOG_ERR("Invalid peer IPv4 address");
		ret = -1;
		goto error;
	}

	sock = socket(peer_updatehub_addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket");
		ret = sock;
		goto error;
	}

	ret = connect(sock, (struct sockaddr *)&peer_updatehub_addr,
		      sizeof(peer_updatehub_addr));
	if (ret < 0) {
		LOG_ERR("Cannot connect to UDP remote");
		ret = -1;
		goto error;
	}

	prepare_fds();

error:
	return ret;
}

static void cleanup_conection(void)
{
	int ret;

	ret = close(sock);
	if (ret < 0) {
		LOG_ERR("Could not close the socket");
	}

	memset(&fds[1], 0, sizeof(fds[1]));
	nfds = 0;
}

static int send_request(enum coap_msgtype msgtype, enum coap_method method,
			enum updatehub_uri_path type)
{
	int ret = -1;
	struct coap_packet request_packet;
	u8_t *data = (u8_t *)k_malloc(MAX_PAYLOAD_SIZE);

	ret = coap_packet_init(&request_packet, data, MAX_PAYLOAD_SIZE, 1,
			       COAP_TYPE_CON, 8, coap_next_token(), method,
			       coap_next_id());
	if (ret < 0) {
		LOG_ERR("Could not init packet");
		goto error;
	}

	u8_t *api_header =
		"Api-Content-Type: application/vnd.updatehub-v1+json";

	switch (method) {
	case COAP_METHOD_GET:
		snprintk(updatehub_ctx.uri_path, MAX_PATH_SIZE,
			 "%s/%s/packages/%s/objects/%s", uri_path(type),
			 CONFIG_UPDATEHUB_PRODUCT_UID, _probe.package_uid,
			 _probe.sha256sum_image);

		ret = coap_packet_append_option(&request_packet,
						COAP_OPTION_URI_PATH,
						updatehub_ctx.uri_path,
						strlen(updatehub_ctx.uri_path));
		if (ret < 0) {
			LOG_ERR("Unable add option to request path");
			goto error;
		}

		ret = coap_append_block2_option(&request_packet,
						&updatehub_ctx.block);
		if (ret < 0) {
			LOG_ERR("Unable coap append block 2");
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
						uri_path(type),
						strlen(uri_path(type)));
		if (ret < 0) {
			LOG_ERR("Unable add option to request path");
			goto error;
		}

		u8_t content_json_format = 50;

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
						 &updatehub_ctx.payload,
						 strlen(updatehub_ctx.payload));
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

	ret = send(sock, request_packet.data, request_packet.offset, 0);
	if (ret < 0) {
		LOG_ERR("Could not send request");
		goto error;
	}

error:
	k_free(data);
	return ret;
}

static void install_update_cb(void)
{
	u8_t *data = (u8_t *)k_malloc(MAX_DOWNLOAD_DATA);

	wait_fds();

	int rcvd = recv(sock, data, MAX_DOWNLOAD_DATA, MSG_DONTWAIT);
	if (rcvd <= 0) {
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		LOG_ERR("Could not receive data");
		goto end;
	}

	int ret = -1;
	struct coap_packet response_packet;

	ret = coap_packet_parse(&response_packet, data, rcvd, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	updatehub_ctx.downloaded_size =
		updatehub_ctx.downloaded_size +
		(response_packet.max_len - response_packet.offset);

	ret = tc_sha256_update(
		&sha256sum, response_packet.data + response_packet.offset,
		response_packet.max_len - response_packet.offset);
	if (ret < 1) {
		LOG_ERR("Could not update sha256sum");
		updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	ret = flash_img_buffered_write(
		&flash_ctx, response_packet.data + response_packet.offset,
		response_packet.max_len - response_packet.offset,
		updatehub_ctx.downloaded_size ==
		updatehub_ctx.block.total_size);
	if (ret < 0) {
		LOG_ERR("Error to write on the flash");
		updatehub_ctx.code_status = UPDATEHUB_INSTALL_ERROR;
		goto end;
	}

	ret = coap_update_from_block(&response_packet, &updatehub_ctx.block);
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (coap_next_block(&response_packet, &updatehub_ctx.block) == 0) {
		LOG_ERR("Could not get the next");
		updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (updatehub_ctx.downloaded_size == updatehub_ctx.block.total_size) {
		u8_t image_hash[TC_SHA256_DIGEST_SIZE];

		ret = tc_sha256_final(image_hash, &sha256sum);
		if (ret < 1) {
			LOG_ERR("Could not finish sha256sum");
			updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}

		int i;
		char buffer[2];
		char sha256sum_image_dowloaded[SHA256SUM_STRING_SIZE];

		memset(&sha256sum_image_dowloaded, 0, SHA256SUM_STRING_SIZE);
		for (i = 0; i < TC_SHA256_DIGEST_SIZE; i++) {
			snprintk(buffer, TC_SHA256_DIGEST_SIZE, "%02x",
				 image_hash[i]);
			strcat(&sha256sum_image_dowloaded[i], buffer);
		}

		if (strcmp(sha256sum_image_dowloaded, _probe.sha256sum_image) !=
		    0) {
			LOG_ERR("SHA256SUM of image are not the same");
			updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
			goto end;
		}
	}

	updatehub_ctx.code_status = UPDATEHUB_OK;

end:
	k_free(data);
}

static enum updatehub_response install_update(void)
{
	int ret = -1;

	ret = boot_erase_img_bank(DT_FLASH_AREA_IMAGE_1_ID);
	if (ret != 0) {
		LOG_ERR("Failed to init flash and erase second slot");
		updatehub_ctx.code_status = UPDATEHUB_FLASH_INIT_ERROR;
		goto error;
	}

	ret = tc_sha256_init(&sha256sum);
	if (ret < 1) {
		LOG_ERR("Could not start sha256sum");
		updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto error;
	}

	ret = start_coap_client();
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	ret = coap_block_transfer_init(&updatehub_ctx.block, COAP_BLOCK_1024,
				       _probe.image_size);
	if (ret < 0) {
		LOG_ERR("Unable init block transfer");
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	flash_img_init(&flash_ctx);

	updatehub_ctx.downloaded_size = 0;
	int verification_download = 0;
	int attempts_download = 0;

	while (updatehub_ctx.downloaded_size !=
	       updatehub_ctx.block.total_size) {
		verification_download = updatehub_ctx.downloaded_size;

		ret = send_request(COAP_TYPE_CON, COAP_METHOD_GET,
				   UPDATEHUB_DOWNLOAD);
		if (ret < 0) {
			updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
			goto cleanup;
		}

		install_update_cb();

		if (updatehub_ctx.code_status != UPDATEHUB_OK) {
			goto cleanup;
		}

		if (verification_download == updatehub_ctx.downloaded_size) {
			if (attempts_download == COAP_MAX_RETRY) {
				LOG_ERR("Could not get the packet");
				updatehub_ctx.code_status =
					UPDATEHUB_DOWNLOAD_ERROR;
				goto cleanup;
			}
			attempts_download++;
		}
	}
cleanup:
	cleanup_conection();
error:
	memset(&_probe, 0, sizeof(_probe));
	updatehub_ctx.downloaded_size = 0;
	return updatehub_ctx.code_status;
}

static int device_identity_get(char *device_id)
{
	u8_t dev_id[16];
	ssize_t length;

	length = hwinfo_get_device_id(dev_id, sizeof(dev_id));
	if (length <= 0) {
		LOG_ERR("Could not get the device id");
		return -1;
	}

	char buf[2];
	int i;

	memset(device_id, 0, DEVICE_ID);

	for (i = 0; i < length; i++) {
		snprintk(buf, DEVICE_ID, "%02x", dev_id[i]);
		strcat(device_id, buf);
	}
	return 0;
}

static int report(enum updatehub_state execution,
		  enum updatehub_response response)
{
	int ret = -1;
	char *device_id = k_malloc(DEVICE_ID);
	char *firmware_version = k_malloc(BOOT_IMG_VER_STRLEN_MAX);

	ret = device_identity_get(device_id);
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

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
	case UPDATEHUB_FLASH_INIT_ERROR:
		state_execution(UPDATEHUB_FLASH_INIT_ERROR);
		break;
	default:
		report.previous_state = "";
	}

	if (strcmp(report.previous_state, "") != 0) {
		report.error_message = updatehub_response(response);
	} else {
		report.error_message = "";
	}

	memset(&updatehub_ctx.payload, 0, MAX_PAYLOAD_SIZE);
	ret = json_obj_encode_buf(send_report_descr,
				  ARRAY_SIZE(send_report_descr), &report,
				  updatehub_ctx.payload, MAX_PAYLOAD_SIZE - 1);
	if (ret < 0) {
		LOG_ERR("Could not encode metadata");
		goto error;
	}

	ret = start_coap_client();
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	ret = send_request(COAP_TYPE_NON_CON, COAP_METHOD_POST,
			   UPDATEHUB_REPORT);
	if (ret < 0) {
		LOG_ERR("Error to send");
		goto cleanup;
	}

	wait_fds();

cleanup:
	cleanup_conection();
error:
	k_free(firmware_version);
	k_free(device_id);
	return ret;
}

static void probe_cb(char *metadata)
{
	wait_fds();

	int rcvd = recv(sock, metadata, MAX_PAYLOAD_SIZE, MSG_DONTWAIT);
	if (rcvd <= 0) {
		LOG_ERR("Could not receive data");
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto end;
	}

	struct coap_packet reply;
	int ret = -1;

	ret = coap_packet_parse(&reply, metadata, rcvd, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
		updatehub_ctx.code_status = UPDATEHUB_DOWNLOAD_ERROR;
		goto end;
	}

	if (COAP_RESPONSE_CODE_NOT_FOUND == coap_header_get_code(&reply)) {
		LOG_INF("No update available");
		updatehub_ctx.code_status = UPDATEHUB_NO_UPDATE;
		goto end;
	}

	char tmp[MAX_PAYLOAD_SIZE];

	memset(&tmp, 0, MAX_PAYLOAD_SIZE);
	memcpy(tmp, reply.data + reply.offset, reply.max_len - reply.offset);
	memset(metadata, 0, MAX_PAYLOAD_SIZE);
	memcpy(metadata, tmp, strlen(tmp));

	updatehub_ctx.code_status = UPDATEHUB_OK;

	LOG_INF("Probe metadata received");

end:
	return;
}

static enum updatehub_response probe(void)
{
	int ret = -1;

	char *metadata = k_malloc(MAX_PAYLOAD_SIZE);
	char *metadata_copy = k_malloc(MAX_PAYLOAD_SIZE);
	char *firmware_version = k_malloc(BOOT_IMG_VER_STRLEN_MAX);
	char *device_id = k_malloc(DEVICE_ID);

	if (!boot_is_img_confirmed()) {
		LOG_ERR("The current image is not confirmed");
		updatehub_ctx.code_status = UPDATEHUB_UNCONFIRMED_IMAGE;
		goto error;
	}

	ret = firmware_version_get(firmware_version);
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	ret = device_identity_get(device_id);
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	struct probe probe_send;

	memset(&probe_send, 0, sizeof(probe_send));
	probe_send.product_uid = CONFIG_UPDATEHUB_PRODUCT_UID;
	probe_send.device_identity.id = device_id;
	probe_send.version = firmware_version;
	probe_send.hardware = CONFIG_BOARD;

	memset(&updatehub_ctx.payload, 0, MAX_PAYLOAD_SIZE);
	ret = json_obj_encode_buf(send_probe_descr,
				  ARRAY_SIZE(send_probe_descr), &probe_send,
				  updatehub_ctx.payload, MAX_PAYLOAD_SIZE - 1);
	if (ret < 0) {
		LOG_ERR("Could not encode metadata");
		updatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto error;
	}

	ret = start_coap_client();
	if (ret < 0) {
		LOG_ERR("Could not connect");
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto error;
	}

	ret = send_request(COAP_TYPE_CON, COAP_METHOD_POST, UPDATEHUB_PROBE);
	if (ret < 0) {
		updatehub_ctx.code_status = UPDATEHUB_NETWORKING_ERROR;
		goto cleanup;
	}

	memset(metadata, 0, MAX_PAYLOAD_SIZE);
	probe_cb(metadata);

	if (updatehub_ctx.code_status != UPDATEHUB_OK) {
		goto cleanup;
	}

	ret = metadata_hash_get(metadata);
	if (ret == 0) {
		updatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
		goto cleanup;
	}

	struct resp_probe_some_boards metadata_some_boards;
	struct resp_probe_any_boards metadata_any_boards;

	memcpy(metadata_copy, metadata, strlen(metadata));
	ret = json_obj_parse(metadata, strlen(metadata),
			     recv_probe_sh_array_descr,
			     ARRAY_SIZE(recv_probe_sh_array_descr),
			     &metadata_some_boards);
	if (ret < 0) {
		ret = json_obj_parse(metadata_copy, strlen(metadata_copy),
				     recv_probe_sh_string_descr,
				     ARRAY_SIZE(recv_probe_sh_string_descr),
				     &metadata_any_boards);
		if (ret < 0) {
			LOG_ERR("Could not parse json");
			updatehub_ctx.code_status = UPDATEHUB_METADATA_ERROR;
			goto cleanup;
		}
		memcpy(_probe.sha256sum_image,
		       metadata_any_boards.objects[1].objects.sha256sum,
		       strlen(metadata_any_boards.objects[1].objects.sha256sum));
		_probe.image_size = metadata_any_boards.objects[1].objects.size;
	} else {
		ret = is_compatible_hardware(&metadata_some_boards);
		if (ret < 0) {
			LOG_ERR("Incompatible hardware");
			updatehub_ctx.code_status =
				UPDATEHUB_INCOMPATIBLE_HARDWARE;
			goto cleanup;
		}
		memcpy(_probe.sha256sum_image,
		       metadata_some_boards.objects[1].objects.sha256sum,
		       strlen(metadata_some_boards.objects[1]
			      .objects.sha256sum));
		_probe.image_size =
			metadata_some_boards.objects[1].objects.size;
	}

	updatehub_ctx.code_status = UPDATEHUB_HAS_UPDATE;

cleanup:
	cleanup_conection();
error:
	k_free(metadata);
	k_free(metadata_copy);
	k_free(firmware_version);
	k_free(device_id);
	return updatehub_ctx.code_status;
}

enum updatehub_response updatehub_probe(void)
{
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	memset(&_probe, 0, sizeof(_probe));

	response = probe();

	return response;
}

enum updatehub_response updatehub_update(void)
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

	LOG_INF("Image flashed successfully, you can reboot now");

#if !defined(CONFIG_UPDATEHUB_SHELL)
	sys_reboot(0);
#endif

	return UPDATEHUB_OK;

error:
	if (response != UPDATEHUB_NETWORKING_ERROR) {
		ret = report(UPDATEHUB_STATE_ERROR, response);
		if (ret < 0) {
			LOG_ERR("Could not reporting error state");
		}
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

#if defined(CONFIG_UPDATEHUB_LOG)
	while (log_buffered_cnt()) {
		k_sleep(5);
	}
#endif

	sys_reboot(0);

error:
	if (response != UPDATEHUB_NETWORKING_ERROR) {
		ret = report(UPDATEHUB_STATE_ERROR, response);
		if (ret < 0) {
			LOG_ERR("Could not reporting error state");
		}
	}
submit_queue:
	work_submit_queue(work);
}

void updatehub_autohandler(void)
{
	static struct k_delayed_work work;

	k_sem_init(&updatehub_sem, 0, 1);

	k_delayed_work_init(&work, autohandler);

	work_submit_queue(&work);
}

#if defined(CONFIG_UPDATEHUB_SHELL)
static int cmd_updatehub_run(const struct shell *shell, size_t argc,
			     char **argv)
{
	enum updatehub_response response = UPDATEHUB_NO_UPDATE;

	shell_fprintf(shell, SHELL_INFO, "Starting UpdateHub run...\n");

	response = updatehub_probe();
	if (response == UPDATEHUB_NO_UPDATE ||
	    response == UPDATEHUB_UNCONFIRMED_IMAGE) {
		goto error;
	}
	if (response != UPDATEHUB_HAS_UPDATE) {
		goto error;
	}

	response = updatehub_update();
	if (response != UPDATEHUB_OK) {
		goto error;
	}

	return 0;

error:
	return -1;
}

static int cmd_info(const struct shell *shell, size_t argc, char **argv)
{
	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	char firmware_version[BOOT_IMG_VER_STRLEN_MAX];

	firmware_version_get(firmware_version);

	shell_fprintf(shell, SHELL_NORMAL, "Firmware Version: %s\n",
		      firmware_version);
	shell_fprintf(shell, SHELL_NORMAL, "Product uid: %s\n",
		      CONFIG_UPDATEHUB_PRODUCT_UID);
	shell_fprintf(shell, SHELL_NORMAL, "UpdateHub Server: %s\n",
		      UPDATEHUB_SERVER);
	return 0;
}

SHELL_CREATE_STATIC_SUBCMD_SET(sub_updatehub) {
	SHELL_CMD(info, NULL, "Info about configuration of UpdateHub's zephyr",
		  cmd_info),
	SHELL_CMD(run, NULL, "Runner Updatehub", cmd_updatehub_run),
	SHELL_SUBCMD_SET_END
};

SHELL_CMD_REGISTER(updatehub, &sub_updatehub, "UpdateHub menu", NULL);
#endif
