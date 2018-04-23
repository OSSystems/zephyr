/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *  @brief UpdateHub Firmware Over-the-Air library for Zephyr.
 */

#ifndef _UPDATEHUB_H_
#define _UPDATEHUB_H_

/**
 * @brief Responses messages from UpdateHub library.
 *
 * @details These messages are used to inform the server and the
 * user about the process status of the UpdateHub library and also 
 * used to standardize the errors that may occur.
 *
 */
enum updatehub_response {
	UPDATEHUB_HAS_UPDATE = 0, /** Has an update available */
	UPDATEHUB_NO_UPDATE, /** No update available */
	UPDATEHUB_NETWORKING_ERROR, /** Fail to connect to the UpdateHub server */
	UPDATEHUB_SIGNATURE_ERROR, /** Invalid update package signature */
	UPDATEHUB_INCOMPATIBLE_HARDWARE, /** Incompatible hardware */
	UPDATEHUB_METADATA_ERROR, /** Fail to parse or to encode the metadata */
	UPDATEHUB_DOWNLOAD_ERROR, /** Fail while downloading the update package */
	UPDATEHUB_INSTALL_ERROR,  /** Fail while installing the update package */
	UPDATEHUB_FLASH_INIT_ERROR, /** Fail to initilialize the flash */
	UPDATEHUB_OK, /** It was Ok */
};

/**
 * @brief Starts the UpdateHub application
 *
 * @details When performing the updatehub_start function call, 
 * the library performs a probe to the server in order to check 
 * if it has any firmware updates. Once there is an update, it 
 * performs a report to the server informing the status of the 
 * application and proceeds to download and install the new
 * firmware in slot 1 in a practical and simple way. After the 
 *  download and installation is completed, it will reboot the 
 *	board and the new firmware will be executed.
 */
void updatehub_start(void);

/**
 * @brief Send a HTTP request to UpdateHub server for verify 
 * if has updates.
 *
 * @details The updatehub_probe function has the responsibility 
 *  to connect on UpdateHub server and asks if there is some update 
 *  to do.
 *
 * @return Return UPDATEHUB_OK if has update, UPDATEHUB_NO_UPDATE if the board already updated, and others if error.
 */
enum updatehub_response updatehub_probe(void);

/**
 * @brief Initializes the installation of the image in the
 * memory of the board
 *
 * @details After called updatehub_probe function and returns 
 *  success can be call updatehub_update function has the 
 *  responsibility to initialize the flash where the update 
 *  will be installed, download the image and install at board.
 *
 * @return Return UPDATEHUB_OK if success, and others if error.
 */
enum updatehub_response updatehub_update(void);

/**
 * @}
 */

#endif /* _UPDATEHUB_H_ */
