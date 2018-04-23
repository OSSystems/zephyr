/*
 * Copyright (c) 2018 O.S.Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *
 *  @brief UpdateHub Firmware Over-the-Air library for Zephyr Project.
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
	UPDATEHUB_NETWORKING_ERROR = 0,
	UPDATEHUB_INCOMPATIBLE_HARDWARE,
	UPDATEHUB_UNCONFIRMED_IMAGE,
	UPDATEHUB_METADATA_ERROR,
	UPDATEHUB_DOWNLOAD_ERROR,
	UPDATEHUB_INSTALL_ERROR,
	UPDATEHUB_FLASH_INIT_ERROR,
	UPDATEHUB_OK,
	UPDATEHUB_HAS_UPDATE,
	UPDATEHUB_NO_UPDATE,

};

/**
 * @brief Runs Updatehub probe and Updatehub update automatically.
 *
 * @details The UpdateHub handler performs the probe updatehub call in a
 * predetermined time interval. Having updates to be made the handler will
 * perform the hardware update task.
 */
void updatehub_autohandler(void);

/**
 * @brief The UpdateHub probe verify if there is some update to be performed.
 *
 * @return UPDATEHUB_HAS_UPDATE has an update available.
 * @return UPDATEHUB_NO_UPDATE no update available.
 * @return UPDATEHUB_NETWORKING_ERROR fail to connect to the UpdateHub server.
 * @return UPDATEHUB_INCOMPATIBLE_HARDWARE if Incompatible hardware.
 * @return UPDATEHUB_METADATA_ERROR fail to parse or to encode the metadata.
 */
enum updatehub_response updatehub_probe(void);

/**
 * @brief Apply the update package.
 *
 * @details Must be used after the updatehub probe, if you have updates to
 * be made, will perform the installation of the new image and the hardware
 * will rebooting.
 *
 * @return Return UPDATEHUB_OK if success
 * @return UPDATEHUB_NETWORKING_ERROR if Fail to connect to the server.
 * @return UPDATEHUB_DOWNLOAD_ERROR Fail while downloading the update package.
 * @return UPDATEHUB_INSTALL_ERROR Fail while installing the update package.
 * @return UPDATEHUB_FLASH_INIT_ERROR fail to initilialize the flash .
 */
enum updatehub_response updatehub_update(void);

/**
 * @}
 */

#endif /* _UPDATEHUB_H_ */
