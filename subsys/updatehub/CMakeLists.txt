#
# Copyright (c) 2018 O.S.Systems
#
# SPDX-License-Identifier: Apache-2.0
#

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_UPDATEHUB device_identity.c)
zephyr_library_sources_ifdef(CONFIG_UPDATEHUB updatehub.c)

zephyr_link_interface_ifdef(CONFIG_MBEDTLS mbedTLS)
zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS mbedTLS)

generate_inc_file_for_target(
 app 
 $ENV{UPDATEHUB_UHUPKG_PUBLIC_KEY}
 ${ZEPHYR_BINARY_DIR}/include/generated/public_key.pem.inc
)
