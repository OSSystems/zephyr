#
# Copyright (c) 2018,2019 O.S.Systems
#
# SPDX -License-Identifier: Apache-2.0
#

zephyr_library()

zephyr_library_sources_ifdef(CONFIG_UPDATEHUB updatehub.c)
zephyr_library_sources_ifdef(CONFIG_UPDATEHUB_SHELL shell.c)

if(CONFIG_UPDATEHUB_DTLS)
    set(gen_dir ${ZEPHYR_BINARY_DIR}/include/generated/)

    foreach(inc_file
        servercert.der
        privkey.der
        )
    generate_inc_file_for_target(
        ${ZEPHYR_CURRENT_LIBRARY}
        certificates/${inc_file}
        ${gen_dir}/${inc_file}.inc
        )
    endforeach()
endif()
