UpdateHub sample
################

Overview
********

These are samples on how to implement simple, polling or manual, local update
using UpdateHub. UpdateHub is an enterprise-grade solution which makes simple
to remotely update all your Linux-based devices in the field. It handles all
aspects related to sending Firmware Over-the-Air (FOTA) updates with maximum
security and efficiency, while you focus in adding value to your product.

In this document you will find two modes of UpdateHub operation: polling and
manual

Polling mode runs automatically on a predefined period, probing the server
for updates and installing them without requiring user intervention. You
can access the sample source code for this mode `updatehub_polling`_.

.. _updatehub_polling: updatehub_polling

Manual mode requires the user to call the server probe and then, if there is
an available update, also requires the user to decide if it is apropriate to
update now or later. You can access the sample source code for this mode
`updatehub_manual`_.

.. _updatehub_manual: updatehub_manual

Caveats
*******

* The Zephyr port of ``UpdateHub`` is configured to run on a Freedom-K64F
  MCU by default. The application should build and run for other platforms
  without modification.

* The MCUboot bootloader is required for ``UpdateHub`` to function
  properly. More information about the Device Firmware Upgrade subsystem and
  MCUboot can be found in :ref:`mcuboot`.

Building and Running
********************

The below steps describe how to build and run the ``UpdateHub`` sample in
Zephyr. Where examples are given, it is assumed the sample is being built for
the Freedom-K64F Development Kit (``BOARD=fdrm_k64f``).

Step 1: Build MCUboot
=====================

Build MCUboot by following the instructions in the :ref:`mcuboot` documentation
page.

Step 2: Flash MCUboot
=====================

Flash the resulting image file to the 0x0 address of the flash memory. This can
be done in multiple ways, but the most common ones would be using make or ninja:

.. code-block:: console

   make flash
   # or
   ninja flash

Step 3: Build UpdateHub
==============================

``UpdateHub`` can be built for the fdrm_k64f as follows:

.. zephyr-app-commands::
    :zephyr-app: samples/updatehub/updatehub_<manual-or-polling>
    :board: fdrm_k64f
    :build-dir: fdrm_k64f_build
    :goals: build

.. updatehub_sample_sign:

Step 4: Sign the first image
============================

From this section onwards you can use either a binary (``.bin``) or an Intel
Hex (``.hex``) image format. This is written as ``(bin|hex)`` in this
document, so edit the commands accordingly before running them.

Using MCUboot's :file:`imgtool.py` script, sign the :file:`zephyr.(bin|hex)`
file you built in Step 3. In the below example, the MCUboot repo is located at
:file:`~/src/mcuboot`.

.. code-block:: console

   ~/src/mcuboot/scripts/imgtool.py sign \
        --key ~/src/mcuboot/root-rsa-2048.pem \
        --header-size 0x200 \
        --align 8 \
        --version 1.0.0 \
        --slot-size <image-slot-size> \
        <path-to-zephyr.(bin|hex)> signed.(bin|hex)

The command above creates an image file called :file:`signed.(bin|hex)` in the
current directory.

Step 5: Flash the first image
=============================

Upload the :file:`signed.(bin|hex)` file from Step 4 to image slot-0 of your
board.  The location of image slot-0 varies by board, as described in
:ref:`mcuboot_partitions`.  For the fdrm_k64f, slot-0 is located at address
``0xc000``.

Using :file:`pyocd` you don't need to specify the slot-0 starting address.

.. code-block:: console

    sudo pyocd-flashtool <path-to-signed.bin>


Step 6: Signing the test image
================================

For the update to be correctly validated on the server you will need sign the
(``bin|hex``) image, piping the output to another file.

.. code-block:: console

   ~/src/mcuboot/scripts/imgtool.py sign \
        --key ~/src/mcuboot/root-rsa-2048.pem \
        --header-size 0x200 \
        --align 8 \
        --version 2.0.0 \
        --slot-size <image-slot-size> \
        <path-to-zephyr.(bin|hex)> signed_v2.(bin|hex)


Step 7: Create a package with UpdateHub Utilities (``uhu``)
=======================================================

First you need install UpdateHub Utilities (``uhu``) at your system, using:

.. code-block:: console

    pip3 install uhu

After installing uhu you will need to set the ``product-uid``:

.. code-block:: console

    uhu product use "e4d37cfe6ec48a2d069cc0bbb8b078677e9a0d8df3a027c4d8ea131130c4265f"

Also add the package and it's mode (``zephyr``):

.. code-block:: console

    uhu package add signed_v2.(bin|hex) -m zephyr

Then inform what ``version`` this image is:

.. code-block:: console

   uhu package version 2.0.0.0

And finally you can build the package by running:

.. code-block:: console

    uhu package archive --output <name-of-package>.pkg


Step 8: Start the updatehub-ce-server
=====================================

For default the updatehub application is set to start on the official server.
For more details on how to use the official server please reffer to the
documentation on the `updatehub.io`_.

.. _updatehub.io: https://updatehub.io

However if you would like to use your own server. The steps bellow explain how
updatehub works with updatehub-ce-server.
Starting updatehub-ce-server you can just running the following Docker command:

.. code-block:: console

    docker run -d -p 8080:8080 -p 5683:5683/udp --rm  updatehub/updatehub-ce-server:latest

Using this server you can set the variable ``CONFIG_UPDATEHUB_PROBE_SERVER``
on the ``prj.conf`` file with your local ip address or you can use the ip address
directly on the shell command line, these steps bellow explain using the shell
command line.

Step 9: Add the package the server
==================================

Now you need add the package at updatehub-ce-server, for this you will need to
open your browser to the server URL, ``<your-ip-addres>:8080``, and then log
into the server using ``admin`` as the login and password by default.  After
log-in you must click on the package menu and then ``UPLOAD PACKAGE``, and select
the package built on the step 7.

Step 10: Registry device on server
==================================

For registry your device at updatehub_ce_server you need open your terminal
where you use for debbuging the board, and type the following command:

.. code-block:: console

    updatehub run <your-local-ip>

If everything is alright will print on the screen ``No update available``.

Step 11: Create a rollout
=========================

You need go where the updatehub_ce_server is open on the browser and click on
menu Rollout and after ``CREATE ROLLOUT``, and select the version of the package
that you add on the step 9. After that the update is published, and the server
is ready to accept update requests.

Step 12: Run the update
=======================

Open your terminal that you use for debbuging the board, and type the following
command:

.. code-block:: console

    updatehub run <your-local-ip>

And then wait. The board will ping the server, check if there's any new updates,
and then download the update package you've just created. If everything goes
fine the message `Image flashed successfully, you can reboot now` will be
printed on the terminal.

Step 13: Reboot the system
==========================

Open your terminal where you use for debbuging the board, and type the following
command:

.. code-block:: console

    kernel reboot cold

Your board will reboot and then start with the new image. After rebooting the
board will automatically ping the server again and the message `No update
available` will be printed on the terminal.
