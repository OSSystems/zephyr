UpdateHub manual sample
#######################

Overview
********

This sample application implements a Simple UpdateHub manual.
UpdateHub is is an enterprise-grade solution which makes simple to remotely
update all your Linux-based devices in the field. It handles all aspects
related to sending Firmware Over-the-Air (FOTA) updates with maximum security
and efficiency, while you focus in adding value to your product.

Caveats
*******

* The Zephyr port of `updatehub_manual` is configured to run on a NXP Fdrm_k64f MCU. The
  application should build and run for other platforms without modification

* The MCUboot bootloader is required for ``updatehub_manual`` to function
  properly. More information about the Device Firmware Upgrade subsystem and
  MCUboot can be found in :ref:`mcuboot`.

Building and Running
********************

The below steps describe how to build and run the ``updatehub_manual`` sample in
Zephyr. Where examples are given, they assume the sample is being built for
the Nxp Fdrm_k64f Development Kit (``BOARD=fdrm_k64f``).

Step 1: Build MCUboot
=====================

Build MCUboot by following the instructions in the :ref:`mcuboot`
documentation page.

Step 2: Flash MCUboot
======================

Flash the resulting image file to address 0x0 of flash memory.
This can be done in multiple ways.

Using make or ninja:

.. code-block:: console

   make flash
   # or
   ninja flash

Step 3: Build updatehub_manual
=====================

``updatehub_manual`` can be built for the fdrm_k64f as follows:

.. zephyr-app-commands::
    :zephyr-app: samples/updatehub/updatehub_manual
    :board: fdrm_k64f
    :build-dir: fdrm_k64f_build
    :goals: build

.. updatehub_manual_sample_sign:

Step 4: Sign the image
======================

.. note::
   From this section onwards you can use either a binary (``.bin``) or an
   Intel Hex (``.hex``) image format. This is written as ``(bin|hex)`` in this
   document.

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

The above command creates an image file called :file:`signed.(bin|hex)` in the
current directory.

Step 5: Flash the updatehub_manual image
===============================

Upload the :file:`signed.(bin|hex)` file from Step 4 to image slot-0 of your
board.  The location of image slot-0 varies by board, as described in
:ref:`mcuboot_partitions`.  For the fdrm_k64f, slot-0 is located at address
``0xc000``.

Using :file:`pyocd` you don't need to specify the slot-0 starting address.

.. code-block:: console

    sudo pyocd-flashtool <path-to-signed.bin>


Step 6: Sign other image
========================

For to test this sample, you need sign the same (bin|hex) using other name and version.

.. code-block:: console

   ~/src/mcuboot/scripts/imgtool.py sign \
        --key ~/src/mcuboot/root-rsa-2048.pem \
        --header-size 0x200 \
        --align 8 \
        --version 2.0.0 \
        --slot-size <image-slot-size> \
        <path-to-zephyr.(bin|hex)> signed_v2.(bin|hex)


Step 7: Create a package with uhu
==================================

First you need install uhu at your system, using

.. code-block:: console

    pip3 install uhu

After to install the uhu, you need set the product-uid:

.. code-block:: console

    uhu product use "e4d37cfe6ec48a2d069cc0bbb8b078677e9a0d8df3a027c4d8ea131130c4265f"

The package and how mode is,

.. code-block:: console

    uhu package add signed_v2.bin -m zephyr

and inform what version this image is,

.. code-block:: console

   uhu package version 2.0.0.0

Finally you can build the package running

.. code-block:: console

    uhu package archive --output <name-of-package>.pkg


Step 8: Start the updatehub-ce-server
===================================

Start the server is easier just run the following command:

.. code-block:: console

    docker run -d -p 8080:8080 -p 5683:5683/udp --rm  updatehub/updatehub-ce-server:latest


Step 9: Add the package the server
=============================

Now you need add the package at updatehub-ce-server, for this, you need
open your browser and open the server `localhost:8080`, for default the
login and password is `admin`.
Now, you need click on the package menu and after `UPLOAD PACKAGE`, and
select your package built on the step 7.

Step 10: Ping device on server
============================

For ping your device at updatehub_ce_server you need open your terminal
where you use for debbuging the board, and type the following command:

.. code-block:: console

    updatehub run <your-local-ip>

If everything is alright will print on the screen `No update available`.

Step 11: Create rollout
=========================

You need go where the updatehub_ce_server is open on the browser and
click on menu Rollout and after `CREATE ROLLOUT`, and select the version
of the package that you add on the step 9.

Step 12: Go to update
======================

Open your terminal where you use for debbuging the board, and type the
following command:

.. code-block:: console

    updatehub run <your-local-ip>

If everything is alright will print on the screen `Image flashed
successfully, could reboot now`.

Step 13: Reboot the system
===========================

Open your terminal where you use for debbuging the board, and type the
following command:

.. code-block:: console

    kernel reboot cold

Your board will reboot and the new image will start. After restart
the board will ping automatically to server and the message `No update
available` will print on the screen.