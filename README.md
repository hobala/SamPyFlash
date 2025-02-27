# SamPyFlash
USB HID bootloader host application for command line for SAM/PIC32 MCUs using the Harmony bootloader

## Introduction
The Script takes an Intel .hex file as an argument and flashes its content to the attached device.
The device must be in USB HID bootloader mode. The bootloader must be on the device already of course.
The application follows these steps:
* search the USB device with Vendor ID 0x04D8 and Product ID 0x003C
* claim the default interface of this device (0)
* read bootloader version
* erase the flash
* program the .hex file
* jump to the application

## Note
The code - so far - was only tested with a SAM L22N device. But as it is implemented following the documentation for the UDB Harmony Bootloader library, it should also work for other 32bit MCUs using the Harmony based USB HID bootloader ([UDP bootloader library documentation](https://microchip-mplab-harmony.github.io/bootloader/GUID-4B1469D8-2DAF-46D9-85B4-31895F8645A9.html)). The documentation - however - has some flaws.

A GUI based possibility to flash these devices is using the Harmony provided Unified Host Application GUI (Java based).

## Help
Just start with --help and see command line options.

## Start Address in HEX file
The Intel Hex file created by Atmel / Microchip studio creates record type 0x03 entries. This is a weakness by the arm-gcc suite.
As the bootloader on the device expects only 0x05 values it would produce an error sending the 0x03 entry to the device. This error in fact occurs with the Unified Host Application. Here, we just convert them to 0x05 values but in fact it is ignored by the USB HID bootloader anyway as the vector tables in the application contains the start address already.

## Standalone Windows Binary
A Windows binary can be created with pyinstaller:
`pyinstaller --onefile SamPyFlash.py`
This will create an .exe file in a dist subdirectory.


