#################################################################################################
# SAM USB HID bootloader host application for command line
# This allows communication to a 32bit SAM device that uses the USB HID bootloader from Harmony
#  (only tested on SAM L22 so far ...)
#################################################################################################
#
# MIT License
#
# Copyright (c) 2025 CSS MicroSystems GmbH, Germany
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# **Feedback Encouragement:**
# While not required, we would greatly appreciate it if any enhancements or bug 
# fixes you make to this software are contributed back to the public repository. 
# This helps improve the software for everyone.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#################################################################################################

import argparse

# using the usb1 library on Windows ...
import usb1

# profiling
#import cProfile


import time
import struct

# === USB HID Bootloader Config (also command line arguments) ===
VENDOR_ID = 0x04D8   # Microchip Vendor ID
PRODUCT_ID = 0x003C  # USB HID Bootloader PID

ENDPOINT_IN = 0x81   # HID IN
ENDPOINT_OUT = 0x01  # HID OUT
PACKET_SIZE = 64     # USB HID report size
INTERFACE = 0        # default interface of USB device

# === Bootloader Frame Constants ===
SOH = 0x01  # Start of frame
EOT = 0x04  # End of frame
DLE = 0x10  # Data Link Escape (escape special characters)

# === Bootloader Commands ===
CMD_READ_VERSION = 0x01  # Read Bootloader Version
CMD_ERASE_FLASH = 0x02   # Erase the Flash
CMD_PROGRAM_FLASH = 0x03 # Program the Flash
CMD_READ_CRC = 0x04      # Read the CRC
CMD_START_APP = 0x05     # Jump to the application

# === Debugging (can be overwritten on command line) ===
DEBUG = False


def debug_print(message):
    if DEBUG:
        print(f"[DEBUG] {message}")
        
def parse_equal_value(arg_string):
    try:
        return int(arg_string, 0)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid argument format: {arg_string}")

def bootloader_CalculateCrc(data):
    """Calculates the CRC using the bootloader's algorithm."""
    crc_table = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef
    ]

    crc = 0
    len_data = len(data)

    while len_data != 0:
        i = ((crc >> 12) ^ (data[0] >> 4))
        crc = crc_table[i & 0x0F] ^ (crc << 4)
        i = ((crc >> 12) ^ (data[0] >> 0))
        crc = crc_table[i & 0x0F] ^ (crc << 4)
        data = data[1:]  # Move to the next byte
        len_data -= 1

    return crc & 0xFFFF


# === Frame Encoding with DLE Escape ===
def encode_frame(command, payload=[]):
    """Encode a bootloader frame with SOH, CRC, and EOT, escaping special bytes."""
    data = [command] + payload
    crc_bootloader = bootloader_CalculateCrc(data) # Compute CRC using bootloader algorithm
  
    frame = [SOH]  # Start of Header
    for byte in data:
        if byte in (SOH, EOT, DLE):
            frame.append(DLE)  # Escape special byte
        frame.append(byte)
    
    # Append CRC (LSB first)
    for byte in struct.pack("<H", crc_bootloader):  # Little-endian CRC
        if byte in (SOH, EOT, DLE):
            frame.append(DLE)  # Escape special byte
        frame.append(byte)
    
    frame.append(EOT)  # End of frame
    return frame

# === USB Communication ===
def send_command(handle, command, payload=[]):
    """Send a formatted frame to the bootloader via USB HID"""
    frame = encode_frame(command, payload)
    frame += [0xFF] * (PACKET_SIZE - len(frame))  # Pad to 64 bytes
    hex_frame = [hex(byte) for byte in frame] # Konvertierung in Hexadezimaldarstellung
    debug_print(f"Encoded Frame (Hex): {hex_frame}")
    try:
        handle.interruptWrite(ENDPOINT_OUT, bytes(frame), timeout=1000)
        #time.sleep(0.05)  # Delay to allow bootloader to process
    except usb1.USBError as e:
        print(f"Error sending command: {e}")

def read_response(handle):
    """Read and decode a response from the bootloader"""
    try:
        response = handle.interruptRead(ENDPOINT_IN, PACKET_SIZE, timeout=5000)
        response = list(response) # convert response to a list
        decoded_response = []
        i = 0
        while i < len(response):
            if response[i] == DLE:
                if i + 1 < len(response):
                    decoded_response.append(response[i + 1])
                    i += 2  # Skip both DLE and the escaped byte
                else:
                    # Handle incomplete escape sequence (DLE at the end)
                    print("Error: Incomplete DLE escape sequence")
                    break
            else:
                decoded_response.append(response[i])
                i += 1
        return decoded_response
    except usb1.USBError as e:
        if e.value == -7:  # LIBUSB_ERROR_TIMEOUT Code is -7
            print("Timeout Error occurred")
        else:
            print(f"USBError: {e}")
        return None
   
# === Read Bootloader Version ===
def read_bootloader_version(handle):
    """Send Read Bootloader Version command and parse response"""
    print("Reading bootloader version...")

    send_command(handle, CMD_READ_VERSION)

    response = read_response(handle)

    if response:
        debug_print(f"Raw Response: {response}") # debugging raw response

        if response[0] == SOH and response[1] == CMD_READ_VERSION:
            major_version = response[2]
            minor_version = response[3]
            print(f"Bootloader Version: {major_version}.{minor_version}")
        else:
            print("Error: Invalid bootloader response")
    else:
        print("Error: No response received.")

# === Erase Flash ===
def erase_flash(handle):
    """Send Erase Flash command and parse response"""
    print("Erase the Flash...")

    send_command(handle, CMD_ERASE_FLASH)

    response = read_response(handle)

    if response:
        debug_print(f"Raw Response: {response}") # debugging raw response

        if response[0] == SOH and response[1] == CMD_ERASE_FLASH:
            print("... done erasing flash")
        else:
            print("Error: Invalid bootloader response")
    else:
        print("Error: No response received.")


# === Flash HEX file ===
def program_flash(handle, data):
    """Send Intel hex record to device and flash application area"""
    # loop over the complete hex file
    # A hex record must be at-least 5 bytes. (1 Data Len byte + 1 rec type byte+ 2 address bytes + 1 crc)
    # HEX_RECORD is the Intel Hex record in hexadecimal format
    # The PC host application sends one or multiple hex records in Intel Hex format along with the program Flash command
    # Each line in the Intel hexadecimal file represents a hexadecimal record
    # Each hexadecimal record starts with a colon (:) and is in ASCII format.
    # The PC host application discards the colon and converts the remaining data from
    # ASCII to hexadecimal, and then sends the data to the Bootloader
    #
    # example of hex file format:
    #   ----------- start of file below this line -------------------------------
    #   :10390000F82B002019B3000015B3000015B3000018
    #   :1039100000000000000000000000000000000000A7
    #   :1039200000000000000000000000000015B30000CF
    #   :10393000000000000000000015B3000015B30000F7
    #   :1039400015B30000F9B20000A5800000CD7E000094
    #   :1039500015B3000095AD000015B3000015B30000CD
    #   :10396000057E0000A5830000B5830000C58300002C
    #   :10397000D5830000E5830000F583000015B3000047
    #   :10398000419600005196000061960000719600007B
    #   :10399000417D000015B3000015B3000015B3000011
    #   :1039A00015B3000015B3000010B5064C2378002BAA
    #   .... [many more lines]
    #   :0839400000000000000000007F
    #   :040000030000B3192D
    #   :00000001FF
    #   --------- end of file right before this line ----------------------------
    # 6 fields (left to right)
    # 1) start code ":" (all characters preceding should be ignored ...)
    # 2) byte count (two hex digits (max. 0xFF - 255) used here: 16 (0x10)
    # 3) Address (four hex digits): 16-bit memory address offset of the data (big endian values)
    # 4) record type: two hex digits (00 to 05)
    #   00: data
    #   01: end of file
    #   02: extended segment address
    #   03: start segment address
    #   04: extended linear address
    #   05: start lilnear address
    # 5) data sequence of n bytes, represented by 2n hex digits.
    # 6) checksum (two hex digits)
    # Convert data list to hex string
    hex_data = ' '.join(f'{byte:02X}' for byte in data)

    # Extract record length, address, data, and checksum
    record_length = data[0]
    address = (data[1] << 8) | data[2]
    record_type = data[3]
    data_bytes = ' '.join(f'{byte:02X}' for byte in data[4:-1])
    checksum = data[-1]

    # Print the data in Intel HEX style
    #print(f"Programming: {record_length:02X} {address:04X} {record_type:02X} {data_bytes} {checksum:02X}")

    # Send the data as the payload
    send_command(handle, CMD_PROGRAM_FLASH, data)

    # Read the response (assuming read_response is defined elsewhere)
    response = read_response(handle)

    if response:
        debug_print(f"Raw Response: {response}") # debugging raw response

        # Assuming the response is SOH, CMD_PROGRAM_FLASH, CRC, EOT
        if response[0] == SOH and response[1] == CMD_PROGRAM_FLASH:
            pass
            #print("... data programmed successfully")
        else:
            print("Error: Invalid bootloader response")
    else:
        print("Error: No response received.")

# Problem with type 03 records in the hex file:
# explanation from stackoverflow.com:
#    "The arm-*-objcopy program is not very intelligent and just produces the 03 record
#     when the entry address is within the first megabyte for compatibility reasons,
#     and the 05 otherwise.
#     A flash tool can safely ignore these record types on bare metal ARM, because the vector
#     table contains the required addresses already. You could try filtering the hex file
#     to remove these records, e.g. using sed.'
# Our approach: Just convert the 03 records to 05 records on the fly as the USB HID bootloader only knows about 05 records ...
# Note: The Harmony bootloader basically ignores the 05 record types anyway. So one could also skip them here ...
def convert_03_to_05(record_data):
    """Converts a 0x03 record to a 0x05 record and prints a warning on new lines."""
    if record_data[3] != 0x03:
        raise ValueError("Record type is not 0x03")

    # Create a copy of the record data
    new_record = record_data[:]

    # Change the record type to 0x05
    new_record[3] = 0x05

    # Recalculate the checksum
    new_record[-1] = calculate_hex_record_checksum(new_record[:-1])

    # Print the warning and records on new lines
    print("\nWarning: Converting record 03 to 05")  # Added newline before warning
    print(f"Old record:     :{''.join(f'{byte:02X}' for byte in record_data)}")
    print(f"New record:     :{''.join(f'{byte:02X}' for byte in new_record)}")
    print("This record is ignored by the bootloader anyway ...")

    return new_record

def process_hex_file(hex_file_path, handle):
    """Reads an Intel HEX file and manages the programming flow."""
    try:
        with open(hex_file_path, 'r') as hex_file:
            # Find start and end addresses
            start_address = None
            end_address = 0
            extended_linear_address = 0 # start address
            extended_segment_address = 0

            for line in hex_file:
                line = line.strip()
                colon_index = line.find(':')
                if colon_index == -1:
                    continue
                line = line[colon_index + 1:]

                record_hex = line
                record_data = [int(record_hex[i:i + 2], 16) for i in range(0, len(record_hex), 2)]
                record_type = record_data[3]

                if record_type == 0x00:  # Data record
                    address_offset = (record_data[1] << 8) | record_data[2]
                    if start_address is None:
                        start_address = address_offset
                    end_address = max(end_address, address_offset + extended_segment_address)
                elif record_type == 0x03: # extended linear address record
                    extended_linear_address = 16 * ((record_data[4] << 8) | record_data[5]) + ((record_data[6] << 8) | record_data[7])
                elif record_type == 0x02: # extended segment address record
                    extended_segment_address = 16 * ((record_data[4] << 8) | record_data[5])

            if start_address is not None:
                print(f"Programming from {start_address:08X} to {end_address:08X} (extended_segment_address={extended_segment_address:08X})")
                step_size = (end_address - start_address) // 10
                progress_addresses = [start_address + i * step_size for i in range(11)]

                hex_file.seek(0) #reset file pointer to the beginning of the file.
                extended_segment_address = 0 # reset extended address variable.

                for line in hex_file:
                    line = line.strip()
                    colon_index = line.find(':')
                    if colon_index == -1:
                        continue
                    line = line[colon_index + 1:]

                    record_hex = line
                    record_data = [int(record_hex[i:i + 2], 16) for i in range(0, len(record_hex), 2)]
                    record_type = record_data[3]
                    address_offset = (record_data[1] << 8) | record_data[2]
                    if record_type == 0x02: # extended segment address record
                        extended_segment_address = 16 * ((record_data[4] << 8) | record_data[5])
                    address_offset += extended_segment_address

                    if address_offset in progress_addresses:
                        print(f"{address_offset:08X} ... ", end="", flush=True)
                    if record_type == 0x03:
                        record_data = convert_03_to_05(record_data)

                    if record_type != 0x01:
                        checksum_calculated = calculate_hex_record_checksum(record_data[:-1])
                        checksum_file = record_data[-1]
                        if checksum_calculated == checksum_file:
                            program_flash(handle, record_data)
                        else:
                            print(f"Checksum mismatch in line: {line}")
                    else:
                        program_flash(handle, record_data)
                        print("End of File record reached.")
                print("Programming complete.")

    except FileNotFoundError:
        print(f"Error: File not found: {hex_file_path}")
        
def calculate_hex_record_checksum(data):
    """
    Calculates the checksum of an Intel HEX record.
    """
    if not isinstance(data, (list, bytearray)):
        raise ValueError("Data must be a list or bytearray of integers.")

    data_sum = sum(data)
    lsb = data_sum & 0xFF  # Extract the LSB of the sum
    checksum = (~lsb + 1) & 0xFF  # Calculate two's complement
    return checksum

# Example usage (assuming program_flash is defined elsewhere):
# def program_flash(handle, data):
#     print(f"Programming flash with data: {data}")

# process_hex_file("my_firmware.hex", my_usb_handle, program_flash)

class CustomArgumentParser(argparse.ArgumentParser):
    def format_help(self):
        help_string = super().format_help()
        help_string = help_string.replace("--vendor-id VALUE", "--vendor-id=VALUE")
        help_string = help_string.replace("--product-id VALUE", "--product-id=VALUE")
        return help_string

# === Jump to application ===
def jump_to_application(handle):
    """Jump to the application"""
    print("Now going to jump to the application...")
    send_command(handle, CMD_START_APP)
    try:
        response = read_response(handle)
        if response:
            debug_print(f"Raw Response: {response}")
            if response[0] == SOH and response[1] == CMD_START_APP:
                print("... accepted jump")
            else:
                print("Error: Invalid bootloader response")
        else:
            print("Error: No response received.")
    except usb1.USBError as e:
        if e.value == -1: #LIBUSB_ERROR_IO
            print("Jump to application successful. USB connection closed by device.")
        else:
            print(f"USBError: {e}")

# Main function
def main():
    global VENDOR_ID, PRODUCT_ID, DEBUG
    # parse command line arguments
    parser = CustomArgumentParser(description="Bootloader Tool", usage="%(prog)s HEXFILE [--vendor-id=VALUE] [--product-id=VALUE] [--debug]")
    parser.add_argument("HEXFILE", help="Path to the Intel HEX file")
    parser.add_argument("--vendor-id", type=parse_equal_value, metavar="VALUE", help="Vendor ID (e.g., --vendor-id=0x04D8)")
    parser.add_argument("--product-id", type=parse_equal_value, metavar="VALUE", help="Product ID (e.g., --product-id=0x003C)")
    parser.add_argument("--debug", action="store_true", help="activate debugging")
    args = parser.parse_args()


    # Override global variables if arguments are provided
    if args.vendor_id is not None:
        VENDOR_ID = args.vendor_id

    if args.product_id is not None:
        PRODUCT_ID = args.product_id

    with usb1.USBContext() as context:
        handle = context.openByVendorIDAndProductID(
            VENDOR_ID,
            PRODUCT_ID,
            skip_on_error=True,
        )

        if handle is None:
            print(f"Error: Device with Vendor ID 0x{VENDOR_ID:04X} and Product ID 0x{PRODUCT_ID:04X} not found.")
            exit(1)

        print(f"Vendor ID: 0x{VENDOR_ID:04X}")
        print(f"Product ID: 0x{PRODUCT_ID:04X}")
        print(f"Hex File: {args.HEXFILE}")

        # Claim the interface to interact with the device
        if handle:
            try:
                with handle.claimInterface(INTERFACE):
                    print("Device found and interface claimed.")
                    read_bootloader_version(handle)
                    erase_flash(handle)

                    # Correct way to profile process_hex_file()
                    # profiler = cProfile.Profile()
                    # profiler.enable()
                    # process_hex_file(args.HEXFILE, handle)
                    # profiler.disable()
                    # profiler.print_stats()
                    process_hex_file(args.HEXFILE,handle)
                    jump_to_application(handle)
            except usb1.USBError as e:
                print(f"Error while communicating with the device: {e}")
            finally:
                handle.close()
        else:
            print("Device not found.")

if __name__ == "__main__":
    main()
