package bios9.rfid.mifare.exceptions

class InvalidMadVersionException (
    version: UByte,
) : RuntimeException("Invalid MIFARE Application Directory (MAD) version. Version must be either 1 or 2, version found: $version.")