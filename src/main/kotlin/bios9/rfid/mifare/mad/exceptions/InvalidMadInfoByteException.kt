package bios9.rfid.mifare.mad.exceptions

class InvalidMadInfoByteException(
    byte: UByte,
    madVersion: Int
) : RuntimeException("Invalid MIFARE Application Directory (MAD) info byte $byte for MAD version $madVersion. Info byte cannot be 0x10, cannot exceed 0x25, and the MADv1 info byte cannot exceed 0x0E.")