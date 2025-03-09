package bios9.rfid.mifare.mad.exceptions

class InvalidMadCrcException(
    sector: Int
) : RuntimeException("MIFARE Application Directory (MAD) CRC validation failed for sector $sector. Calculated CRC did not match the CRC provided in the data.")