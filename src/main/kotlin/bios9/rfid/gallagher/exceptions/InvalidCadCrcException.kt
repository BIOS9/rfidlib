package bios9.rfid.gallagher.exceptions

class InvalidCadCrcException(sector: Int) :
    RuntimeException(
        "Card Application Directory (CAD) CRC validation failed for sector $sector. Calculated CRC did not match the CRC provided in the data.")
