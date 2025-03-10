package bios9.rfid.mifare.classic.exceptions

class InvalidSectorSize(
    expected: Int,
    actual: Int
) : RuntimeException("Invalid MIFARE classic sector size. Expected = $expected, actual = $actual")