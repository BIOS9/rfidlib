package bios9.rfid.gallagher

import bios9.rfid.gallagher.exceptions.InvalidCadCrcException
import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.util.BitReader
import java.util.BitSet

@OptIn(ExperimentalUnsignedTypes::class)
class CardAppliationDirectory private constructor() {
    companion object {
        private val CAD_KEY_A: UByteArray = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u) // Same as MAD key.

        fun readFromMifareClassic(tag: MifareClassic, sector: Int): CardAppliationDirectory {
            require(sector in 1..39) { "Card Application Directory must be in sector 1 to 39" }

            tag.authenticateSector(sector, CAD_KEY_A, MifareKeyType.KeyA)

            // We don't need the sector trailer here.
            val sectorData =
                tag.readBlock(MifareClassic.sectorToBlock(sector, 0)) +
                tag.readBlock(MifareClassic.sectorToBlock(sector, 1)) +
                tag.readBlock(MifareClassic.sectorToBlock(sector, 2))

            // First two bytes are CRC, then the rest is data.
            val expectedCrc = ((sectorData[0].toUInt() shl 8) or sectorData[1].toUInt()).toUShort() // Convert 2 CRC bytes into a short
            val data = sectorData.drop(2).toUByteArray()

            if (Crc16Cad.compute(data) != expectedCrc) {
                throw InvalidCadCrcException(sector)
            }

            // There are 12 "mappings" of Region Code + Facility Code -> Sector.
            // They're an odd size of 3.5 bytes which means it's not very clean to read them byte by byte so we have to use something to handle that.
            val reader = BitReader(data.drop(2).toUByteArray()) // Ignore 2 unknown bytes in the header.
            val mappings = (0..11)
                .map { reader.readBits(28) }
                .map {
                    val regionCode = (it and 0xF000000u) shr 24
                    val facilityCode = (it and 0xFFFF00u) shr 8
                    val credSector = it and 0xFFu
                    Pair(regionCode.toUByte(), facilityCode.toUShort()) to credSector.toUByte()
                }
                .takeWhile { (_, value) -> value != 0u.toUByte() } // Stop when sector 0 is reached. Sector 0 cannot be used.
                .toMap()

            return CardAppliationDirectory()
        }
    }
}