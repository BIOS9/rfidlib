package bios9.rfid.gallagher

import bios9.rfid.gallagher.exceptions.InvalidCadCrcException
import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareClassicKeyProvider
import bios9.util.BitReader
import bios9.util.BitWriter
import java.util.BitSet

@OptIn(ExperimentalUnsignedTypes::class)
class CardAppliationDirectory private constructor(
    val credentials: Map<Pair<UByte, UShort>, Int>
) {
    companion object {
        val CAD_KEY_A: UByteArray = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u) // Same as MAD key.
        val CAD_KEY_B: UByteArray = ubyteArrayOf(0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u) // Same as MAD key.
        val CAD_ACCESS_BITS: UByteArray = ubyteArrayOf(0x78u, 0x77u, 0x88u) // Key A read, Key B read/write all blocks.

        fun readFromMifareClassic(tag: MifareClassic, sector: Int, keyProvider: MifareClassicKeyProvider): CardAppliationDirectory {
            require(sector in 1..39) { "Card Application Directory must be in sector 1 to 39" }

            keyProvider.authenticate(tag, sector)

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
                    Pair(regionCode.toUByte(), facilityCode.toUShort()) to credSector.toInt()
                }
                .takeWhile { (_, value) -> value != 0 } // Stop when sector 0 is reached. Sector 0 cannot be used.
                .toMap()

            return CardAppliationDirectory(mappings)
        }
    }

    fun writeToMifareClassic(tag: MifareClassic, sector: Int, keyProvider: MifareClassicKeyProvider, cad: CardAppliationDirectory) {
        require(sector in 1..39) { "Card Application Directory must be in sector 1 to 39" }
        keyProvider.authenticate(tag, sector)

        val writer = BitWriter()
        cad.credentials.forEach { (key, sector) ->
            val (regionCode, facilityCode) = key
            val mapping = (regionCode.toUInt() shl 24) or (facilityCode.toUInt() shl 8) or sector.toUInt()
            writer.writeBits(mapping, 28)
        }

        while (writer.size() < 42 * 8) {
            writer.writeBits(0u, 28)
        }

        val data = ubyteArrayOf(0x00u, 0x00u) + writer.toUByteArray()
        val crc = Crc16Cad.compute(data)
        val cadTrailer = CAD_KEY_A + CAD_ACCESS_BITS + ubyteArrayOf(0u.toUByte()) + CAD_KEY_B
        val finalData = ubyteArrayOf((crc.toUInt() shr 8).toUByte(), crc.toUByte()) + data + cadTrailer

        tag.writeBlock(MifareClassic.sectorToBlock(sector, 0), finalData.sliceArray(0 .. 15))
        tag.writeBlock(MifareClassic.sectorToBlock(sector, 1), finalData.sliceArray(16 .. 31))
        tag.writeBlock(MifareClassic.sectorToBlock(sector, 2), finalData.sliceArray(32 .. 47))
        tag.writeBlock(MifareClassic.sectorToBlock(sector, 3), finalData.sliceArray(48 .. 63))
    }

    override fun toString(): String {
        val credStr = credentials
            .map { "\t\t(FC: ${it.key.first}, RC: ${it.key.second}) -> ${it.value}" }
            .joinToString("\n")

        return "CardAppliationDirectory(\n" +
                "\tcredentials=(\n" +
                "$credStr\n" +
                "\t)\n" +
                ")"
    }
}