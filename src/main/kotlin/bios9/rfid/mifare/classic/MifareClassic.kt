package bios9.rfid.mifare.classic

@OptIn(ExperimentalUnsignedTypes::class)
interface MifareClassic {
    fun authenticateSector(sector: Int, key: UByteArray, keyType: MifareKeyType)
    fun getSize(): MifareTagSize
    fun readBlock(block: Int): UByteArray
    fun writeBlock(block: Int, data: UByteArray)

    companion object {
        fun sectorToBlock(sector: Int): Int {
            return sector * 4
        }

        fun sectorToBlock(sector: Int, blockOffset: Int): Int {
            return (sector * 4) + blockOffset
        }

        fun blockToSector(block: Int): Int {
            return block / 4
        }
    }
}