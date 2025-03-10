package bios9.rfid.mifare.classic

@OptIn(ExperimentalUnsignedTypes::class)
interface MifareClassic {
    fun authenticateSector(sector: Int, key: UByteArray, keyType: MifareKeyType)
    fun getSize(): MifareTagSize
    fun readBlock(block: Int): UByteArray
    fun writeBlock(block: Int, data: UByteArray)

    fun readSector(sector: Int): UByteArray {
        return (0..3)
            .flatMap { block -> readBlock((sector * 4) + block).asIterable() }
            .toUByteArray()
    }
}