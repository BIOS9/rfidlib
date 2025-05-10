package bios9.rfid.mifare.classic

@OptIn(ExperimentalUnsignedTypes::class)
interface MifareClassic {
  fun authenticateSector(sector: Int, key: UByteArray, keyType: MifareKeyType)

  fun getSize(): MifareTagSize

  fun readBlock(block: Int): UByteArray

  fun writeBlock(block: Int, data: UByteArray)

  companion object {
    val DEFAULT_KEY: UByteArray = ubyteArrayOf(0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu)

    fun sectorToBlock(sector: Int): Int {
      return sectorToBlock(sector, 0)
    }

    fun sectorToBlock(sector: Int, blockOffset: Int): Int {
      require(sector in 0..39) { "Sector must be in 0..39" }
      if (sector < 32) {
        require(blockOffset in 0..3) { "Block offset must be in 0..3 for 4 block sectors." }
        return (sector * 4) + blockOffset
      } else {
        require(blockOffset in 0..15) { "Block offset must be in 0..15 for 16 block sectors." }
        return ((sector - 32) * 16) +
            128 +
            blockOffset // Mifare 4k has 16 block sectors for sector 32 and above.
      }
    }

    fun blockToSector(block: Int): Int {
      require(block in 0..255) { "Block must be in 0..255" }
      if (block < 128) {
        return block / 4
      } else {
        return ((block - 128) / 16) + 32
      }
    }
  }
}
