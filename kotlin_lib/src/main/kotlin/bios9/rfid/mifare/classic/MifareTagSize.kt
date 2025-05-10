package bios9.rfid.mifare.classic

enum class MifareTagSize(val totalBytes: Int, val sectorCount: Int, val blockCount: Int) {
  SizeMini(320, 5, 20), // MIFARE Mini: 320 bytes, 5 sectors, 20 blocks
  Size1k(1024, 16, 64), // MIFARE Classic 1K: 1024 bytes, 16 sectors, 64 blocks
  Size2k(2048, 32, 128), // MIFARE Classic 2K (rare): 2048 bytes, 32 sectors, 128 blocks
  Size4k(4096, 40, 256); // MIFARE Classic 4K: 4096 bytes, 40 sectors, 256 blocks

  override fun toString(): String {
    return "MIFARE ${name.removePrefix("Size")} - $totalBytes bytes, $sectorCount sectors, $blockCount blocks"
  }
}
