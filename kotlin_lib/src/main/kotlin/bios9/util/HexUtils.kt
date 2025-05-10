package bios9.util

@OptIn(ExperimentalUnsignedTypes::class)
object HexUtils {
  fun String.hexToUByteArray(): UByteArray {
    val cleanedHex = replace(" ", "") // Remove spaces
    require(cleanedHex.length % 2 == 0) { "Hex string must have an even length" }
    return cleanedHex.chunked(2).map { it.toUByte(16) }.toUByteArray()
  }
}
