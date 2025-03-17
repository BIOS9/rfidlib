package bios9.util

@OptIn(ExperimentalUnsignedTypes::class)
class BitReader(private val data: UByteArray) {
  private var byteIndex = 0
  private var bitIndex = 0

  fun readBits(bitCount: Int): UInt {
    var value = 0u
    repeat(bitCount) {
      val bit = (data[byteIndex].toInt() shr (7 - bitIndex)) and 1
      value = (value shl 1) or bit.toUInt()

      if (++bitIndex == 8) { // Move to the next byte
        bitIndex = 0
        byteIndex++
      }
    }
    return value
  }

  fun hasMoreBits(): Boolean = byteIndex < data.size
}
