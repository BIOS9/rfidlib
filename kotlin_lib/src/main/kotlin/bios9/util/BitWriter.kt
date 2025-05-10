package bios9.util

@OptIn(ExperimentalUnsignedTypes::class)
class BitWriter {
  private val data = mutableListOf<UByte>()
  private var currentByte: UByte = 0u
  private var bitIndex = 0
  private var totalBits = 0

  fun writeBits(value: UInt, bitCount: Int) {
    repeat(bitCount) { i ->
      val bit = (value shr (bitCount - 1 - i)) and 1u
      currentByte = (currentByte.toInt() shl 1 or bit.toInt()).toUByte()
      bitIndex++
      totalBits++

      if (bitIndex == 8) { // Byte is full, add to list and reset
        data.add(currentByte)
        currentByte = 0u
        bitIndex = 0
      }
    }
  }

  fun toUByteArray(): UByteArray {
    if (bitIndex > 0) { // If there are leftover bits, pad and add the last byte
      currentByte = (currentByte.toInt() shl (8 - bitIndex)).toUByte()
      data.add(currentByte)
    }
    return data.toUByteArray()
  }

  fun size(): Int = totalBits
}
