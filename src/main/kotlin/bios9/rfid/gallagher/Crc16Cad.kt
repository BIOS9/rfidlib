package bios9.rfid.gallagher

/**
 * Card Application Directory (CAD) Cyclic Redundancy Check (CRC) calculation.
 * Based on https://github.com/megabug/gallagher-research/blob/master/formats/cad.md
 */
@OptIn(ExperimentalUnsignedTypes::class)
class Crc16Cad private constructor() {
    companion object {
        private const val POLYNOMIAL = 0x1021u // Reversed polynomial 0x8408
        private const val INIT_VALUE = 0xFFFFu

        fun compute(data: UByteArray): UShort {
            var crc = INIT_VALUE.toUShort()

            for (byte in data) {
                crc = update(crc, byte)
            }

            return crc
        }

        private fun update(crc: UShort, byte: UByte): UShort {
            var newCrc = (crc xor byte.toUShort()).toUInt()

            for (bit in 0 until 8) {
                newCrc = if (newCrc and 1u != 0u) {
                    (newCrc shr 1) xor POLYNOMIAL
                } else {
                    newCrc shr 1
                }
            }

            return (newCrc and 0xFFFFu).toUShort() // Ensure result is within 16 bits
        }
    }
}