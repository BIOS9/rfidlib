package bios9.rfid.mifare

/**
 * Mifare Application Directory (MAD) Cyclic Redundancy Check (CRC) calculation.
 * Based on NXP MAD specification https://www.nxp.com/docs/en/application-note/AN10787.pdf
 * And https://github.com/RfidResearchGroup/proxmark3/blob/master/common/crc.c
 */
@OptIn(ExperimentalUnsignedTypes::class)
class Crc8Mad {
    companion object {
        private const val POLYNOMIAL = 0x1Du // MIFARE MAD polynomial
        private const val INIT_VALUE = 0xC7u // Initial value from MIFARE MAD spec

        fun compute(data: UByteArray): UByte {
            var crc = INIT_VALUE.toUByte()

            for (byte in data) {
                crc = update(crc, byte)
            }

            return crc
        }

        private fun update(crc: UByte, byte: UByte): UByte {
            var newCrc = (crc xor byte).toUInt()

            for (bit in 0 until 8) {
                newCrc = if (newCrc and 0x80u != 0u) {
                    (newCrc shl 1) xor POLYNOMIAL
                } else {
                    newCrc shl 1
                }
            }

            return newCrc.toUByte()
        }
    }
}