package bios9.rfid.mifare.mad

import bios9.rfid.mifare.exceptions.*

/**
 * Mifare Application Directory (MAD) decoding and encoding.
 *
 * Based on https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/mad.c
 * And https://www.nxp.com/docs/en/application-note/AN10787.pdf
 */
@OptIn(ExperimentalUnsignedTypes::class)
class MifareApplicationDirectory private constructor(
    val multiApplicationCard: Boolean,
    val cardPublisherSector: UByte?,
    val applications: Map<Int, MadAid>
) {
    companion object {
        fun create(multiApplicationCard: Boolean, cardPublisherSector: UByte?, applications: Map<Int, MadAid>): MifareApplicationDirectory {
            return MifareApplicationDirectory(multiApplicationCard, cardPublisherSector, applications)
        }

        /**
         * Decode and validate Mifare Application Directory (MAD) version 1 sectors 0 and 16 from a Mifare tag.
         *
         * @param sector0 64 byte sector 0 from a Mifare tag which includes MADv1 data.
         */
        fun decode(sector0: UByteArray) : MifareApplicationDirectory {
            return decode(sector0, null)
        }

        /**
         * Decode and validate Mifare Application Directory (MAD) version 2 sectors 0 and 16 from a Mifare tag.
         *
         * @param sector0 64 byte sector 0 from a Mifare tag which includes MADv1 data.
         * @param sector16 Optional 64 byte sector 16 from a Mifare tag which includes additional MADv2 data.
         */
        fun decode(sector0: UByteArray, sector16: UByteArray?): MifareApplicationDirectory {
            require(sector0.size == 64) { "Invalid sector0 length: ${sector0.size}. Length must be 64 bytes." }
            if (sector16 != null) {
                require(sector16.size == 64) { "Invalid sector16 length: ${sector16.size}. Length must be 64 bytes." }
            }

            val generalPurposeByte: UByte = sector0[(3 * 16) + 9]

            // A GPB value of 0x96 indicates the MIFARE card has not been personalized and thus the MAD is invalid.
            if (generalPurposeByte == 0x69u.toUByte()) {
                throw NotPersonalizedException()
            }

            // The DA bit of the GPB specifies if MAD is present.
            if (generalPurposeByte and 0x80u == 0u.toUByte()) {
                throw MadNotFoundException()
            }

            // The MA bit of the GBP specifies if the card is multi-application or single-application.
            val multiApplicationCard = generalPurposeByte and 0x40u != 0u.toUByte()

            // The ADV bits of the GBP specify the MAD version.
            // 0b01 for V1, 0b10 for V2.
            val madVersion = generalPurposeByte and 0x03u
            if (madVersion < 1u || madVersion > 2u) {
                throw InvalidMadVersionException(madVersion)
            }

            // CRC calculation for MADv1 sector 0.
            // Expected CRC is offset by 16 bytes of manufacturer data in sector 0 (UID etc.).
            val expectedCrc0 = sector0[16]
            if (Crc8Mad.compute(sector0.sliceArray(17..47)) != expectedCrc0) {
                throw InvalidMadCrcException(0)
            }

            // Decode info byte, if it's non-zero, set the Card Publisher Sector (CPS).
            val sector0InfoByte = decodeInfoByte(sector0[17], 1)
            var cardPublisherSector = if (sector0InfoByte == 0u.toUByte()) null else sector0InfoByte

            val sector0Aids: Map<Int, MadAid> = sector0
                .slice(18 .. 47)
                .chunked(2)
                .mapIndexed { index, uBytes ->
                    val aid = MadAid.fromRaw(uBytes[1], uBytes[0])
                    index + 1 to aid
                }
                .toMap()

            // Sector 16 needs to be provided for MADv2
            if (madVersion == 2u.toUByte()) {
                requireNotNull(sector16) { "MAD version was 2 but sector 16 is null." }

                // CRC calculation for MADv2 sector 16.
                val expectedCrc16 = sector16[0] // First byte in sector 16 is the CRC.
                if (Crc8Mad.compute(sector16.sliceArray(1..47)) != expectedCrc16) {
                    throw InvalidMadCrcException(16)
                }

                // Use the MADv2 CPS if it's present and non-zero.
                val sector16InfoByte = decodeInfoByte(sector16[1], 2)
                if (sector16InfoByte != 0u.toUByte()) {
                    cardPublisherSector = sector16InfoByte
                }

                val sector16Aids: Map<Int, MadAid> = sector16
                    .slice(2 .. 47)
                    .chunked(2)
                    .mapIndexed { index, uBytes ->
                        val aid = MadAid.fromRaw(uBytes[1], uBytes[0])
                        index + 17 to aid
                    }
                    .toMap()

                // When MADv2, concatenate AIDs from MADv1 sector0 and MADv2 sector16
                return create(multiApplicationCard, cardPublisherSector, sector0Aids + sector16Aids)
            }

            return create(multiApplicationCard, cardPublisherSector, sector0Aids)
        }

        /**
         * Decodes and validates MAD info byte.
         *
         * @param byte Info byte from MAD sector.
         * @return 6 bit pointer to the Card Publisher Sector (CPS).
         */
        private fun decodeInfoByte(byte: UByte, madVersion: Int): UByte {
            val infoByte = byte and 0x3Fu // Bits 6 and 7 are reserved, so ignore.

            // Spec says 0x10 shall not be used.
            // Card publisher sector cannot be MADv2 sector 16.
            if (infoByte == 0x10u.toUByte()) {
                throw InvalidMadInfoByteException(infoByte, madVersion)
            }

            // Spec says 0x28..0x3F shall not be used.
            // Spec also says info byte can only point to 38 sectors.
            // I take this to mean 40 sectors - sector 0 and sector 16 = 38. This means the highest valid value is sector 39 (0x27).
            if (infoByte >= 0x28u) {
                throw InvalidMadInfoByteException(infoByte, madVersion)
            }

            // Spec says MADv1 in sector 0 is 4 bytes, and can only point to 15 sectors (excluding sector 0 since that means the value is absent).
            if (infoByte > 15u && madVersion == 1) {
                throw InvalidMadInfoByteException(infoByte, madVersion)
            }

            return infoByte
        }
    }
}

