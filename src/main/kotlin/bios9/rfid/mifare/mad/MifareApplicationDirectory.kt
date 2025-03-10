package bios9.rfid.mifare.mad

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.rfid.mifare.classic.exceptions.InvalidSectorSize
import bios9.rfid.mifare.mad.exceptions.*

/**
 * Mifare Application Directory (MAD) decoding and encoding.
 *
 * Based on https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/mad.c
 * And https://www.nxp.com/docs/en/application-note/AN10787.pdf
 */
@OptIn(ExperimentalUnsignedTypes::class)
class MifareApplicationDirectory private constructor (
    val multiApplicationCard: Boolean,
    val madVersion: UByte,
    val cardPublisherSector: UByte?,
    val applications: Map<Int, MadAid>
) {
    companion object {
        private val MAD_KEY_A: UByteArray = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u)

        fun create(multiApplicationCard: Boolean, madVersion: UByte, cardPublisherSector: UByte?, applications: Map<Int, MadAid>): MifareApplicationDirectory {
            require(madVersion in 1u .. 2u) { "MAD version must be 1 or 2" }

            if (cardPublisherSector != null) {
                require(cardPublisherSector != 0u.toUByte()) { "Card Publisher Sector cannot be 0 (Reserved for MADv1)" }

                // Spec specifies that the CPS cannot be sector 16.
                require(cardPublisherSector != 0x10u.toUByte()) { "Card Publisher Sector cannot be 0x10 (reserved for MADv2)" }

                // Spec says 0x28..0x3F shall not be used.
                // Spec also says info byte can only point to 38 sectors.
                // I take this to mean 40 sectors - sector 0 and sector 16 = 38. This means the highest valid value is sector 39 (0x27).
                require(cardPublisherSector <= 0x27u) { "Card Publisher Sector must be <= 0x27" }

                // Spec says MADv1 in sector 0 is 4 bytes, and can only point to 15 sectors (excluding sector 0 since that means the value is absent).
                if (madVersion == 1u.toUByte()) {
                    require(cardPublisherSector < 0x10u) { "Card Publisher Sector must less than 0x10 for MADv1" }
                }
            }

            // Max sector 15 for MADv1, sector 39 for MADv2.
            val maxAppSector = if (madVersion == 1u.toUByte()) 0x0F else 0x27

            // Fill unspecified applications with FREE AID.
            val allApplications: Map<Int, MadAid> = (1..maxAppSector)
                .filter { s -> s == 0x10 }
                .associateWith { s ->
                    applications[s] ?: MadAid.fromAdministrationCode(MadAdministrationCode.FREE)
                }

            require(!applications.containsKey(0)) { "An application must not be associated with sector 0 (Reserved for MADv1)" }
            require(!applications.containsKey(0x10)) { "An application must not be associated with sector 0x10 (Reserved for MADv2)" }
            require(applications.none { (sector, _) -> sector > maxAppSector }) { "Applications cannot be associated with sectors higher than $maxAppSector for MADv$madVersion" }

            return MifareApplicationDirectory(multiApplicationCard, madVersion, cardPublisherSector, allApplications)
        }

        /**
         * Read, decode and validate a Mifare Application Directory (MAD) from a Mifare Classic tag.
         *
         * @param tag A Mifare Classic tag that supports reading sectors and uses well-known MAD keys.
         */
        fun readFromMifareClassic(tag: MifareClassic): MifareApplicationDirectory {
            // Sector 0 must be present and readable MADv1
            tag.authenticateSector(0, MAD_KEY_A, MifareKeyType.KeyA)
            val sector0 = tag.readSector(0)

            if (sector0.size != 64) {
                throw InvalidSectorSize(64, sector0.size)
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
            val sector0InfoByte = sector0[17] and 0b00111111u // Bits 6 and 7 of info byte are reserved, so ignore.
            var cardPublisherSector = if (sector0InfoByte == 0u.toUByte()) null else sector0InfoByte

            val sector0Aids: Map<Int, MadAid> = sector0
                .slice(18 .. 47)
                .chunked(2)
                .mapIndexed { index, uBytes ->
                    val aid = MadAid.fromRaw(uBytes[1], uBytes[0])
                    index + 1 to aid
                }
                .toMap()

            if (madVersion == 2u.toUByte()) {
                // Sector 16 must be present and readable MADv2
                tag.authenticateSector(16, MAD_KEY_A, MifareKeyType.KeyA)
                val sector16 = tag.readSector(16)
                if (sector16.size != 64) {
                    throw InvalidSectorSize(64, sector16.size)
                }

                // CRC calculation for MADv2 sector 16.
                val expectedCrc16 = sector16[0] // First byte in sector 16 is the CRC.
                if (Crc8Mad.compute(sector16.sliceArray(1..47)) != expectedCrc16) {
                    throw InvalidMadCrcException(16)
                }

                // Use the MADv2 CPS if it's present and non-zero.
                val sector16InfoByte = sector16[1] and 0b00111111u // Bits 6 and 7 of info byte are reserved, so ignore.
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
                return create(multiApplicationCard, madVersion, cardPublisherSector, sector0Aids + sector16Aids)
            }

            return create(multiApplicationCard, madVersion, cardPublisherSector, sector0Aids)
        }
    }
}

