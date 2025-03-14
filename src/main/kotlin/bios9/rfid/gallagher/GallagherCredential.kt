package bios9.rfid.gallagher

/**
 * A Gallagher cardholder credential.
 * Uniquely identifies a credential, e.g., an RFID tag.
 *
 * Based on the work of https://github.com/megabug/gallagher-research
 * This class aims to handle all the obfuscation/deobfuscation of the credential data.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class GallagherCredential private constructor(
    val regionCode: UByte,       // 4 bits
    val facilityCode: UShort,    // 16 bits
    val cardNumber: UInt,        // 24 bits
    val issueLevel: UByte        // 4 bits
) {
    val regionCodeLetter: Char // The region code is also displayed as a letter from A-P
        get() = ('A'.code + regionCode.toInt()).toChar()

    companion object {
        // S-Box for encoding credential data.
        private val encodingSubstitutionTable = ubyteArrayOf(
            0xA3u, 0xB0u, 0x80u, 0xC6u, 0xB2u, 0xF4u, 0x5Cu, 0x6Cu, 0x81u, 0xF1u, 0xBBu, 0xEBu, 0x55u, 0x67u, 0x3Cu, 0x05u,
            0x1Au, 0x0Eu, 0x61u, 0xF6u, 0x22u, 0xCEu, 0xAAu, 0x8Fu, 0xBDu, 0x3Bu, 0x1Fu, 0x5Eu, 0x44u, 0x04u, 0x51u, 0x2Eu,
            0x4Du, 0x9Au, 0x84u, 0xEAu, 0xF8u, 0x66u, 0x74u, 0x29u, 0x7Fu, 0x70u, 0xD8u, 0x31u, 0x7Au, 0x6Du, 0xA4u, 0x00u,
            0x82u, 0xB9u, 0x5Fu, 0xB4u, 0x16u, 0xABu, 0xFFu, 0xC2u, 0x39u, 0xDCu, 0x19u, 0x65u, 0x57u, 0x7Cu, 0x20u, 0xFAu,
            0x5Au, 0x49u, 0x13u, 0xD0u, 0xFBu, 0xA8u, 0x91u, 0x73u, 0xB1u, 0x33u, 0x18u, 0xBEu, 0x21u, 0x72u, 0x48u, 0xB6u,
            0xDBu, 0xA0u, 0x5Du, 0xCCu, 0xE6u, 0x17u, 0x27u, 0xE5u, 0xD4u, 0x53u, 0x42u, 0xF3u, 0xDDu, 0x7Bu, 0x24u, 0xACu,
            0x2Bu, 0x58u, 0x1Eu, 0xA7u, 0xE7u, 0x86u, 0x40u, 0xD3u, 0x98u, 0x97u, 0x71u, 0xCBu, 0x3Au, 0x0Fu, 0x01u, 0x9Bu,
            0x6Eu, 0x1Bu, 0xFCu, 0x34u, 0xA6u, 0xDAu, 0x07u, 0x0Cu, 0xAEu, 0x37u, 0xCAu, 0x54u, 0xFDu, 0x26u, 0xFEu, 0x0Au,
            0x45u, 0xA2u, 0x2Au, 0xC4u, 0x12u, 0x0Du, 0xF5u, 0x4Fu, 0x69u, 0xE0u, 0x8Au, 0x77u, 0x60u, 0x3Fu, 0x99u, 0x95u,
            0xD2u, 0x38u, 0x36u, 0x62u, 0xB7u, 0x32u, 0x7Eu, 0x79u, 0xC0u, 0x46u, 0x93u, 0x2Fu, 0xA5u, 0xBAu, 0x5Bu, 0xAFu,
            0x52u, 0x1Du, 0xC3u, 0x75u, 0xCFu, 0xD6u, 0x4Cu, 0x83u, 0xE8u, 0x3Du, 0x30u, 0x4Eu, 0xBCu, 0x08u, 0x2Du, 0x09u,
            0x06u, 0xD9u, 0x25u, 0x9Eu, 0x89u, 0xF2u, 0x96u, 0x88u, 0xC1u, 0x8Cu, 0x94u, 0x0Bu, 0x28u, 0xF0u, 0x47u, 0x63u,
            0xD5u, 0xB3u, 0x68u, 0x56u, 0x9Cu, 0xF9u, 0x6Fu, 0x41u, 0x50u, 0x85u, 0x8Bu, 0x9Du, 0x59u, 0xBFu, 0x9Fu, 0xE2u,
            0x8Eu, 0x6Au, 0x11u, 0x23u, 0xA1u, 0xCDu, 0xB5u, 0x7Du, 0xC7u, 0xA9u, 0xC8u, 0xEFu, 0xDFu, 0x02u, 0xB8u, 0x03u,
            0x6Bu, 0x35u, 0x3Eu, 0x2Cu, 0x76u, 0xC9u, 0xDEu, 0x1Cu, 0x4Bu, 0xD1u, 0xEDu, 0x14u, 0xC5u, 0xADu, 0xE9u, 0x64u,
            0x4Au, 0xECu, 0x8Du, 0xF7u, 0x10u, 0x43u, 0x78u, 0x15u, 0x87u, 0xE4u, 0xD7u, 0x92u, 0xE1u, 0xEEu, 0xE3u, 0x90u
        )

        // Reverse S-Box for decoding data. Generated from the encoding S-Box.
        private val decodingSubstitutionTable = ubyteArrayOf(
            0x2Fu, 0x6Eu, 0xDDu, 0xDFu, 0x1Du, 0x0Fu, 0xB0u, 0x76u, 0xADu, 0xAFu, 0x7Fu, 0xBBu, 0x77u, 0x85u, 0x11u, 0x6Du,
            0xF4u, 0xD2u, 0x84u, 0x42u, 0xEBu, 0xF7u, 0x34u, 0x55u, 0x4Au, 0x3Au, 0x10u, 0x71u, 0xE7u, 0xA1u, 0x62u, 0x1Au,
            0x3Eu, 0x4Cu, 0x14u, 0xD3u, 0x5Eu, 0xB2u, 0x7Du, 0x56u, 0xBCu, 0x27u, 0x82u, 0x60u, 0xE3u, 0xAEu, 0x1Fu, 0x9Bu,
            0xAAu, 0x2Bu, 0x95u, 0x49u, 0x73u, 0xE1u, 0x92u, 0x79u, 0x91u, 0x38u, 0x6Cu, 0x19u, 0x0Eu, 0xA9u, 0xE2u, 0x8Du,
            0x66u, 0xC7u, 0x5Au, 0xF5u, 0x1Cu, 0x80u, 0x99u, 0xBEu, 0x4Eu, 0x41u, 0xF0u, 0xE8u, 0xA6u, 0x20u, 0xABu, 0x87u,
            0xC8u, 0x1Eu, 0xA0u, 0x59u, 0x7Bu, 0x0Cu, 0xC3u, 0x3Cu, 0x61u, 0xCCu, 0x40u, 0x9Eu, 0x06u, 0x52u, 0x1Bu, 0x32u,
            0x8Cu, 0x12u, 0x93u, 0xBFu, 0xEFu, 0x3Bu, 0x25u, 0x0Du, 0xC2u, 0x88u, 0xD1u, 0xE0u, 0x07u, 0x2Du, 0x70u, 0xC6u,
            0x29u, 0x6Au, 0x4Du, 0x47u, 0x26u, 0xA3u, 0xE4u, 0x8Bu, 0xF6u, 0x97u, 0x2Cu, 0x5Du, 0x3Du, 0xD7u, 0x96u, 0x28u,
            0x02u, 0x08u, 0x30u, 0xA7u, 0x22u, 0xC9u, 0x65u, 0xF8u, 0xB7u, 0xB4u, 0x8Au, 0xCAu, 0xB9u, 0xF2u, 0xD0u, 0x17u,
            0xFFu, 0x46u, 0xFBu, 0x9Au, 0xBAu, 0x8Fu, 0xB6u, 0x69u, 0x68u, 0x8Eu, 0x21u, 0x6Fu, 0xC4u, 0xCBu, 0xB3u, 0xCEu,
            0x51u, 0xD4u, 0x81u, 0x00u, 0x2Eu, 0x9Cu, 0x74u, 0x63u, 0x45u, 0xD9u, 0x16u, 0x35u, 0x5Fu, 0xEDu, 0x78u, 0x9Fu,
            0x01u, 0x48u, 0x04u, 0xC1u, 0x33u, 0xD6u, 0x4Fu, 0x94u, 0xDEu, 0x31u, 0x9Du, 0x0Au, 0xACu, 0x18u, 0x4Bu, 0xCDu,
            0x98u, 0xB8u, 0x37u, 0xA2u, 0x83u, 0xECu, 0x03u, 0xD8u, 0xDAu, 0xE5u, 0x7Au, 0x6Bu, 0x53u, 0xD5u, 0x15u, 0xA4u,
            0x43u, 0xE9u, 0x90u, 0x67u, 0x58u, 0xC0u, 0xA5u, 0xFAu, 0x2Au, 0xB1u, 0x75u, 0x50u, 0x39u, 0x5Cu, 0xE6u, 0xDCu,
            0x89u, 0xFCu, 0xCFu, 0xFEu, 0xF9u, 0x57u, 0x54u, 0x64u, 0xA8u, 0xEEu, 0x23u, 0x0Bu, 0xF1u, 0xEAu, 0xFDu, 0xDBu,
            0xBDu, 0x09u, 0xB5u, 0x5Bu, 0x05u, 0x86u, 0x13u, 0xF3u, 0x24u, 0xC5u, 0x3Fu, 0x44u, 0x72u, 0x7Cu, 0x7Eu, 0x36u
        )

        fun create(regionCode: UByte, facilityCode: UShort, cardNumber: UInt, issueLevel: UByte): GallagherCredential {
            // Can rely on unsigned type to prevent negative values, and all values of unsigned facility code are valid for 16 bit short.
            require(regionCode <= 0x0Fu) { "Invalid region code: $regionCode" }
            require(cardNumber <= 0xFFFFFFu) { "Invalid card number: $cardNumber" }
            require(issueLevel <= 0x0Fu) { "Invalid issue level: $issueLevel" }

            return GallagherCredential(regionCode, facilityCode, cardNumber, issueLevel)
        }

        /**
         * Decodes a Gallagher 8 byte credential block into a readable GallagherCredential object.
         * The 8 byte credential block can be read from a Gallagher RFID tag.
         *
         * @param data 8 byte Gallagher credential block.
         */
        fun decode(data: UByteArray): GallagherCredential {
            require(data.size == 8) { "Invalid data length: $data. Data must be 8 bytes." }

            // More information here https://github.com/megabug/gallagher-research/blob/master/formats/cardholder/cardholder.md

            // Remove the first layer of obfuscation on the data by running it through the S-Box in reverse.
            val substituted = UByteArray(8) { i -> decodingSubstitutionTable[data[i].toInt()] }

            // Extract the bits from various places in the 8 bytes to form each of the cardholder credential values.
            val regionCode = ((substituted[3] and 0x1Fu).toUInt() shr 1).toUByte()
            val facilityCode =
                (((substituted[5] and 0x0Fu).toUInt() shl 12) or (substituted[1].toUInt() shl 4) or ((substituted[7] and 0xF0u).toUInt() shr 4)).toUShort()
            val cardNumber =
                (substituted[0].toUInt() shl 16) or ((substituted[4] and 0x1Fu).toUInt() shl 11) or (substituted[2].toUInt() shl 3) or (substituted[3].toUInt() shr 5)
            val issueLevel = substituted[7] and 0x0Fu

            return create(regionCode, facilityCode, cardNumber, issueLevel)
        }
    }

    /**
     * Generate a Gallagher 8 byte credential block.
     * This 8 byte block format is what is written to RFID tags.
     */
    fun encode(): UByteArray {
        // Arrange the credential values into an 8 byte block.
        // More information here https://github.com/megabug/gallagher-research/blob/master/formats/cardholder/cardholder.md
        val arranged = ubyteArrayOf(
            (cardNumber shr 16).toUByte(),
            (facilityCode.toUInt() shr 4).toUByte(),
            ((cardNumber and 0x7FFu) shr 3).toUByte(),
            (((cardNumber and 0x7u) shl 5) or (regionCode.toUInt() shl 1)).toUByte(),
            ((cardNumber and 0xFFFFu) shr 11).toUByte(),
            (facilityCode.toUInt() shr 12).toUByte(),
            0u,
            (((facilityCode.toUInt() and 0xFu) shl 4) or issueLevel.toUInt()).toUByte(),
        )

        return UByteArray(8) { i -> encodingSubstitutionTable[arranged[i].toInt()] } // Run the 8 byte block through a substitution table (S-Box).
    }

    override fun toString(): String {
        return "GallagherCredential(regionCode=$regionCode ($regionCodeLetter), facilityCode=$facilityCode, cardNumber=$cardNumber, issueLevel=$issueLevel)"
    }
}