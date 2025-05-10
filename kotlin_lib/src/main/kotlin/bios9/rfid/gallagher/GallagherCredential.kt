package bios9.rfid.gallagher

import bios9.util.HexUtils.hexToUByteArray

/**
 * A Gallagher cardholder credential. Uniquely identifies a credential, e.g., an RFID tag.
 *
 * Based on the work of https://github.com/megabug/gallagher-research This class aims to handle all
 * the obfuscation/deobfuscation of the credential data.
 */
@OptIn(ExperimentalUnsignedTypes::class)
class GallagherCredential
private constructor(
    val regionCode: UByte, // 4 bits
    val facilityCode: UShort, // 16 bits
    val cardNumber: UInt, // 24 bits
    val issueLevel: UByte // 4 bits
) {
  val regionCodeLetter: Char // The region code is also displayed as a letter from A-P
    get() = ('A'.code + regionCode.toInt()).toChar()

  companion object {
    // S-Box for encoding credential data.
    private val encodingSubstitutionTable =
        ("A3 B0 80 C6 B2 F4 5C 6C 81 F1 BB EB 55 67 3C 05 1A 0E 61 F6 22 CE AA 8F BD 3B 1F 5E 44 04 51 2E" +
                "4D 9A 84 EA F8 66 74 29 7F 70 D8 31 7A 6D A4 00 82 B9 5F B4 16 AB FF C2 39 DC 19 65 57 7C 20 FA" +
                "5A 49 13 D0 FB A8 91 73 B1 33 18 BE 21 72 48 B6 DB A0 5D CC E6 17 27 E5 D4 53 42 F3 DD 7B 24 AC" +
                "2B 58 1E A7 E7 86 40 D3 98 97 71 CB 3A 0F 01 9B 6E 1B FC 34 A6 DA 07 0C AE 37 CA 54 FD 26 FE 0A" +
                "45 A2 2A C4 12 0D F5 4F 69 E0 8A 77 60 3F 99 95 D2 38 36 62 B7 32 7E 79 C0 46 93 2F A5 BA 5B AF" +
                "52 1D C3 75 CF D6 4C 83 E8 3D 30 4E BC 08 2D 09 06 D9 25 9E 89 F2 96 88 C1 8C 94 0B 28 F0 47 63" +
                "D5 B3 68 56 9C F9 6F 41 50 85 8B 9D 59 BF 9F E2 8E 6A 11 23 A1 CD B5 7D C7 A9 C8 EF DF 02 B8 03" +
                "6B 35 3E 2C 76 C9 DE 1C 4B D1 ED 14 C5 AD E9 64 4A EC 8D F7 10 43 78 15 87 E4 D7 92 E1 EE E3 90")
            .hexToUByteArray()

    // Reverse S-Box for decoding data. Generated from the encoding S-Box.
    private val decodingSubstitutionTable =
        ("2F 6E DD DF 1D 0F B0 76 AD AF 7F BB 77 85 11 6D F4 D2 84 42 EB F7 34 55 4A 3A 10 71 E7 A1 62 1A" +
                "3E 4C 14 D3 5E B2 7D 56 BC 27 82 60 E3 AE 1F 9B AA 2B 95 49 73 E1 92 79 91 38 6C 19 0E A9 E2 8D" +
                "66 C7 5A F5 1C 80 99 BE 4E 41 F0 E8 A6 20 AB 87 C8 1E A0 59 7B 0C C3 3C 61 CC 40 9E 06 52 1B 32" +
                "8C 12 93 BF EF 3B 25 0D C2 88 D1 E0 07 2D 70 C6 29 6A 4D 47 26 A3 E4 8B F6 97 2C 5D 3D D7 96 28" +
                "02 08 30 A7 22 C9 65 F8 B7 B4 8A CA B9 F2 D0 17 FF 46 FB 9A BA 8F B6 69 68 8E 21 6F C4 CB B3 CE" +
                "51 D4 81 00 2E 9C 74 63 45 D9 16 35 5F ED 78 9F 01 48 04 C1 33 D6 4F 94 DE 31 9D 0A AC 18 4B CD" +
                "98 B8 37 A2 83 EC 03 D8 DA E5 7A 6B 53 D5 15 A4 43 E9 90 67 58 C0 A5 FA 2A B1 75 50 39 5C E6 DC" +
                "89 FC CF FE F9 57 54 64 A8 EE 23 0B F1 EA FD DB BD 09 B5 5B 05 86 13 F3 24 C5 3F 44 72 7C 7E 36")
            .hexToUByteArray()

    fun create(
        regionCode: UByte,
        facilityCode: UShort,
        cardNumber: UInt,
        issueLevel: UByte
    ): GallagherCredential {
      // Can rely on unsigned type to prevent negative values, and all values of unsigned facility
      // code are valid for 16 bit short.
      require(regionCode <= 0x0Fu) { "Invalid region code: $regionCode" }
      require(cardNumber <= 0xFFFFFFu) { "Invalid card number: $cardNumber" }
      require(issueLevel <= 0x0Fu) { "Invalid issue level: $issueLevel" }

      return GallagherCredential(regionCode, facilityCode, cardNumber, issueLevel)
    }

    /**
     * Decodes a Gallagher 8 byte credential block into a readable GallagherCredential object. The 8
     * byte credential block can be read from a Gallagher RFID tag.
     *
     * @param data 8 byte Gallagher credential block.
     */
    fun decode(data: UByteArray): GallagherCredential {
      require(data.size == 8) { "Invalid data length: $data. Data must be 8 bytes." }

      // More information here
      // https://github.com/megabug/gallagher-research/blob/master/formats/cardholder/cardholder.md

      // Remove the first layer of obfuscation on the data by running it through the S-Box in
      // reverse.
      val substituted = UByteArray(8) { i -> decodingSubstitutionTable[data[i].toInt()] }

      // Extract the bits from various places in the 8 bytes to form each of the cardholder
      // credential values.
      val regionCode = ((substituted[3] and 0x1Fu).toUInt() shr 1).toUByte()
      val facilityCode =
          (((substituted[5] and 0x0Fu).toUInt() shl 12) or
                  (substituted[1].toUInt() shl 4) or
                  ((substituted[7] and 0xF0u).toUInt() shr 4))
              .toUShort()
      val cardNumber =
          (substituted[0].toUInt() shl 16) or
              ((substituted[4] and 0x1Fu).toUInt() shl 11) or
              (substituted[2].toUInt() shl 3) or
              (substituted[3].toUInt() shr 5)
      val issueLevel = substituted[7] and 0x0Fu

      return create(regionCode, facilityCode, cardNumber, issueLevel)
    }
  }

  /**
   * Generate a Gallagher 8 byte credential block. This 8 byte block format is what is written to
   * RFID tags.
   */
  fun encode(): UByteArray {
    // Arrange the credential values into an 8 byte block.
    // More information here
    // https://github.com/megabug/gallagher-research/blob/master/formats/cardholder/cardholder.md
    val arranged =
        ubyteArrayOf(
            (cardNumber shr 16).toUByte(),
            (facilityCode.toUInt() shr 4).toUByte(),
            ((cardNumber and 0x7FFu) shr 3).toUByte(),
            (((cardNumber and 0x7u) shl 5) or (regionCode.toUInt() shl 1)).toUByte(),
            ((cardNumber and 0xFFFFu) shr 11).toUByte(),
            (facilityCode.toUInt() shr 12).toUByte(),
            0u,
            (((facilityCode.toUInt() and 0xFu) shl 4) or issueLevel.toUInt()).toUByte(),
        )

    return UByteArray(8) { i ->
      encodingSubstitutionTable[arranged[i].toInt()]
    } // Run the 8 byte block through a substitution table (S-Box).
  }

  override fun toString(): String {
    return "GallagherCredential(regionCode=$regionCode ($regionCodeLetter), facilityCode=$facilityCode, cardNumber=$cardNumber, issueLevel=$issueLevel)"
  }
}
