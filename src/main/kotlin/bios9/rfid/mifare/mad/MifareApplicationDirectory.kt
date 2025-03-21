package bios9.rfid.mifare.mad

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareClassicKeyProvider
import bios9.rfid.mifare.mad.exceptions.*

/**
 * Mifare Application Directory (MAD) decoding and encoding.
 *
 * Based on https://github.com/RfidResearchGroup/proxmark3/blob/master/client/src/mifare/mad.c And
 * https://www.nxp.com/docs/en/application-note/AN10787.pdf
 */
@OptIn(ExperimentalUnsignedTypes::class)
class MifareApplicationDirectory
private constructor(
    val multiApplicationCard: Boolean,
    val madVersion: UByte,
    val cardPublisherSector: UByte?,
    val applications: Map<Int, MadAid>
) {
  companion object {
    val MAD_KEY_A: UByteArray = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u)
    val MAD_KEY_B: UByteArray = ubyteArrayOf(0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u)
    val MAD_ACCESS_BITS: UByteArray =
        ubyteArrayOf(0x78u, 0x77u, 0x88u) // Key A read, Key B read/write all blocks.

    fun create(
        multiApplicationCard: Boolean,
        madVersion: UByte,
        cardPublisherSector: UByte?,
        applications: Map<Int, MadAid>
    ): MifareApplicationDirectory {
      require(madVersion in 1u..2u) { "MAD version must be 1 or 2" }

      if (cardPublisherSector != null) {
        require(cardPublisherSector != 0u.toUByte()) {
          "Card Publisher Sector cannot be 0 (Reserved for MADv1)"
        }

        // Spec specifies that the CPS cannot be sector 16.
        require(cardPublisherSector != 0x10u.toUByte()) {
          "Card Publisher Sector cannot be 0x10 (reserved for MADv2)"
        }

        // Spec says 0x28..0x3F shall not be used.
        // Spec also says info byte can only point to 38 sectors.
        // I take this to mean 40 sectors - sector 0 and sector 16 = 38. This means the highest
        // valid value is sector 39 (0x27).
        require(cardPublisherSector <= 0x27u) { "Card Publisher Sector must be <= 0x27" }

        // Spec says MADv1 in sector 0 is 4 bytes, and can only point to 15 sectors (excluding
        // sector 0 since that means the value is absent).
        if (madVersion == 1u.toUByte()) {
          require(cardPublisherSector < 0x10u) {
            "Card Publisher Sector must less than 0x10 for MADv1"
          }
        }
      }

      // Max sector 15 for MADv1, sector 39 for MADv2.
      val maxAppSector = if (madVersion == 1u.toUByte()) 0x0F else 0x27

      // Fill unspecified applications with FREE AID.
      val allApplications: Map<Int, MadAid> =
          (1..maxAppSector)
              .filter { s -> s != 0x10 }
              .associateWith { s ->
                applications[s] ?: MadAid.fromAdministrationCode(MadAdministrationCode.FREE)
              }

      require(!applications.containsKey(0)) {
        "An application must not be associated with sector 0 (Reserved for MADv1)"
      }
      require(!applications.containsKey(0x10)) {
        "An application must not be associated with sector 0x10 (Reserved for MADv2)"
      }
      require(applications.none { (sector, _) -> sector > maxAppSector }) {
        "Applications cannot be associated with sectors higher than $maxAppSector for MADv$madVersion"
      }

      return MifareApplicationDirectory(
          multiApplicationCard, madVersion, cardPublisherSector, allApplications)
    }

    /**
     * Read, decode and validate a Mifare Application Directory (MAD) from a Mifare Classic tag.
     *
     * @param tag A Mifare Classic tag that supports reading sectors and uses well-known MAD keys.
     * @param keyProvider A key provider used to authenticate with the MIFARE classic tag.
     */
    fun readFromMifareClassic(
        tag: MifareClassic,
        keyProvider: MifareClassicKeyProvider
    ): MifareApplicationDirectory {
      // Sector 0 must be present and readable MADv1
      keyProvider.authenticate(tag, 0)
      val block3 =
          tag.readBlock(3) // Block 3 contains the General Purpose Byte, Keys and access conditions.

      val generalPurposeByte: UByte = block3[9]

      // A GPB value of 0x96 indicates the MIFARE card has not been personalized and thus the MAD is
      // invalid.
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
      val block1 = tag.readBlock(1) // CRC and AIDs are stored in block 1.
      val block2 = tag.readBlock(2) // Rest of AIDs are stored in block 2.
      val expectedCrc0 = block1[0]
      // We have to drop the first byte of the MADv1 data since that is the expected CRC.
      val madv1Data = (block1 + block2).drop(1)
      if (Crc8Mad.compute(madv1Data.toUByteArray()) != expectedCrc0) {
        throw InvalidMadCrcException(0)
      }

      // Decode info byte, if it's non-zero, set the Card Publisher Sector (CPS).
      val sector0InfoByte =
          madv1Data[0] and 0b00111111u // Bits 6 and 7 of info byte are reserved, so ignore.
      var cardPublisherSector = if (sector0InfoByte == 0u.toUByte()) null else sector0InfoByte

      val sector0Aids: Map<Int, MadAid> =
          madv1Data
              .drop(1) // Skip the info byte.
              .chunked(2)
              .mapIndexed { index, uBytes ->
                val aid = MadAid.fromRaw(uBytes[1], uBytes[0])
                index + 1 to aid
              }
              .toMap()

      if (madVersion == 2u.toUByte()) {
        // Sector 16 must be present and readable MADv2
        keyProvider.authenticate(tag, 16)
        val sec16block0 = tag.readBlock(MifareClassic.sectorToBlock(16, 0))
        val madV2Data =
            (sec16block0.drop(1) + // Drop the CRC
                    tag.readBlock(MifareClassic.sectorToBlock(16, 1)) +
                    tag.readBlock(MifareClassic.sectorToBlock(16, 2)))
                .toUByteArray()

        // CRC calculation for MADv2 sector 16.
        val expectedCrc16 = sec16block0[0] // First byte in sector 16 is the CRC.
        if (Crc8Mad.compute(madV2Data) != expectedCrc16) {
          throw InvalidMadCrcException(16)
        }

        // Use the MADv2 CPS if it's present and non-zero.
        val sector16InfoByte =
            madV2Data[0] and 0b00111111u // Bits 6 and 7 of info byte are reserved, so ignore.
        if (sector16InfoByte != 0u.toUByte()) {
          cardPublisherSector = sector16InfoByte
        }

        val sector16Aids: Map<Int, MadAid> =
            madV2Data
                .drop(1) // Skip info byte.
                .chunked(2)
                .mapIndexed { index, uBytes ->
                  val aid = MadAid.fromRaw(uBytes[1], uBytes[0])
                  index + 17 to aid
                }
                .toMap()

        // When MADv2, concatenate AIDs from MADv1 sector0 and MADv2 sector16
        return create(
            multiApplicationCard, madVersion, cardPublisherSector, sector0Aids + sector16Aids)
      }

      return create(multiApplicationCard, madVersion, cardPublisherSector, sector0Aids)
    }
  }

  /**
   * Writes MIFARE Application Directory (MAD) to a MIFARE Classic tag. MAD sectors will be
   * protected with default MAD A and B keys.
   *
   * @param tag Tag to write MAD to.
   * @param keyProvider A key provider used to authenticate with the MIFARE classic tag.
   */
  fun writeToMifareClassic(tag: MifareClassic, keyProvider: MifareClassicKeyProvider) {
    // Authenticate Sector 0 (MADv1)
    keyProvider.authenticate(tag, 0)

    val madv1Data =
        buildList {
              add(cardPublisherSector ?: 0u) // Info Byte (CPS or 0 if absent)
              applications
                  .filterKeys { it in 1..15 }
                  .values
                  .forEach { aid ->
                    add(aid.rawValue.toUByte())
                    add((aid.rawValue.toUInt() shr 8).toUByte())
                  }
            }
            .toUByteArray()
    val crcV1 = Crc8Mad.compute(madv1Data)
    val gpb =
        0b10000000u or // DA bit.
            (if (multiApplicationCard) 1u shl 6 else 0u) or // MA bit
            madVersion.toUInt() // ADV bits (MAD version).
    val madTrailer = MAD_KEY_A + MAD_ACCESS_BITS + ubyteArrayOf(gpb.toUByte()) + MAD_KEY_B
    val madV1Blocks = ubyteArrayOf(crcV1) + madv1Data + madTrailer

    tag.writeBlock(1, madV1Blocks.sliceArray(0..15))
    tag.writeBlock(2, madV1Blocks.sliceArray(16..31))
    tag.writeBlock(3, madV1Blocks.sliceArray(32..47))

    if (madVersion == 2u.toUByte()) {
      // Authenticate Sector 16 (MADv2)
      keyProvider.authenticate(tag, 16)

      val madv2Data =
          buildList {
                add(cardPublisherSector ?: 0u) // Info Byte (CPS or 0 if absent)
                applications
                    .filterKeys { it in 17..39 }
                    .values
                    .forEach { aid ->
                      add(aid.rawValue.toUByte())
                      add((aid.rawValue.toUInt() shr 8).toUByte())
                    }
              }
              .toUByteArray()

      val crcV2 = Crc8Mad.compute(madv2Data)
      val madV2Blocks = ubyteArrayOf(crcV2) + madv2Data + madTrailer

      tag.writeBlock(MifareClassic.sectorToBlock(16, 0), madV2Blocks.sliceArray(0..15))
      tag.writeBlock(MifareClassic.sectorToBlock(16, 1), madV2Blocks.sliceArray(16..31))
      tag.writeBlock(MifareClassic.sectorToBlock(16, 2), madV2Blocks.sliceArray(32..47))
      tag.writeBlock(MifareClassic.sectorToBlock(16, 3), madV2Blocks.sliceArray(48..63))
    }
  }

  override fun toString(): String {
    val appStr =
        applications
            .filterValues { it.rawValue != 0u.toUShort() }
            .map { "\t\t${it.key}: ${it.value}" }
            .joinToString("\n")

    return "MifareApplicationDirectory(\n" +
        "\tmultiApplicationCard=$multiApplicationCard,\n" +
        "\tmadVersion=$madVersion,\n" +
        "\tcardPublisherSector=$cardPublisherSector,\n" +
        "\tapplications=(\n" +
        "$appStr\n" +
        "\t)\n" +
        ")"
  }
}
