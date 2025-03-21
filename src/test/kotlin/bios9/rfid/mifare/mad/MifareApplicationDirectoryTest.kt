package bios9.rfid.mifare.mad

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareClassicKeyProvider
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.rfid.mifare.mad.exceptions.InvalidMadCrcException
import bios9.rfid.mifare.mad.exceptions.InvalidMadVersionException
import bios9.rfid.mifare.mad.exceptions.MadNotFoundException
import bios9.rfid.mifare.mad.exceptions.NotPersonalizedException
import bios9.util.HexUtils.hexToUByteArray
import io.mockk.*
import io.mockk.junit5.MockKExtension
import kotlin.test.*
import kotlin.test.Test

@MockKExtension.ConfirmVerification
@MockKExtension.CheckUnnecessaryStub
@OptIn(ExperimentalUnsignedTypes::class)
class MifareApplicationDirectoryTest {
  private val madKeyA = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u)
  private val madKeyB = ubyteArrayOf(0xB0u, 0xB1u, 0xB2u, 0xB3u, 0xB4u, 0xB5u)

  private val validSector0 =
      ("9D 49 91 16 DE 28 02 00 E3 27 00 20 00 00 00 17" +
              "CD 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" +
              "00 00 00 00 00 00 00 00 00 00 00 00 11 48 12 48" +
              "00 00 00 00 00 00 78 77 88 C1 00 00 00 00 00 00")
          .hexToUByteArray()
  private val validSector0MoreAids =
      ("9D 49 91 16 DE 28 02 00 E3 27 00 20 00 00 00 17" +
              "23 00 01 FE 02 FD 03 FC 04 FB 05 FA 06 F9 07 F8" +
              "08 F7 09 F6 0A F5 0B F4 0C F3 0D F2 0E F1 0F F0" +
              "00 00 00 00 00 00 78 77 88 C1 00 00 00 00 00 00")
          .hexToUByteArray()
  private val validSector16 =
      ("D2 00 11 EE 12 ED 13 EC 14 EB 15 EA 16 E9 17 E8" +
              "18 E7 19 E6 1A E5 1B E4 1C E3 1D E2 1E E1 1F E0" +
              "20 DF 21 DE 22 DD 23 DC 24 DB 25 DA 26 D9 27 D8" +
              "00 00 00 00 00 00 78 77 88 C2 00 00 00 00 00 00")
          .hexToUByteArray()

  private val defaultReadKeyProvider: MifareClassicKeyProvider =
      MifareClassicKeyProvider { tag, sector ->
        tag.authenticateSector(sector, madKeyA, MifareKeyType.KeyA)
      }

  private val defaultWriteKeyProvider: MifareClassicKeyProvider =
      MifareClassicKeyProvider { tag, sector ->
        tag.authenticateSector(sector, madKeyB, MifareKeyType.KeyB)
      }

  /** Replaces byte at index in array with specified value. */
  private fun UByteArray.replaceIndex(index: Int, newValue: UByte): UByteArray =
      this.mapIndexed { i, oldValue -> if (index == i) newValue else oldValue }.toUByteArray()

  /** Recalculates and replaces CRC value for MAD v1 sector. */
  private fun UByteArray.recalculateMadV1Crc(): UByteArray {
    require(this.size == 64)
    return this.replaceIndex(16, Crc8Mad.compute(this.sliceArray(17..47)))
  }

  /** Recalculates and replaces CRC value for MAD v2 sector. */
  private fun UByteArray.recalculateMadV2Crc(): UByteArray {
    require(this.size == 64)
    return this.replaceIndex(0, Crc8Mad.compute(this.sliceArray(1..47)))
  }

  /** Converts MADv1 sector into MADv2 sector by changing version bits. */
  private fun UByteArray.makeMadV2(): UByteArray {
    require(this.size == 64)
    require(this[57] == 0xC1u.toUByte())
    return this.replaceIndex(57, 0xC2u)
  }

  private fun mockClassic1k(sector0: UByteArray): MifareClassic {
    val tag = mockk<MifareClassic>()
    every { tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA) } just runs
    every { tag.readBlock(0) } returns sector0.sliceArray(0..15)
    every { tag.readBlock(1) } returns sector0.sliceArray(16..31)
    every { tag.readBlock(2) } returns sector0.sliceArray(32..47)
    every { tag.readBlock(3) } returns sector0.sliceArray(48..63)

    return tag
  }

  private fun mockClassic4k(sector0: UByteArray, sector16: UByteArray): MifareClassic {
    val tag = mockk<MifareClassic>()
    every { tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA) } just runs
    every { tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA) } just runs
    every { tag.readBlock(0) } returns sector0.sliceArray(0..15)
    every { tag.readBlock(1) } returns sector0.sliceArray(16..31)
    every { tag.readBlock(2) } returns sector0.sliceArray(32..47)
    every { tag.readBlock(3) } returns sector0.sliceArray(48..63)
    every { tag.readBlock(64) } returns sector16.sliceArray(0..15)
    every { tag.readBlock(65) } returns sector16.sliceArray(16..31)
    every { tag.readBlock(66) } returns sector16.sliceArray(32..47)
    every { tag.readBlock(67) } returns sector16.sliceArray(48..63)

    return tag
  }

  @Test
  fun `valid mad v1 should decode`() {
    val tag = mockClassic1k(validSector0)

    val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    assertEquals(1u, mad.madVersion)

    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3) // Should start by reading block 3 to get GPB.
      tag.readBlock(1)
      tag.readBlock(2)
    }
    confirmVerified(tag)
  }

  @Test
  fun `unpersonalized card should fail`() {
    // When GPB is 0x69 it indicates an unpersonalized card.
    val tag = mockClassic1k(validSector0.replaceIndex(57, 0x69u))
    assertFailsWith<NotPersonalizedException> {
      MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    }
    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3) // Should start by reading block 3 to get GPB.
    }
    confirmVerified(tag)
  }

  @Test
  fun `false mad DA bit should fail`() {
    // First bit of GPB is the DA bit.
    val tag = mockClassic1k(validSector0.replaceIndex(57, 0b01000001u))
    assertFailsWith<MadNotFoundException> {
      MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    }
    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3) // Should start by reading block 3 to get GPB.
    }
    confirmVerified(tag)
  }

  @Test
  fun `multi-application bit should be read`() {
    // Second bit of GPB is the MA bit.
    // Check multi-application.
    val maTag = mockClassic1k(validSector0.replaceIndex(57, 0b11000001u))
    assertTrue(
        MifareApplicationDirectory.readFromMifareClassic(maTag, defaultReadKeyProvider)
            .multiApplicationCard,
        "Expected multi-application card")

    verifySequence {
      maTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      maTag.readBlock(3)
      maTag.readBlock(1)
      maTag.readBlock(2)
    }
    confirmVerified(maTag)

    // Check single-application.
    val saTag = mockClassic1k(validSector0.replaceIndex(57, 0b10000001u))
    assertFalse(
        MifareApplicationDirectory.readFromMifareClassic(saTag, defaultReadKeyProvider)
            .multiApplicationCard,
        "Expected single-application card")

    verifySequence {
      saTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      saTag.readBlock(3)
      saTag.readBlock(1)
      saTag.readBlock(2)
    }
    confirmVerified(saTag)
  }

  @Test
  fun `invalid mad version should fail`() {
    // Final two bits of GPB is the MAD version which must be 1 or 2.
    val tag1 = mockClassic1k(validSector0.replaceIndex(57, 0b11000000u))
    assertFailsWith<InvalidMadVersionException> {
      // 0b00 MAD version bits.
      MifareApplicationDirectory.readFromMifareClassic(tag1, defaultReadKeyProvider)
    }
    verifySequence {
      tag1.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag1.readBlock(3)
    }
    confirmVerified(tag1)

    val tag2 = mockClassic1k(validSector0.replaceIndex(57, 0b11000011u))
    assertFailsWith<InvalidMadVersionException> {
      // 0b11 MAD version bits.
      MifareApplicationDirectory.readFromMifareClassic(tag2, defaultReadKeyProvider)
    }
    verifySequence {
      tag2.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag2.readBlock(3)
    }
    confirmVerified(tag1)
  }

  @Test
  fun `invalid mad v1 crc should fail`() {
    // 17th byte in sector 0 is CRC.
    val tag = mockClassic1k(validSector0.replaceIndex(16, 0u))
    assertFailsWith<InvalidMadCrcException> {
      MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    }
    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3)
      tag.readBlock(1)
      tag.readBlock(2)
    }
    confirmVerified(tag)
  }

  @Test
  fun `check card publisher sector`() {
    // 18th byte in sector 0 is the info byte which contains the CPS pointer.
    // CRC must be recalculated when modifying info byte 17.

    val nullCpsTag = mockClassic1k(validSector0.replaceIndex(17, 0u).recalculateMadV1Crc())
    assertNull(
        MifareApplicationDirectory.readFromMifareClassic(nullCpsTag, defaultReadKeyProvider)
            .cardPublisherSector)

    verifySequence {
      nullCpsTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      nullCpsTag.readBlock(3)
      nullCpsTag.readBlock(1)
      nullCpsTag.readBlock(2)
    }
    confirmVerified(nullCpsTag)

    for (cps in 0x01u..0x0Fu) {
      val tag = mockClassic1k(validSector0.replaceIndex(17, cps.toUByte()).recalculateMadV1Crc())
      assertEquals(
          cps.toUByte(),
          MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
              .cardPublisherSector)

      verifySequence {
        tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
        tag.readBlock(3)
        tag.readBlock(1)
        tag.readBlock(2)
      }
      confirmVerified(tag)
    }
  }

  @Test
  fun `check invalid mad v1 card publisher sector`() {
    // CPS cannot point to sector 0x10 since that's reserved for MADv2.
    val tag1 = mockClassic1k(validSector0.replaceIndex(17, 0x10u).recalculateMadV1Crc())
    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.readFromMifareClassic(tag1, defaultReadKeyProvider)
    }
    verifySequence {
      tag1.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag1.readBlock(3)
      tag1.readBlock(1)
      tag1.readBlock(2)
    }
    confirmVerified(tag1)

    // Mad V1 CPS cannot exceed 15.
    for (info in 0x10u..0x3Fu) {
      val tag = mockClassic1k(validSector0.replaceIndex(17, info.toUByte()).recalculateMadV1Crc())
      assertFailsWith<IllegalArgumentException> {
        MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
      }
    }
  }

  @Test
  fun `valid mad v2 should decode`() {
    val tag = mockClassic4k(validSector0.makeMadV2(), validSector16)

    val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    assertEquals(2u, mad.madVersion)

    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3)
      tag.readBlock(1)
      tag.readBlock(2)
      tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(64)
      tag.readBlock(65)
      tag.readBlock(66)
    }
    confirmVerified(tag)
  }

  @Test
  fun `invalid mad v2 crc should fail`() {
    // Replace CRC with 0 for MADv2 sector.
    val tag = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(0, 0u))

    assertFailsWith<InvalidMadCrcException> {
      MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
    }

    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3)
      tag.readBlock(1)
      tag.readBlock(2)
      tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(64)
      tag.readBlock(65)
      tag.readBlock(66)
    }
    confirmVerified(tag)
  }

  @Test
  fun `check valid mad v2 cps`() {
    // 2nd byte in sector 16 is the info byte which contains the CPS pointer.

    val nullCpsTag =
        mockClassic4k(
            validSector0.makeMadV2(), validSector16.replaceIndex(1, 0x0u).recalculateMadV2Crc())
    assertNull(
        MifareApplicationDirectory.readFromMifareClassic(nullCpsTag, defaultReadKeyProvider)
            .cardPublisherSector)

    verifySequence {
      nullCpsTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      nullCpsTag.readBlock(3)
      nullCpsTag.readBlock(1)
      nullCpsTag.readBlock(2)
      nullCpsTag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
      nullCpsTag.readBlock(64)
      nullCpsTag.readBlock(65)
      nullCpsTag.readBlock(66)
    }
    confirmVerified(nullCpsTag)

    for (cps in 0x01u..0x027u) {
      // Skip MADv2 sector.
      if (cps == 0x10u) {
        continue
      }

      val tag =
          mockClassic4k(
              validSector0.makeMadV2(),
              validSector16.replaceIndex(1, cps.toUByte()).recalculateMadV2Crc())
      assertEquals(
          cps.toUByte(),
          MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
              .cardPublisherSector)

      verifySequence {
        tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
        tag.readBlock(3)
        tag.readBlock(1)
        tag.readBlock(2)
        tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
        tag.readBlock(64)
        tag.readBlock(65)
        tag.readBlock(66)
      }
      confirmVerified(nullCpsTag)
    }
  }

  @Test
  fun `invalid mad v2 cps should fail`() {
    // 2nd byte in sector 16 is the info byte which contains the CPS pointer.

    // CPS cannot point at MAD v2 sector 16 (0x10).
    val tag1 =
        mockClassic4k(
            validSector0.makeMadV2(), validSector16.replaceIndex(1, 0x10u).recalculateMadV2Crc())
    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.readFromMifareClassic(tag1, defaultReadKeyProvider)
    }
    verifySequence {
      tag1.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag1.readBlock(3)
      tag1.readBlock(1)
      tag1.readBlock(2)
      tag1.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
      tag1.readBlock(64)
      tag1.readBlock(65)
      tag1.readBlock(66)
    }
    confirmVerified(tag1)

    // CPS pointer cannot exceed sector 39.
    for (info in 0x28u..0x3Fu) {
      val tag =
          mockClassic4k(
              validSector0.makeMadV2(),
              validSector16.replaceIndex(1, info.toUByte()).recalculateMadV2Crc())
      assertFailsWith<IllegalArgumentException> {
        MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)
      }

      verifySequence {
        tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
        tag.readBlock(3)
        tag.readBlock(1)
        tag.readBlock(2)
        tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
        tag.readBlock(64)
        tag.readBlock(65)
        tag.readBlock(66)
      }
      confirmVerified(tag)
    }
  }

  @Test
  fun `check valid mad v1 applications`() {
    val tag = mockClassic1k(validSector0)

    val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)

    assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
    for (sector in 1..13) {
      assertEquals(
          MadAid.fromAdministrationCode(MadAdministrationCode.FREE), mad.applications[sector])
    }

    // Gallagher AIDs
    assertEquals(
        MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x11u),
        mad.applications[14])
    assertEquals(
        MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x12u),
        mad.applications[15])

    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3)
      tag.readBlock(1)
      tag.readBlock(2)
    }
    confirmVerified(tag)
  }

  @Test
  fun `check more valid mad v1 applications`() {
    val tag = mockClassic1k(validSector0MoreAids)

    val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)

    assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
    for (sector in 1..15) {
      assertEquals(
          MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
    }

    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3)
      tag.readBlock(1)
      tag.readBlock(2)
    }
    confirmVerified(tag)
  }

  @Test
  fun `check valid mad v2 applications`() {
    val tag = mockClassic4k(validSector0MoreAids.makeMadV2(), validSector16)

    val mad = MifareApplicationDirectory.readFromMifareClassic(tag, defaultReadKeyProvider)

    assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
    for (sector in 1..39) {
      if (sector == 16) {
        continue // Skip MADv2 sector.
      }
      assertEquals(
          MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
    }

    verifySequence {
      tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(3)
      tag.readBlock(1)
      tag.readBlock(2)
      tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
      tag.readBlock(64)
      tag.readBlock(65)
      tag.readBlock(66)
    }

    confirmVerified(tag)
  }

  @Test
  fun `check create mad`() {
    MifareApplicationDirectory.create(true, 1u, null, mapOf())
    MifareApplicationDirectory.create(false, 1u, null, mapOf())
    MifareApplicationDirectory.create(true, 2u, null, mapOf())
    MifareApplicationDirectory.create(false, 2u, null, mapOf())

    for (cps in 1u..15u) {
      MifareApplicationDirectory.create(true, 1u, cps.toUByte(), mapOf())
      MifareApplicationDirectory.create(false, 1u, cps.toUByte(), mapOf())
    }

    for (cps in 1u..39u) {
      if (cps == 16u) {
        continue // Skip MADv2 sector
      }
      MifareApplicationDirectory.create(true, 2u, cps.toUByte(), mapOf())
      MifareApplicationDirectory.create(false, 2u, cps.toUByte(), mapOf())
    }
  }

  @Test
  fun `check create mad v1 with apps`() {
    for (sector in 1..15) {
      val mad =
          MifareApplicationDirectory.create(
              true,
              1u,
              null,
              mapOf(
                  sector to
                      MadAid.fromRaw(
                          sector.toUByte().inv(), sector.toUByte()) // Fill with some AIDs
                  ))
      assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
    }

    val madFull =
        MifareApplicationDirectory.create(
            true,
            1u,
            null,
            (1..15).associateWith { s -> MadAid.fromRaw(s.toUByte().inv(), s.toUByte()) })

    assertEquals(15, madFull.applications.size, "Expected 15 MADv1 sector AIDs.")
    for (sector in 1..15) {
      assertEquals(sector.toUByte(), madFull.applications[sector]!!.applicationCode)
    }
  }

  @Test
  fun `check create mad v2 with apps`() {
    for (sector in 1..39) {
      if (sector == 16) {
        continue // Skip MADv2 sector
      }
      val mad =
          MifareApplicationDirectory.create(
              true,
              2u,
              null,
              mapOf(
                  sector to
                      MadAid.fromRaw(
                          sector.toUByte().inv(), sector.toUByte()) // Fill with some AIDs.
                  ))
      assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
    }

    val madFull =
        MifareApplicationDirectory.create(
            true,
            2u,
            null,
            (1..39)
                .filter { s -> s != 16 } // Skip MADv2 sector.
                .associateWith { s -> MadAid.fromRaw(s.toUByte().inv(), s.toUByte()) })
    assertEquals(38, madFull.applications.size, "Expected 38 MADv2 sector AIDs.")
    for (sector in 1..39) {
      if (sector == 16) {
        continue // Skip MADv2 sector 16.
      }
      assertEquals(sector.toUByte(), madFull.applications[sector]!!.applicationCode)
    }
  }

  @Test
  fun `check create invalid mad version`() {
    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(true, 0u, null, mapOf())
    }

    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(true, 3u, null, mapOf())
    }
  }

  @Test
  fun `check create invalid mad cps`() {
    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(true, 1u, 0u, mapOf())
    }

    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(true, 2u, 0u, mapOf())
    }

    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(true, 1u, 16u, mapOf())
    }

    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(true, 2u, 40u, mapOf())
    }
  }

  @Test
  fun `check create mad v1 with invalid apps`() {
    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(
          true, 1u, null, mapOf(0 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    }

    for (sector in 16..100) {
      assertFailsWith<IllegalArgumentException> {
        MifareApplicationDirectory.create(
            true, 1u, null, mapOf(sector to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
      }
    }
  }

  @Test
  fun `check create mad v2 with invalid apps`() {
    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(
          true, 2u, null, mapOf(0 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    }

    assertFailsWith<IllegalArgumentException> {
      MifareApplicationDirectory.create(
          true, 2u, null, mapOf(16 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
    }

    for (sector in 40..100) {
      assertFailsWith<IllegalArgumentException> {
        MifareApplicationDirectory.create(
            true, 1u, null, mapOf(sector to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)))
      }
    }
  }

  @Test
  fun `check mad v1 apps are filled`() {
    val mad = MifareApplicationDirectory.create(true, 1u, null, mapOf())
    assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs")
    assertTrue(
        mad.applications.all { (_, aid) ->
          aid == MadAid.fromAdministrationCode(MadAdministrationCode.FREE)
        },
        "Expected all empty apps to be filled with FREE")
  }

  @Test
  fun `check mad v2 apps are filled`() {
    val mad = MifareApplicationDirectory.create(true, 2u, null, mapOf())
    assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs")
    assertTrue(
        mad.applications.all { (_, aid) ->
          aid == MadAid.fromAdministrationCode(MadAdministrationCode.FREE)
        },
        "Expected all empty apps to be filled with FREE")
  }

  @Test
  fun `mad v1 should write correctly`() {
    val mad =
        MifareApplicationDirectory.create(
            true,
            1u,
            null,
            mapOf(
                14 to MadAid.fromRaw(0x4811u),
                15 to MadAid.fromRaw(0x4812u),
            ))

    val tag = mockk<MifareClassic>()
    every { tag.authenticateSector(any(), any(), any()) } just runs
    every { tag.writeBlock(any(), any()) } just runs

    mad.writeToMifareClassic(tag, defaultWriteKeyProvider)

    verifySequence {
      tag.authenticateSector(0, madKeyB, MifareKeyType.KeyB)
      tag.writeBlock(1, validSector0.sliceArray(16..31))
      tag.writeBlock(2, validSector0.sliceArray(32..47))
      tag.writeBlock(
          3,
          ubyteArrayOf(
              0xA0u,
              0xA1u,
              0xA2u,
              0xA3u,
              0xA4u,
              0xA5u,
              0x78u,
              0x77u,
              0x88u,
              0xC1u,
              0xB0u,
              0xB1u,
              0xB2u,
              0xB3u,
              0xB4u,
              0xB5u))
    }

    confirmVerified(tag)
  }

  @Test
  fun `mad v2 should write correctly`() {
    val mad =
        MifareApplicationDirectory.create(
            true,
            2u,
            null,
            (1..39)
                .filter { it != 16 }
                .associateWith { MadAid.fromRaw(it.toUByte().inv(), it.toUByte()) })

    val tag = mockk<MifareClassic>()
    every { tag.authenticateSector(any(), any(), any()) } just runs
    every { tag.writeBlock(any(), any()) } just runs

    mad.writeToMifareClassic(tag, defaultWriteKeyProvider)

    verifySequence {
      tag.authenticateSector(0, madKeyB, MifareKeyType.KeyB)
      tag.writeBlock(1, validSector0MoreAids.sliceArray(16..31))
      tag.writeBlock(2, validSector0MoreAids.sliceArray(32..47))
      tag.writeBlock(
          3,
          ubyteArrayOf(
              0xA0u,
              0xA1u,
              0xA2u,
              0xA3u,
              0xA4u,
              0xA5u,
              0x78u,
              0x77u,
              0x88u,
              0xC2u,
              0xB0u,
              0xB1u,
              0xB2u,
              0xB3u,
              0xB4u,
              0xB5u))
      tag.authenticateSector(16, madKeyB, MifareKeyType.KeyB)
      tag.writeBlock(MifareClassic.sectorToBlock(16, 0), validSector16.sliceArray(0..15))
      tag.writeBlock(MifareClassic.sectorToBlock(16, 1), validSector16.sliceArray(16..31))
      tag.writeBlock(MifareClassic.sectorToBlock(16, 2), validSector16.sliceArray(32..47))
      tag.writeBlock(
          MifareClassic.sectorToBlock(16, 3),
          ubyteArrayOf(
              0xA0u,
              0xA1u,
              0xA2u,
              0xA3u,
              0xA4u,
              0xA5u,
              0x78u,
              0x77u,
              0x88u,
              0xC2u,
              0xB0u,
              0xB1u,
              0xB2u,
              0xB3u,
              0xB4u,
              0xB5u))
    }

    confirmVerified(tag)
  }
}
