package bios9.rfid.mifare.mad

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.rfid.mifare.classic.exceptions.InvalidSectorSize
import bios9.rfid.mifare.mad.exceptions.InvalidMadCrcException
import bios9.rfid.mifare.mad.exceptions.InvalidMadVersionException
import bios9.rfid.mifare.mad.exceptions.MadNotFoundException
import bios9.rfid.mifare.mad.exceptions.NotPersonalizedException
import io.mockk.*
import io.mockk.junit5.MockKExtension
import kotlin.test.*
import kotlin.test.Test

@MockKExtension.CheckUnnecessaryStub
@OptIn(ExperimentalUnsignedTypes::class)
class MifareApplicationDirectoryTest {
    val madKeyA = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u)

    val validSector0 = ubyteArrayOf(
        0x9Du, 0x49u, 0x91u, 0x16u, 0xDEu, 0x28u, 0x02u, 0x00u, 0xE3u, 0x27u, 0x00u, 0x20u, 0x00u, 0x00u, 0x00u, 0x17u,
        0xCDu, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x11u, 0x48u, 0x12u, 0x48u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x78u, 0x77u, 0x88u, 0xC1u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    )

    val validSector0MoreAids = ubyteArrayOf(
        0x9Du, 0x49u, 0x91u, 0x16u, 0xDEu, 0x28u, 0x02u, 0x00u, 0xE3u, 0x27u, 0x00u, 0x20u, 0x00u, 0x00u, 0x00u, 0x17u,
        0x23u, 0x00u, 0x01u, 0xFEu, 0x02u, 0xFDu, 0x03u, 0xFCu, 0x04u, 0xFBu, 0x05u, 0xFAu, 0x06u, 0xF9u, 0x07u, 0xF8u,
        0x08u, 0xF7u, 0x09u, 0xF6u, 0x0Au, 0xF5u, 0x0Bu, 0xF4u, 0x0Cu, 0xF3u, 0x0Du, 0xF2u, 0x0Eu, 0xF1u, 0x0Fu, 0xF0u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x78u, 0x77u, 0x88u, 0xC1u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    )

    val validSector16 = ubyteArrayOf(
        0xD2u, 0x00u, 0x11u, 0xEEu, 0x12u, 0xEDu, 0x13u, 0xECu, 0x14u, 0xEBu, 0x15u, 0xEAu, 0x16u, 0xE9u, 0x17u, 0xE8u,
        0x18u, 0xE7u, 0x19u, 0xE6u, 0x1Au, 0xE5u, 0x1Bu, 0xE4u, 0x1Cu, 0xE3u, 0x1Du, 0xE2u, 0x1Eu, 0xE1u, 0x1Fu, 0xE0u,
        0x20u, 0xDFu, 0x21u, 0xDEu, 0x22u, 0xDDu, 0x23u, 0xDCu, 0x24u, 0xDBu, 0x25u, 0xDAu, 0x26u, 0xD9u, 0x27u, 0xD8u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x78u, 0x77u, 0x88u, 0xC2u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    )

    /**
     * Replaces byte at index in array with specified value.
     */
    fun UByteArray.replaceIndex(index: Int, newValue: UByte): UByteArray =
        this.mapIndexed { i, oldValue ->
            if (index == i) newValue else oldValue
        }.toUByteArray()

    /**
     * Recalculates and replaces CRC value for MAD v1 sector.
     */
    fun UByteArray.recalculateMadV1Crc(): UByteArray {
        require(this.size == 64)
        return this.replaceIndex(16, Crc8Mad.compute(this.sliceArray(17 .. 47)))
    }

    /**
     * Recalculates and replaces CRC value for MAD v2 sector.
     */
    fun UByteArray.recalculateMadV2Crc(): UByteArray {
        require(this.size == 64)
        return this.replaceIndex(0, Crc8Mad.compute(this.sliceArray(1 .. 47)))
    }

    /**
     * Converts MADv1 sector into MADv2 sector by changing version bits.
     */
    fun UByteArray.makeMadV2(): UByteArray {
        require(this.size == 64)
        require(this[57] == 0xC1u.toUByte())
        return this.replaceIndex(57, 0xC2u)
    }

    private fun mockClassic1k(sector0: UByteArray): MifareClassic{
        val tag = mockk<MifareClassic>()
        every { tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA) } just runs
        every { tag.readSector(0) } returns sector0

        return tag
    }

    private fun mockClassic4k(sector0: UByteArray, sector16: UByteArray): MifareClassic{
        val tag = mockk<MifareClassic>()
        every { tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA) } just runs
        every { tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA) } just runs
        every { tag.readSector(0) } returns sector0
        every { tag.readSector(16) } returns sector16

        return tag
    }

    @Test
    fun `valid mad v1 should decode`() {
        val tag = mockClassic1k(validSector0)

        val mad = MifareApplicationDirectory.readFromMifareClassic(tag)
        assertEquals(1u, mad.madVersion)

        verifySequence {
            tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            tag.readSector(0)
        }

        confirmVerified(tag)
    }

    @Test
    fun `missing mad v1 sector should fail`() {
        val tag = mockClassic1k(validSector0)
        every { tag.readSector(0) } throws Exception()

        assertFailsWith<Exception> {
            MifareApplicationDirectory.readFromMifareClassic(tag)
        }
    }

    @Test
    fun `invalid mad sector size should fail`() {
        val tag1 = mockClassic1k(validSector0.take(63).toUByteArray())
        assertFailsWith<InvalidSectorSize> {
            MifareApplicationDirectory.readFromMifareClassic(tag1)
        }

        val tag2 = mockClassic1k((validSector0 + 0u).toUByteArray())
        assertFailsWith<InvalidSectorSize> {
            MifareApplicationDirectory.readFromMifareClassic(tag2)
        }

        val tag3 = mockClassic4k(validSector0.makeMadV2(), validSector16.take(63).toUByteArray())
        assertFailsWith<InvalidSectorSize> {
            MifareApplicationDirectory.readFromMifareClassic(tag3)
        }

        val tag4 = mockClassic4k(validSector0.makeMadV2(), (validSector16 + 0u).toUByteArray())
        assertFailsWith<InvalidSectorSize> {
            MifareApplicationDirectory.readFromMifareClassic(tag4)
        }
    }

    @Test
    fun `unpersonalized card should fail`() {
        // When GPB is 0x69 it indicates an unpersonalized card.
        val tag = mockClassic1k(validSector0.replaceIndex(57, 0x69u))

        assertFailsWith<NotPersonalizedException> {
            MifareApplicationDirectory.readFromMifareClassic(tag)
        }
    }

    @Test
    fun `false mad DA bit should fail`() {
        // First bit of GPB is the DA bit.
        val tag = mockClassic1k(validSector0.replaceIndex(57, 0b01000001u))

        assertFailsWith<MadNotFoundException> {
            MifareApplicationDirectory.readFromMifareClassic(tag)
        }
    }

    @Test
    fun `multi-application bit should be read`() {
        // Second bit of GPB is the MA bit.
        // Check multi-application.
        val maTag = mockClassic1k(validSector0.replaceIndex(57, 0b11000001u))
        assertTrue(MifareApplicationDirectory.readFromMifareClassic(maTag).multiApplicationCard, "Expected multi-application card")

        verifySequence {
            maTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            maTag.readSector(0)
        }

        confirmVerified(maTag)

        // Check single-application.
        val saTag = mockClassic1k(validSector0.replaceIndex(57, 0b10000001u))
        assertFalse(MifareApplicationDirectory.readFromMifareClassic(saTag).multiApplicationCard, "Expected single-application card")

        verifySequence {
            saTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            saTag.readSector(0)
        }

        confirmVerified(saTag)
    }

    @Test
    fun `invalid mad version should fail`() {
        // Final two bits of GPB is the MAD version which must be 1 or 2.
        val tag1 = mockClassic1k(validSector0.replaceIndex(57, 0b11000000u))
        assertFailsWith<InvalidMadVersionException> {
            // 0b00 MAD version bits.
            MifareApplicationDirectory.readFromMifareClassic(tag1)
        }

        val tag2 = mockClassic1k(validSector0.replaceIndex(57, 0b11000011u))
        assertFailsWith<InvalidMadVersionException> {
            // 0b11 MAD version bits.
            MifareApplicationDirectory.readFromMifareClassic(tag2)
        }
    }

    @Test
    fun `invalid mad v1 crc should fail`() {
        // 17th byte in sector 0 is CRC.
        val tag = mockClassic1k(validSector0.replaceIndex(16, 0u))
        assertFailsWith<InvalidMadCrcException> {
            MifareApplicationDirectory.readFromMifareClassic(tag)
        }
    }

    @Test
    fun `check card publisher sector`() {
        // 18th byte in sector 0 is the info byte which contains the CPS pointer.
        // CRC must be recalculated when modifying info byte 17.

        val nullCpsTag = mockClassic1k(validSector0.replaceIndex(17, 0u).recalculateMadV1Crc())
        assertNull(MifareApplicationDirectory.readFromMifareClassic(nullCpsTag).cardPublisherSector)

        verifySequence {
            nullCpsTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            nullCpsTag.readSector(0)
        }

        confirmVerified(nullCpsTag)

        for (cps in 0x01u .. 0x0Fu) {
            val tag = mockClassic1k(validSector0.replaceIndex(17, cps.toUByte()).recalculateMadV1Crc())
            assertEquals(cps.toUByte(), MifareApplicationDirectory.readFromMifareClassic(tag).cardPublisherSector)

            verifySequence {
                tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
                tag.readSector(0)
            }

            confirmVerified(tag)
        }
    }

    @Test
    fun `check invalid mad v1 card publisher sector`() {
        // CPS cannot point to sector 0x10 since that's reserved for MADv2.
        val tag1 = mockClassic1k(validSector0.replaceIndex(17, 0x10u).recalculateMadV1Crc())
        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.readFromMifareClassic(tag1)
        }

        // Mad V1 CPS cannot exceed 15.
        for (info in 0x10u .. 0x3Fu) {
            val tag = mockClassic1k(validSector0.replaceIndex(17, info.toUByte()).recalculateMadV1Crc())
            assertFailsWith<IllegalArgumentException> {
                MifareApplicationDirectory.readFromMifareClassic(tag)
            }
        }
    }

    @Test
    fun `missing mad v2 sector should fail`() {
        val tag = mockClassic4k(validSector0.makeMadV2(), validSector16)
        every { tag.readSector(16) } throws Exception()

        assertFailsWith<Exception> {
            MifareApplicationDirectory.readFromMifareClassic(tag)
        }
    }

    @Test
    fun `valid mad v2 should decode`() {
        val tag = mockClassic4k(validSector0.makeMadV2(), validSector16)

        val mad = MifareApplicationDirectory.readFromMifareClassic(tag)
        assertEquals(2u, mad.madVersion)

        verifySequence {
            tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            tag.readSector(0)
            tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
            tag.readSector(16)
        }

        confirmVerified(tag)
    }

    @Test
    fun `invalid mad v2 crc should fail`() {
        // Replace CRC with 0 for MADv2 sector.
        val tag = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(0, 0u))

        assertFailsWith<InvalidMadCrcException> {
            MifareApplicationDirectory.readFromMifareClassic(tag)
        }
    }

    @Test
    fun `check valid mad v2 cps`() {
        // 2nd byte in sector 16 is the info byte which contains the CPS pointer.

        val nullCpsTag = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(1, 0x0u).recalculateMadV2Crc())
        assertNull(MifareApplicationDirectory.readFromMifareClassic(nullCpsTag).cardPublisherSector)

        verifySequence {
            nullCpsTag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            nullCpsTag.readSector(0)
            nullCpsTag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
            nullCpsTag.readSector(16)
        }

        confirmVerified(nullCpsTag)

        for (cps in 0x01u .. 0x027u) {
            // Skip MADv2 sector.
            if (cps == 0x10u) {
                continue
            }

            val tag = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(1, cps.toUByte()).recalculateMadV2Crc())
            assertEquals(cps.toUByte(), MifareApplicationDirectory.readFromMifareClassic(tag).cardPublisherSector)
        }
    }

    @Test
    fun `invalid mad v2 cps should fail`() {
        // 2nd byte in sector 16 is the info byte which contains the CPS pointer.

        // CPS cannot point at MAD v2 sector 16 (0x10).
        val tag1 = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(1, 0x10u).recalculateMadV2Crc())
        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.readFromMifareClassic(tag1)
        }

        // CPS pointer cannot exceed sector 39.
        for (info in 0x28u .. 0x3Fu) {
            val tag = mockClassic4k(validSector0.makeMadV2(), validSector16.replaceIndex(1, info.toUByte()).recalculateMadV2Crc())
            assertFailsWith<IllegalArgumentException> {
                MifareApplicationDirectory.readFromMifareClassic(tag)
            }
        }
    }

    @Test
    fun `check valid mad v1 applications`() {
        val tag = mockClassic1k(validSector0)

        val mad = MifareApplicationDirectory.readFromMifareClassic(tag)

        assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
        for (sector in 1..13) {
            assertEquals(MadAid.fromAdministrationCode(MadAdministrationCode.FREE), mad.applications[sector])
        }

        // Gallagher AIDs
        assertEquals(MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x11u), mad.applications[14])
        assertEquals(MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x12u), mad.applications[15])

        verifySequence {
            tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            tag.readSector(0)
        }

        confirmVerified(tag)
    }

    @Test
    fun `check more valid mad v1 applications`() {
        val tag = mockClassic1k(validSector0MoreAids)

        val mad = MifareApplicationDirectory.readFromMifareClassic(tag)

        assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
        for (sector in 1..15) {
            assertEquals(MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
        }

        verifySequence {
            tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            tag.readSector(0)
        }

        confirmVerified(tag)
    }

    @Test
    fun `check valid mad v2 applications`() {
        val tag = mockClassic4k(validSector0MoreAids.makeMadV2(), validSector16)

        val mad = MifareApplicationDirectory.readFromMifareClassic(tag)

        assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
        for (sector in 1..38) {
            if (sector == 16) {
                continue // Skip MADv2 sector.
            }
            assertEquals(MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
        }

        verifySequence {
            tag.authenticateSector(0, madKeyA, MifareKeyType.KeyA)
            tag.readSector(0)
            tag.authenticateSector(16, madKeyA, MifareKeyType.KeyA)
            tag.readSector(16)
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
            val mad = MifareApplicationDirectory.create(true, 1u, null, mapOf(
                sector to MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()) // Fill with some AIDs
            ))
            assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
        }

        val madFull = MifareApplicationDirectory.create(true, 1u, null,
            (1..15).associateWith { s ->
                MadAid.fromRaw(s.toUByte().inv(), s.toUByte())
            }
        )

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
            val mad = MifareApplicationDirectory.create(true, 2u, null, mapOf(
                sector to MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()) // Fill with some AIDs.
            ))
            assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
        }

        val madFull = MifareApplicationDirectory.create(true, 2u, null,
            (1..39)
                .filter { s -> s != 16 } // Skip MADv2 sector.
                .associateWith { s ->
                MadAid.fromRaw(s.toUByte().inv(), s.toUByte())
            }
        )
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
            MifareApplicationDirectory.create(true, 1u, null, mapOf(
                0 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)
            ))
        }

        for (sector in 16..100) {
            assertFailsWith<IllegalArgumentException> {
                MifareApplicationDirectory.create(true, 1u, null, mapOf(
                    sector to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)
                ))
            }
        }
    }

    @Test
    fun `check create mad v2 with invalid apps`() {
        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.create(true, 2u, null, mapOf(
                0 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)
            ))
        }

        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.create(true, 2u, null, mapOf(
                16 to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)
            ))
        }

        for (sector in 40..100) {
            assertFailsWith<IllegalArgumentException> {
                MifareApplicationDirectory.create(true, 1u, null, mapOf(
                    sector to MadAid.fromFunction(MadFunctionCluster.FOOD, 0u)
                ))
            }
        }
    }

    @Test
    fun `check mad v1 apps are filled`() {
        val mad = MifareApplicationDirectory.create(true, 1u, null, mapOf())
        assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs")
        assertTrue(mad.applications.all { (_, aid) -> aid == MadAid.fromAdministrationCode(MadAdministrationCode.FREE) }, "Expected all empty apps to be filled with FREE")
    }

    @Test
    fun `check mad v2 apps are filled`() {
        val mad = MifareApplicationDirectory.create(true, 2u, null, mapOf())
        assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs")
        assertTrue(mad.applications.all { (_, aid) -> aid == MadAid.fromAdministrationCode(MadAdministrationCode.FREE) }, "Expected all empty apps to be filled with FREE")
    }
}