package bios9.rfid.mifare.mad

import bios9.rfid.mifare.mad.exceptions.*
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.fail
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.math.truncate
import kotlin.test.*

@OptIn(ExperimentalUnsignedTypes::class)
class MifareApplicationDirectoryTest {
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

    @Test
    fun `valid mad v1 should decode`() {
        MifareApplicationDirectory.decode(validSector0)
    }

    @Test
    fun `invalid mad sector size should fail`() {
        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.decode(UByteArray(63))
        }

        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.decode(UByteArray(65))
        }

        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.decode(UByteArray(64), UByteArray(63))
        }

        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.decode(UByteArray(64), UByteArray(65))
        }
    }

    @Test
    fun `unpersonalized card should fail`() {
        val sector0 = validSector0.copyOf()
        // When GPB is 0x69 it indicates an unpersonalized card.
        sector0[57] = 0x69u

        assertFailsWith<NotPersonalizedException> {
            MifareApplicationDirectory.decode(sector0)
        }
    }

    @Test
    fun `false mad DA bit should fail`() {
        val sector0 = validSector0.copyOf()
        // First bit of GPB is the DA bit.
        sector0[57] = 0b01000001u

        assertFailsWith<MadNotFoundException> {
            MifareApplicationDirectory.decode(sector0)
        }
    }

    @Test
    fun `multi-application bit should be read`() {
        val sector0 = validSector0.copyOf()
        // Second bit of GPB is the MA bit.
        sector0[57] = 0b11000001u
        assertTrue(MifareApplicationDirectory.decode(sector0).multiApplicationCard, "Expected multi-application card")
        sector0[57] = 0b10000001u
        assertFalse(MifareApplicationDirectory.decode(sector0).multiApplicationCard, "Expected single-application card")
    }

    @Test
    fun `invalid mad version should fail`() {
        val sector0 = validSector0.copyOf()
        // Final two bits of GPB is the MAD version which must be 1 or 2.
        sector0[57] = 0b11000000u
        assertFailsWith<InvalidMadVersionException> {
            MifareApplicationDirectory.decode(sector0)
        }
        sector0[57] = 0b11000011u
        assertFailsWith<InvalidMadVersionException> {
            MifareApplicationDirectory.decode(sector0)
        }
    }

    @Test
    fun `invalid mad v1 crc should fail`() {
        val sector0 = validSector0.copyOf()
        // 17th byte in sector 0 is CRC/
        sector0[16] = 0u
        assertFailsWith<InvalidMadCrcException> {
            MifareApplicationDirectory.decode(sector0)
        }
    }

    @Test
    fun `check card publisher sector`() {
        val sector0 = validSector0.copyOf()
        // 18th byte in sector 0 is the info byte which contains the CPS pointer.
        sector0[17] = 0x05u
        sector0[16] = Crc8Mad.compute(sector0.sliceArray(17..47)) // Need to recalculate CRC when modifying this byte.
        assertEquals(0x05u.toUByte(), MifareApplicationDirectory.decode(sector0).cardPublisherSector)

        sector0[17] = 0u
        sector0[16] = Crc8Mad.compute(sector0.sliceArray(17..47))
        assertNull(MifareApplicationDirectory.decode(sector0).cardPublisherSector)

        sector0[17] = 0x0Fu
        sector0[16] = Crc8Mad.compute(sector0.sliceArray(17..47)) // Need to recalculate CRC when modifying this byte.
        assertEquals(0x0Fu.toUByte(), MifareApplicationDirectory.decode(sector0).cardPublisherSector)
    }

    @Test
    fun `check invalid mad v1 card publisher sector`() {
        val sector0 = validSector0.copyOf()
        // 18th byte in sector 0 is the info byte which contains the CPS pointer.
        sector0[17] = 0x10u
        sector0[16] = Crc8Mad.compute(sector0.sliceArray(17..47)) // Need to recalculate CRC when modifying this byte.
        assertFailsWith<InvalidMadInfoByteException> {
            MifareApplicationDirectory.decode(sector0)
        }

        // Mad V1 CPS cannot exceed 15.
        for (info in 0x10u .. 0x3Fu) {
            sector0[17] = info.toUByte()
            sector0[16] = Crc8Mad.compute(sector0.sliceArray(17..47)) // Need to recalculate CRC when modifying this byte.
            assertFailsWith<InvalidMadInfoByteException> {
                MifareApplicationDirectory.decode(sector0)
            }
        }
    }

    @Test
    fun `missing mad v2 sector should fail`() {
        val sector0 = validSector0.copyOf()
        // Set GPB to indicate MAD v2.
        sector0[57] = 0b11000010u
        assertFailsWith<IllegalArgumentException> {
            MifareApplicationDirectory.decode(sector0)
        }
    }

    @Test
    fun `valid mad v2 should decode`() {
        val sector0 = validSector0.copyOf()
        val sector16 = validSector16.copyOf()

        // Set GPB in sector 0 to indicate MAD v2.
        sector0[57] = 0b11000010u
        MifareApplicationDirectory.decode(sector0, sector16)
    }

    @Test
    fun `invalid mad v2 crc should fail`() {
        val sector0 = validSector0.copyOf()
        val sector16 = validSector16.copyOf()

        // Set GPB in sector 0 to indicate MAD v2.
        sector0[57] = 0b11000010u

        sector16[0] = 0u // Change CRC
        assertFailsWith<InvalidMadCrcException> {
            MifareApplicationDirectory.decode(sector0, sector16)
        }
    }

    @Test
    fun `check valid mad v2 cps`() {
        val sector0 = validSector0.copyOf()
        val sector16 = validSector16.copyOf()

        // Set GPB in sector 0 to indicate MAD v2.
        sector0[57] = 0b11000010u
        MifareApplicationDirectory.decode(sector0, sector16)

        // 2nd byte in sector 16 is the info byte which contains the CPS pointer.
        sector16[1] = 0x05u
        sector16[0] = Crc8Mad.compute(sector16.sliceArray(1..47)) // Need to recalculate CRC when modifying this byte.
        assertEquals(0x05u.toUByte(), MifareApplicationDirectory.decode(sector0, sector16).cardPublisherSector)

        sector16[1] = 0x11u
        sector16[0] = Crc8Mad.compute(sector16.sliceArray(1..47)) // Need to recalculate CRC when modifying this byte.
        assertEquals(0x11u.toUByte(), MifareApplicationDirectory.decode(sector0, sector16).cardPublisherSector)

        sector16[1] = 0u
        sector16[0] = Crc8Mad.compute(sector16.sliceArray(1..47))
        assertNull(MifareApplicationDirectory.decode(sector0, sector16).cardPublisherSector)

        sector16[1] = 0x27u
        sector16[0] = Crc8Mad.compute(sector16.sliceArray(1..47)) // Need to recalculate CRC when modifying this byte.
        assertEquals(0x27u.toUByte(), MifareApplicationDirectory.decode(sector0, sector16).cardPublisherSector)
    }

    @Test
    fun `invalid mad v2 cps should fail`() {
        val sector0 = validSector0.copyOf()
        val sector16 = validSector16.copyOf()

        // Set GPB in sector 0 to indicate MAD v2.
        sector0[57] = 0b11000010u

        // 2nd byte in sector 16 is the info byte which contains the CPS pointer.
        // CPS cannot point at MAD v2 sector 16 (0x10).
        sector16[1] = 0x10u
        sector16[0] = Crc8Mad.compute(sector16.sliceArray(1..47)) // Need to recalculate CRC when modifying this byte.
        assertFailsWith<InvalidMadInfoByteException> {
            MifareApplicationDirectory.decode(sector0, sector16)
        }

        // CPS pointer cannot exceed sector 39.
        for (info in 0x28u .. 0x3Fu) {
            sector16[1] = info.toUByte()
            sector16[0] = Crc8Mad.compute(sector16.sliceArray(1..47)) // Need to recalculate CRC when modifying this byte.
            assertFailsWith<InvalidMadInfoByteException> {
                MifareApplicationDirectory.decode(sector0, sector16)
            }
        }
    }

    @Test
    fun `check valid mad v1 applications`() {
        val sector0 = validSector0.copyOf()
        val mad = MifareApplicationDirectory.decode(sector0)

        assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
        for (sector in 1..13) {
            assertEquals(MadAid.fromAdministrationCode(MadAdministrationCode.FREE), mad.applications[sector])
        }

        // Gallagher AIDs
        assertEquals(MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x11u), mad.applications[14])
        assertEquals(MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x12u), mad.applications[15])
    }

    @Test
    fun `check more valid mad v1 applications`() {
        val sector0 = validSector0MoreAids.copyOf()
        val mad = MifareApplicationDirectory.decode(sector0)

        assertEquals(15, mad.applications.size, "Expected 15 MADv1 sector AIDs.")
        for (sector in 1..15) {
            assertEquals(MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
        }
    }

    @Test
    fun `check valid mad v2 applications`() {
        val sector0 = validSector0MoreAids.copyOf()
        val sector16 = validSector16.copyOf()

        // Set GPB in sector 0 to indicate MAD v2.
        sector0[57] = 0b11000010u

        val mad = MifareApplicationDirectory.decode(sector0, sector16)

        assertEquals(38, mad.applications.size, "Expected 38 MADv2 sector AIDs.")
        for (sector in 1..38) {
            if (sector == 16) {
                continue // Skip MADv2 sector.
            }
            assertEquals(MadAid.fromRaw(sector.toUByte().inv(), sector.toUByte()), mad.applications[sector])
        }
    }
}