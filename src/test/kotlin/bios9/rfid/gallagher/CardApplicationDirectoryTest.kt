package bios9.rfid.gallagher

import bios9.rfid.mifare.classic.MifareClassic
import bios9.rfid.mifare.classic.MifareKeyType
import bios9.rfid.mifare.mad.MifareApplicationDirectory
import io.mockk.*
import io.mockk.junit5.MockKExtension
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

@MockKExtension.ConfirmVerification
@MockKExtension.CheckUnnecessaryStub
@OptIn(ExperimentalUnsignedTypes::class)
class CardApplicationDirectoryTest {
    private val cadKeyA = ubyteArrayOf(0xA0u, 0xA1u, 0xA2u, 0xA3u, 0xA4u, 0xA5u)

    private val validCadSector = ubyteArrayOf(
        0x1Bu, 0x58u, 0x00u, 0x01u, 0xC1u, 0x33u, 0x70u, 0xFDu, 0x13u, 0x38u, 0x0Du, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u,
        0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x78u, 0x77u, 0x88u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u
    )

    private fun mockClassic(sector: Int, data: UByteArray): MifareClassic {
        val tag = mockk<MifareClassic>()
        every { tag.authenticateSector(sector, cadKeyA, MifareKeyType.KeyA) } just runs
        every { tag.readBlock(MifareClassic.sectorToBlock(sector, 0)) } returns data.sliceArray(0 .. 15)
        every { tag.readBlock(MifareClassic.sectorToBlock(sector, 1)) } returns data.sliceArray(16 .. 31)
        every { tag.readBlock(MifareClassic.sectorToBlock(sector, 2)) } returns data.sliceArray(32 .. 47)
        every { tag.readBlock(MifareClassic.sectorToBlock(sector, 3)) } returns data.sliceArray(48 .. 63)

        return tag
    }

    @Test
    fun `valid cad should decode`() {
        val sector = 14
        val tag = mockClassic(sector, validCadSector)

        val cad = CardAppliationDirectory.readFromMifareClassic(tag, sector)

        verifySequence {
            tag.authenticateSector(sector, cadKeyA, MifareKeyType.KeyA)
            tag.readBlock(MifareClassic.sectorToBlock(sector, 0)) // Should start by reading block 3 to get GPB.
            tag.readBlock(MifareClassic.sectorToBlock(sector, 1))
            tag.readBlock(MifareClassic.sectorToBlock(sector, 2))
        }
        confirmVerified(tag)
    }
}