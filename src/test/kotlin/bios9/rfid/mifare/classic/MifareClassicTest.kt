package bios9.rfid.mifare.classic

import kotlin.test.assertFailsWith
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MifareClassicTest {
  @Test
  fun `check block to sector`() {
    // 1k sectors
    assertEquals(0, MifareClassic.blockToSector(0))
    assertEquals(0, MifareClassic.blockToSector(1))
    assertEquals(0, MifareClassic.blockToSector(2))
    assertEquals(0, MifareClassic.blockToSector(3))
    assertEquals(1, MifareClassic.blockToSector(4))
    assertEquals(1, MifareClassic.blockToSector(5))
    assertEquals(1, MifareClassic.blockToSector(6))
    assertEquals(1, MifareClassic.blockToSector(7))
    assertEquals(15, MifareClassic.blockToSector(60))
    assertEquals(15, MifareClassic.blockToSector(61))
    assertEquals(15, MifareClassic.blockToSector(62))
    assertEquals(15, MifareClassic.blockToSector(63))

    // 4k sectors
    assertEquals(31, MifareClassic.blockToSector(124))
    assertEquals(31, MifareClassic.blockToSector(125))
    assertEquals(31, MifareClassic.blockToSector(126))
    assertEquals(31, MifareClassic.blockToSector(127))
    for (b in 128..143) {
      assertEquals(32, MifareClassic.blockToSector(b))
    }
    assertEquals(33, MifareClassic.blockToSector(144))
    assertEquals(38, MifareClassic.blockToSector(239))
    for (b in 240..255) {
      assertEquals(39, MifareClassic.blockToSector(b))
    }
  }

  @Test
  fun `check invalid block to sector`() {
    assertFailsWith<IllegalArgumentException> { MifareClassic.blockToSector(-100) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.blockToSector(-1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.blockToSector(256) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.blockToSector(1000) }
  }

  @Test
  fun `check sector to block no offset`() {
    // 1k sectors
    assertEquals(0, MifareClassic.sectorToBlock(0))
    assertEquals(4, MifareClassic.sectorToBlock(1))
    assertEquals(8, MifareClassic.sectorToBlock(2))
    assertEquals(12, MifareClassic.sectorToBlock(3))
    assertEquals(60, MifareClassic.sectorToBlock(15))

    // 4k sectors
    assertEquals(124, MifareClassic.sectorToBlock(31))
    assertEquals(128, MifareClassic.sectorToBlock(32))
    assertEquals(144, MifareClassic.sectorToBlock(33))
    assertEquals(160, MifareClassic.sectorToBlock(34))
    assertEquals(240, MifareClassic.sectorToBlock(39))
  }

  @Test
  fun `check invalid sector to block no offset`() {
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(-100) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(-1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(40) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(100) }
  }

  @Test
  fun `check sector to block offset`() {
    // 1k sectors
    assertEquals(1, MifareClassic.sectorToBlock(0, 1))
    assertEquals(6, MifareClassic.sectorToBlock(1, 2))
    assertEquals(11, MifareClassic.sectorToBlock(2, 3))
    assertEquals(60, MifareClassic.sectorToBlock(15, 0))
    assertEquals(61, MifareClassic.sectorToBlock(15, 1))
    assertEquals(62, MifareClassic.sectorToBlock(15, 2))
    assertEquals(63, MifareClassic.sectorToBlock(15, 3))

    // 4k sectors
    assertEquals(65, MifareClassic.sectorToBlock(16, 1))
    assertEquals(70, MifareClassic.sectorToBlock(17, 2))
    assertEquals(75, MifareClassic.sectorToBlock(18, 3))
    assertEquals(124, MifareClassic.sectorToBlock(31, 0))
    assertEquals(125, MifareClassic.sectorToBlock(31, 1))
    assertEquals(126, MifareClassic.sectorToBlock(31, 2))
    assertEquals(127, MifareClassic.sectorToBlock(31, 3))
    for (o in 0..15) {
      assertEquals(128 + o, MifareClassic.sectorToBlock(32, o))
    }
    for (o in 0..15) {
      assertEquals(144 + o, MifareClassic.sectorToBlock(33, o))
    }
    for (o in 0..15) {
      assertEquals(240 + o, MifareClassic.sectorToBlock(39, o))
    }
  }

  @Test
  fun `check invalid sector to block offset`() {
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(-100, 0) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(-1, 0) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(0, -1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(1, -1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(-1, 1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(-1, -1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(40, 0) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(40, -1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(100, 0) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(15, 4) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(16, 4) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(16, 10) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(31, 4) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(32, -1) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(32, 16) }
    assertFailsWith<IllegalArgumentException> { MifareClassic.sectorToBlock(39, 16) }
  }
}
