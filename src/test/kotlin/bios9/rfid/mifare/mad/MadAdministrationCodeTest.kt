package bios9.rfid.mifare.mad

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MadAdministrationCodeTest {
    @Test
    fun `zero should be free`() {
        val ac = MadAdministrationCode.fromApplicationCode(0u)
        assertEquals(MadAdministrationCode.FREE, ac)
        assertEquals(0u.toUByte(), MadAdministrationCode.FREE.applicationCode)
    }

    @Test
    fun `check unknown administration code`() {
        val ac = MadAdministrationCode.fromApplicationCode(0xFFu)
        assertEquals(MadAdministrationCode.UNKNOWN, ac)
        assertEquals(null, MadAdministrationCode.UNKNOWN.applicationCode)
    }
}