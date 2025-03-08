package bios9.rfid.mifare

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MadAidTest {
    @Test
    fun `create from raw and function cluster code should be consistent`() {
        for (functionClusterCode in UByte.MIN_VALUE..UByte.MAX_VALUE)
            for (applicationCode in UByte.MIN_VALUE..UByte.MAX_VALUE) {
                val fromFunc = MadAid.fromFunction(functionClusterCode.toUByte(), applicationCode.toUByte())
                val fromRaw = MadAid.fromRaw(fromFunc.rawValue)

                // Ensure the fromFunction func assigned the simple properties correctly.
                assertEquals(functionClusterCode.toUByte(), fromFunc.functionClusterCode)
                assertEquals(applicationCode.toUByte(), fromFunc.applicationCode)

                // Ensure the fromRaw func assigned the simple property correctly.
                assertEquals(fromFunc.rawValue, fromFunc.rawValue)

                // Ensure the raw to function cluster code calculation is consistent.
                assertEquals(fromFunc.functionClusterCode, fromRaw.functionClusterCode)
                assertEquals(fromFunc.applicationCode, fromRaw.applicationCode)
            }
    }

    @Test
    fun `unknown function cluster code should show unknown function`() {
        assertEquals("Unknown/Reserved Function Code", MadAid.fromFunction(0x13u, 0u).functionCluster)
    }

    @Test
    fun `administration code should not be present for non-zero function codes`() {
        for (functionClusterCode in 0x01.toUByte()..UByte.MAX_VALUE) {
            assertNull(MadAid.fromFunction(functionClusterCode.toUByte(), 0u).administrationCode)
        }
    }

    @Test
    fun `administration code should be present for zero function codes`() {
        for (applicationCode in UByte.MIN_VALUE..UByte.MAX_VALUE) {
            assertNotNull(MadAid.fromFunction(0u, applicationCode.toUByte()).administrationCode)
        }
    }

    @Test
    fun `zero should be free`() {
        val aid = MadAid.fromRaw(0u)
        assertEquals("Card Administration", aid.functionCluster)
        assertEquals(MadAid.AdministrationCode.FREE, aid.administrationCode)
    }

    @Test
    fun `check known administration codes`() {
        val aid = MadAid.fromRaw(0x4811u)
        assertEquals("Access Control & Security", aid.functionCluster)
    }
}