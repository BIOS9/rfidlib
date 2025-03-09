package bios9.rfid.mifare.mad

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MadAidTest {
    @Test
    fun `create from raw methods should be consistent`() {
        for (functionClusterCode in UByte.MIN_VALUE..UByte.MAX_VALUE)
            for (applicationCode in UByte.MIN_VALUE..UByte.MAX_VALUE) {
                val fromRawBytes = MadAid.fromRaw(functionClusterCode.toUByte(), applicationCode.toUByte())
                val fromRaw = MadAid.fromRaw(fromRawBytes.rawValue)

                // Ensure the fromFunction func assigned the simple properties correctly.
                assertEquals(functionClusterCode.toUByte(), fromRawBytes.functionClusterCode)
                assertEquals(applicationCode.toUByte(), fromRawBytes.applicationCode)

                // Ensure the fromRaw func assigned the simple property correctly.
                assertEquals(fromRawBytes.rawValue, fromRawBytes.rawValue)

                // Ensure the raw to function cluster code calculation is consistent.
                assertEquals(fromRawBytes.functionClusterCode, fromRaw.functionClusterCode)
                assertEquals(fromRawBytes.applicationCode, fromRaw.applicationCode)
            }
    }

    @Test
    fun `unknown function cluster code should be reserved`() {
        assertEquals(MadFunctionCluster.RESERVED, MadAid.fromRaw(0x13u, 0u).functionCluster)
    }

    @Test
    fun `administration code should not be present for non-zero function codes`() {
        for (functionClusterCode in 0x01.toUByte()..UByte.MAX_VALUE) {
            assertNull(MadAid.fromRaw(functionClusterCode.toUByte(), 0u).administrationCode)
        }
    }

    @Test
    fun `administration code should be present for zero function codes`() {
        for (applicationCode in UByte.MIN_VALUE..UByte.MAX_VALUE) {
            val aid = MadAid.fromRaw(0u, applicationCode.toUByte())
            assertNotNull(aid.administrationCode)
        }
    }

    @Test
    fun `check equals`() {
        val expected = MadAid.fromRaw(0x4811u)

        val fromRaw = MadAid.fromRaw(0x4811u)
        val fromRawBytes = MadAid.fromRaw(0x48u, 0x11u)
        val fromFunction = MadAid.fromFunction(MadFunctionCluster.ACCESS_CONTROL_SECURITY_48, 0x11u)

        assertNotSame(expected, fromRaw)
        assertNotSame(expected, fromRawBytes)
        assertNotSame(expected, fromFunction)

        assertEquals(expected, expected)
        assertEquals(expected, fromRaw)
        assertEquals(expected, fromRawBytes)
        assertEquals(expected, fromFunction)

        assertEquals(expected.hashCode(), expected.hashCode())
        assertEquals(expected.hashCode(), fromFunction.hashCode())
        assertEquals(expected.hashCode(), fromRaw.hashCode())
        assertEquals(expected.hashCode(), fromRawBytes.hashCode())
    }

    @Test
    fun `check not equals`() {
        val aid = MadAid.fromRaw(0x4811u)
        val aid2 = MadAid.fromRaw(0x4812u)

        assertNotEquals(aid, aid2)
        assertNotEquals(aid.hashCode(), aid2.hashCode())

        assertNotEquals(aid, null)
        assertNotEquals(aid, "Test")
    }

    @Test
    fun `create from admin code`() {
        val aid = MadAid.fromAdministrationCode(MadAdministrationCode.CARDHOLDER_INFO)
        assertEquals(0u.toUByte(), aid.functionClusterCode)
        assertEquals(MadFunctionCluster.CARD_ADMINISTRATION, aid.functionCluster)
    }
}