package bios9.rfid.mifare.mad

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class MadFunctionClusterTest {
    @Test
    fun `zero should be card admin`() {
        val fc = MadFunctionCluster.fromFunctionClusterCode(0u)
        assertEquals(MadFunctionCluster.CARD_ADMINISTRATION, fc)
        assertEquals(0u.toUByte(), MadFunctionCluster.CARD_ADMINISTRATION.functionClusterCode)
    }

    @Test
    fun `check reserved function cluster`() {
        val fc = MadFunctionCluster.fromFunctionClusterCode(0x13u)
        assertEquals(MadFunctionCluster.RESERVED, fc)
        assertEquals(null, MadFunctionCluster.RESERVED.functionClusterCode)
    }
}