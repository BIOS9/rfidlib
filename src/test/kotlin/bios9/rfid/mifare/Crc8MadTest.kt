package bios9.rfid.mifare

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class Crc8MadTest {
    @Test
    fun `crc should return correct value`() {
        // Test cases created by generating random sets of bytes with length of MAD v1 sector 0 data length (31 bytes), and MAD v2 sector 16 data length (47 bytes)
        // and then running each set through the Proxmark3 CRC8Mad code in https://github.com/RfidResearchGroup/proxmark3/blob/master/common/crc.c
        // The first test case is an example from the MAD spec https://www.nxp.com/docs/en/application-note/AN10787.pdf
        val testCases = listOf(
            ubyteArrayOf(0x01u, 0x01u, 0x08u, 0x01u, 0x08u, 0x01u, 0x08u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x04u, 0x00u, 0x03u, 0x10u, 0x03u, 0x10u, 0x02u, 0x10u, 0x02u, 0x10u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x00u, 0x11u, 0x30u) to 0x89u,
            ubyteArrayOf(0x5Du, 0xAu, 0xA9u, 0xC6u, 0x2Au, 0xE2u, 0xBDu, 0x2Du, 0xF1u, 0xCDu, 0xB2u, 0x6Cu, 0xE1u, 0x9Du, 0xF6u, 0x89u, 0x38u, 0xDAu, 0x1Du, 0x91u, 0xC6u, 0x76u, 0x32u, 0xCAu, 0xC6u, 0x48u, 0x4Au, 0xA4u, 0x75u, 0xB7u, 0x46u, ) to 0x5u,
            ubyteArrayOf(0x3Au, 0x83u, 0xDu, 0xE7u, 0xB0u, 0xFFu, 0x77u, 0x66u, 0xB3u, 0xEDu, 0xFu, 0xE5u, 0xD2u, 0x55u, 0x55u, 0x34u, 0x13u, 0x8Au, 0x7Au, 0xB0u, 0x5Eu, 0x5Eu, 0x6Au, 0xBDu, 0xE3u, 0xFDu, 0xF3u, 0xBAu, 0xA3u, 0x5u, 0x85u, ) to 0x3Bu,
            ubyteArrayOf(0x3u, 0x3Fu, 0xA2u, 0xF6u, 0xC0u, 0x80u, 0x41u, 0x55u, 0xAEu, 0x74u, 0x74u, 0x45u, 0x38u, 0xD3u, 0xDFu, 0xCFu, 0xEAu, 0xE7u, 0xEAu, 0x9Bu, 0xCEu, 0xADu, 0x5Au, 0xEFu, 0x7Bu, 0x7u, 0x81u, 0xE4u, 0x1Bu, 0x9u, 0x44u, ) to 0x64u,
            ubyteArrayOf(0xCDu, 0x2Cu, 0xDCu, 0x1Cu, 0xCCu, 0xC1u, 0xC5u, 0xABu, 0x85u, 0xA1u, 0x99u, 0x8Bu, 0xD4u, 0x10u, 0x0u, 0x11u, 0x9Eu, 0x3u, 0xA1u, 0x8Au, 0xCCu, 0x85u, 0xC8u, 0x8Cu, 0xE0u, 0x0u, 0xB7u, 0x45u, 0x17u, 0x7u, 0xF6u, ) to 0xE7u,
            ubyteArrayOf(0x3Cu, 0x36u, 0xB2u, 0x2Cu, 0x5Cu, 0xD3u, 0xBCu, 0x2Du, 0x99u, 0xBDu, 0x8Cu, 0xFFu, 0xB2u, 0x2Eu, 0x30u, 0xA0u, 0xE2u, 0xDFu, 0x4Eu, 0x70u, 0xCEu, 0xBFu, 0x8Fu, 0x82u, 0x35u, 0x43u, 0x65u, 0xCFu, 0x13u, 0x6u, 0xC2u, ) to 0x78u,
            ubyteArrayOf(0xEBu, 0xB8u, 0x3Cu, 0x69u, 0xE9u, 0xCEu, 0x8Eu, 0x40u, 0x38u, 0xEAu, 0xFFu, 0xACu, 0x11u, 0xC4u, 0xD9u, 0x67u, 0x2Fu, 0x12u, 0xE3u, 0x2Eu, 0x98u, 0xBFu, 0x67u, 0xE4u, 0xC5u, 0x61u, 0x1Au, 0x5Au, 0xAAu, 0xA3u, 0xBAu, ) to 0x13u,
            ubyteArrayOf(0x2Au, 0xD8u, 0xDEu, 0xBu, 0x5Cu, 0xC3u, 0x70u, 0xB5u, 0xEu, 0xD2u, 0x6Cu, 0x3Fu, 0xD3u, 0xC8u, 0xD9u, 0x5Bu, 0xFCu, 0x83u, 0x77u, 0x9u, 0xC3u, 0x10u, 0xF6u, 0xB9u, 0x23u, 0xB9u, 0x44u, 0x73u, 0xFAu, 0x27u, 0x55u, ) to 0xDEu,
            ubyteArrayOf(0x74u, 0x3Bu, 0xD3u, 0x86u, 0x3Fu, 0x76u, 0x3Au, 0xBEu, 0xE9u, 0x6Cu, 0x6Du, 0x80u, 0x4u, 0x88u, 0xFBu, 0x55u, 0x73u, 0xE2u, 0x6Du, 0x97u, 0x21u, 0xA1u, 0xAEu, 0xCBu, 0xFDu, 0x66u, 0xDFu, 0xCCu, 0xBDu, 0xDu, 0x7u, ) to 0x6Du,
            ubyteArrayOf(0x60u, 0xEAu, 0x81u, 0x4Du, 0x3Eu, 0x8Fu, 0x5u, 0xFEu, 0xF1u, 0xABu, 0x52u, 0x44u, 0xD3u, 0x30u, 0xFAu, 0x76u, 0x8Cu, 0xF1u, 0x3Du, 0xCEu, 0xD4u, 0x50u, 0x57u, 0x10u, 0xB1u, 0x7Du, 0x10u, 0x55u, 0x93u, 0xE3u, 0x79u, ) to 0x74u,
            ubyteArrayOf(0x8Du, 0x2Bu, 0x76u, 0xBFu, 0x9Du, 0x47u, 0x8Eu, 0xC6u, 0x91u, 0x19u, 0xE8u, 0xAAu, 0xEDu, 0xB3u, 0x1u, 0x89u, 0xBBu, 0x9Du, 0xDAu, 0xDAu, 0x70u, 0x3Eu, 0xF9u, 0xE0u, 0xE7u, 0x51u, 0xC0u, 0x36u, 0xF1u, 0x44u, 0x8Au, ) to 0x31u,
            ubyteArrayOf(0x54u, 0x3Du, 0x2Bu, 0x50u, 0xC7u, 0xBu, 0xF7u, 0xBu, 0x2Bu, 0x80u, 0x94u, 0x5Du, 0xBBu, 0x7u, 0x7Eu, 0xD3u, 0xBBu, 0xAFu, 0xE1u, 0x63u, 0xBAu, 0x98u, 0xD6u, 0x4Du, 0x64u, 0x5Eu, 0x51u, 0x2Cu, 0x58u, 0x8u, 0xEu, 0x47u, 0x3Eu, 0x52u, 0xA5u, 0x8Du, 0x92u, 0xB2u, 0x43u, 0x3Bu, 0x6Du, 0x53u, 0x2u, 0x8Cu, 0x12u, 0xD0u, 0xC4u, ) to 0xC8u,
            ubyteArrayOf(0x77u, 0xEEu, 0xCFu, 0x65u, 0x1Eu, 0x46u, 0x9Cu, 0xDBu, 0x6Bu, 0xC3u, 0x6u, 0x16u, 0xB4u, 0xF7u, 0x63u, 0x1Cu, 0x6Bu, 0x7u, 0xFDu, 0xCAu, 0x44u, 0x19u, 0x31u, 0x19u, 0x7Eu, 0x87u, 0x94u, 0x26u, 0xF8u, 0xD1u, 0xDAu, 0xADu, 0xD3u, 0xA3u, 0x1Du, 0x5Au, 0x5Du, 0x99u, 0xA7u, 0xDAu, 0xD0u, 0xA4u, 0x97u, 0xA4u, 0xBEu, 0x34u, 0x4Fu, ) to 0x2u,
            ubyteArrayOf(0xB1u, 0x4Eu, 0x34u, 0x69u, 0x6Cu, 0xA2u, 0x5Du, 0x83u, 0xA5u, 0xF6u, 0xA6u, 0x4Bu, 0xB1u, 0x10u, 0x7Au, 0x1Du, 0x11u, 0xBEu, 0x15u, 0x91u, 0x31u, 0x3Eu, 0xFEu, 0xD7u, 0xA1u, 0x88u, 0xB5u, 0x54u, 0xFu, 0xF2u, 0xC1u, 0xABu, 0xFFu, 0xD8u, 0x6Du, 0x75u, 0xA1u, 0xD2u, 0xE8u, 0x9Cu, 0x66u, 0xE4u, 0x9Fu, 0xBu, 0x35u, 0x9u, 0x29u, ) to 0x99u,
            ubyteArrayOf(0x66u, 0xDBu, 0x7Au, 0x27u, 0xC7u, 0x6u, 0x4Au, 0xEDu, 0xE4u, 0xE0u, 0x48u, 0xC4u, 0x4u, 0x38u, 0xF5u, 0x65u, 0xBAu, 0x5Au, 0xB4u, 0xFCu, 0xD6u, 0x54u, 0xA0u, 0xBCu, 0xA5u, 0xB8u, 0x70u, 0x7Eu, 0xE7u, 0xF3u, 0x3Au, 0x38u, 0x37u, 0xFCu, 0xD7u, 0xE4u, 0x3Eu, 0xE6u, 0x9Du, 0xF1u, 0x48u, 0x87u, 0xE5u, 0x8Eu, 0x81u, 0x81u, 0xCBu, ) to 0x6Du,
            ubyteArrayOf(0x58u, 0x7Au, 0xB6u, 0xD5u, 0xC0u, 0x16u, 0x2Bu, 0x29u, 0x4Bu, 0xA4u, 0x4Du, 0xD4u, 0x42u, 0xB0u, 0x89u, 0xD4u, 0xCAu, 0xC8u, 0x29u, 0x91u, 0xAFu, 0xBDu, 0x7Du, 0xEEu, 0xE6u, 0xE3u, 0x7Du, 0xC0u, 0x17u, 0x7Bu, 0x9u, 0x6Fu, 0x33u, 0x6Au, 0x47u, 0x4Cu, 0x30u, 0x26u, 0xA9u, 0x46u, 0x34u, 0x97u, 0x12u, 0x1Cu, 0x7Du, 0x80u, 0x85u, ) to 0xB1u,
            ubyteArrayOf(0x72u, 0x93u, 0xF4u, 0xF1u, 0xD9u, 0x27u, 0xA2u, 0x50u, 0x30u, 0x2Du, 0x7Cu, 0x98u, 0x2u, 0x5u, 0xBEu, 0x13u, 0x50u, 0xDAu, 0x9Bu, 0x9u, 0x12u, 0xE3u, 0xA6u, 0x23u, 0x29u, 0xA5u, 0xF4u, 0x80u, 0x70u, 0x62u, 0x7Bu, 0x61u, 0x9Fu, 0x15u, 0xDEu, 0x5Fu, 0x9Eu, 0xCAu, 0x36u, 0xDEu, 0xCu, 0xCAu, 0xFAu, 0x63u, 0x13u, 0x8Au, 0xA2u, ) to 0x11u,
            ubyteArrayOf(0x9Bu, 0x41u, 0x39u, 0x95u, 0xAAu, 0xC0u, 0x7Cu, 0x55u, 0x71u, 0x87u, 0x48u, 0xB8u, 0xA0u, 0x28u, 0x7Au, 0x12u, 0x73u, 0x7u, 0x9Au, 0x3Au, 0xCBu, 0xC0u, 0x49u, 0x78u, 0x92u, 0xE5u, 0x24u, 0x82u, 0x7Au, 0x57u, 0x80u, 0x94u, 0x24u, 0x5Bu, 0xE9u, 0xC9u, 0x28u, 0xBFu, 0x5u, 0xAEu, 0x76u, 0xD7u, 0xB2u, 0x3Fu, 0xF2u, 0x26u, 0x14u, ) to 0xD0u,
            ubyteArrayOf(0x20u, 0x1Cu, 0xF6u, 0x9Du, 0xA3u, 0xEBu, 0x4Bu, 0x85u, 0xCu, 0xC1u, 0xB4u, 0x39u, 0xC4u, 0x64u, 0x5Bu, 0x16u, 0x61u, 0x14u, 0xDCu, 0xEAu, 0xF3u, 0xB6u, 0x9Du, 0x40u, 0x31u, 0xE9u, 0x3Bu, 0x22u, 0x2Cu, 0xD5u, 0x52u, 0x52u, 0x21u, 0xA4u, 0xDCu, 0xE7u, 0x16u, 0xCu, 0x48u, 0x30u, 0x86u, 0x2Cu, 0xA4u, 0x92u, 0x44u, 0x92u, 0x53u, ) to 0x87u,
            ubyteArrayOf(0x46u, 0x87u, 0xA7u, 0xB7u, 0x19u, 0xA2u, 0x76u, 0xA6u, 0x53u, 0x1Fu, 0x8Du, 0x8Cu, 0xDDu, 0x67u, 0x9Bu, 0x1Bu, 0xACu, 0x35u, 0xEu, 0xACu, 0xB2u, 0x82u, 0x92u, 0x25u, 0x47u, 0xAAu, 0x68u, 0x51u, 0x9u, 0xCAu, 0xEBu, 0xC5u, 0x20u, 0x8Fu, 0x2Eu, 0xC2u, 0x97u, 0xF7u, 0x3u, 0x72u, 0xD9u, 0xC6u, 0x5Bu, 0x5Bu, 0x2Fu, 0x4u, 0xBBu, ) to 0xE8u,
            ubyteArrayOf(0x6Eu, 0xF1u, 0x9Cu, 0xDu, 0xCCu, 0xF4u, 0x73u, 0x67u, 0xBEu, 0x62u, 0xC4u, 0xBAu, 0x37u, 0x4Bu, 0xAFu, 0xDu, 0x8Au, 0xE6u, 0xA1u, 0xA7u, 0xC5u, 0xC8u, 0xB9u, 0xC7u, 0x87u, 0xF3u, 0x80u, 0xECu, 0x42u, 0x46u, 0x5Au, 0xB7u, 0x6u, 0x2Au, 0x33u, 0xC8u, 0x30u, 0x92u, 0xE8u, 0x7Eu, 0xE4u, 0x73u, 0xFCu, 0x1Au, 0x5Cu, 0xDAu, 0xFAu, ) to 0x14u,
        )

        for ((data, expectedCrc) in testCases) {
            assertEquals(expectedCrc.toUByte(), Crc8Mad.compute(data))
        }
    }
}