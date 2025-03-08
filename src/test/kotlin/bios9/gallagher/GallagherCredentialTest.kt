package bios9.gallagher

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows

@OptIn(ExperimentalStdlibApi::class, ExperimentalUnsignedTypes::class)
class GallagherCredentialTest {

    @Test
    fun `valid credential creation should succeed`() {
        val credential =
            GallagherCredential.create(regionCode = 3u, facilityCode = 100u, cardNumber = 500000u, issueLevel = 2u)

        assertEquals(3u.toUByte(), credential.regionCode)
        assertEquals(100u.toUShort(), credential.facilityCode)
        assertEquals(500000u, credential.cardNumber)
        assertEquals(2u.toUByte(), credential.issueLevel)
    }

    @Test
    fun `region code letter should be calculated correctly`() {
        val testCases = listOf(
            0 to 'A',
            1 to 'B',
            5 to 'F',
            10 to 'K',
            15 to 'P'
        )

        for ((regionCode, expectedLetter) in testCases) {
            val credential = GallagherCredential.create(regionCode.toUByte(), 100u, 500000u, 2u)
            assertEquals(
                expectedLetter,
                credential.regionCodeLetter,
                "Expected $expectedLetter for region code $regionCode"
            )
        }
    }

    @Test
    fun `invalid region code should throw exception`() {
        val exception = assertThrows<IllegalArgumentException> {
            GallagherCredential.create(regionCode = 16u, facilityCode = 100u, cardNumber = 500000u, issueLevel = 2u)
        }
        assertEquals("Invalid region code: 16", exception.message)
    }

    @Test
    fun `invalid card number should throw exception`() {
        val exception = assertThrows<IllegalArgumentException> {
            GallagherCredential.create(regionCode = 2u, facilityCode = 50u, cardNumber = 0x1000000u, issueLevel = 1u)
        }
        assertEquals("Invalid card number: 16777216", exception.message)
    }

    @Test
    fun `invalid issue level should throw exception`() {
        val exception = assertThrows<IllegalArgumentException> {
            GallagherCredential.create(regionCode = 1u, facilityCode = 45u, cardNumber = 123456u, issueLevel = 16u)
        }
        assertEquals("Invalid issue level: 16", exception.message)
    }

    @Test
    fun `toString should correctly format output`() {
        val credential =
            GallagherCredential.create(regionCode = 3u, facilityCode = 45u, cardNumber = 123456u, issueLevel = 2u)
        assertEquals(
            "GallagherCredential(regionCode=3 (D), facilityCode=45, cardNumber=123456, issueLevel=2)",
            credential.toString()
        )
    }

    @Test
    fun `encoding should match expected raw output`() {
        val testCases = listOf(
            GallagherCredential.create(0u, 0u, 0u, 0u) to "A3A3A3A3A3A3A3A3",
            GallagherCredential.create(2u, 64844u, 4123540u, 12u) to "20A1FC120405A359",
            GallagherCredential.create(5u, 24188u, 7402878u, 10u) to "6E1C098B51F4A38B",
            GallagherCredential.create(13u, 32643u, 1224475u, 1u) to "61872CCACE6CA3B9",
            GallagherCredential.create(14u, 25487u, 3151704u, 9u) to "82391444805CA3E4",
            GallagherCredential.create(3u, 11803u, 1390761u, 5u) to "CE35CE746C80A3F2",
            GallagherCredential.create(11u, 35851u, 4243243u, 3u) to "5AD5C9078F81A39E",
            GallagherCredential.create(1u, 38766u, 4561877u, 7u) to "A807CAC3F6F1A31C",
            GallagherCredential.create(8u, 64470u, 8299404u, 8u) to "FEF01BD22205A398",
            GallagherCredential.create(9u, 59145u, 4110319u, 14u) to "206EEE8DAA3CA35B",
            GallagherCredential.create(15u, 65535u, 16777215u, 15u) to "909090E32E05A390"
        )

        for ((credential, expectedHex) in testCases) {
            val encodedBytes = credential.encode()
            val encodedHex = encodedBytes.joinToString("") { it.toHexString(HexFormat.UpperCase) }

            assertEquals(expectedHex, encodedHex, "Encoding failed for $credential")
        }
    }

    @Test
    fun `decoding raw data should produce correct credential`() {
        val testCases = listOf(
            "A3A3A3A3A3A3A3A3" to GallagherCredential.create(0u, 0u, 0u, 0u),
            "20A1FC120405A359" to GallagherCredential.create(2u, 64844u, 4123540u, 12u),
            "6E1C098B51F4A38B" to GallagherCredential.create(5u, 24188u, 7402878u, 10u),
            "61872CCACE6CA3B9" to GallagherCredential.create(13u, 32643u, 1224475u, 1u),
            "82391444805CA3E4" to GallagherCredential.create(14u, 25487u, 3151704u, 9u),
            "CE35CE746C80A3F2" to GallagherCredential.create(3u, 11803u, 1390761u, 5u),
            "5AD5C9078F81A39E" to GallagherCredential.create(11u, 35851u, 4243243u, 3u),
            "A807CAC3F6F1A31C" to GallagherCredential.create(1u, 38766u, 4561877u, 7u),
            "FEF01BD22205A398" to GallagherCredential.create(8u, 64470u, 8299404u, 8u),
            "206EEE8DAA3CA35B" to GallagherCredential.create(9u, 59145u, 4110319u, 14u),
            "909090E32E05A390" to GallagherCredential.create(15u, 65535u, 16777215u, 15u)
        )

        for ((hexInput, expectedCredential) in testCases) {
            val rawBytes = hexInput.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
            val decodedCredential = GallagherCredential.decode(rawBytes.toUByteArray())

            assertEquals(expectedCredential.regionCode, decodedCredential.regionCode)
            assertEquals(expectedCredential.facilityCode, decodedCredential.facilityCode)
            assertEquals(expectedCredential.cardNumber, decodedCredential.cardNumber)
            assertEquals(expectedCredential.issueLevel, decodedCredential.issueLevel)
        }
    }

    @Test
    fun `encoding and then decoding should return original credential`() {
        for (rc in 0u..0x0Fu step 2)
            for (fc in 0u..0xFFFFu step 500)
                for (cn in 0u..0xFFFFFFu step 2000)
                    for (il in 0u..0x0Fu step 3) {
                        val credential = GallagherCredential.create(rc.toUByte(), fc.toUShort(), cn, il.toUByte())
                        val encoded = credential.encode()
                        val decoded = GallagherCredential.decode(encoded)

                        assertEquals(credential.regionCode, decoded.regionCode)
                        assertEquals(credential.facilityCode, decoded.facilityCode)
                        assertEquals(credential.cardNumber, decoded.cardNumber)
                        assertEquals(credential.issueLevel, decoded.issueLevel)
                    }
    }
}