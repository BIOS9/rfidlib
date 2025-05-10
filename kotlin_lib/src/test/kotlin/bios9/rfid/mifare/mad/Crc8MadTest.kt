package bios9.rfid.mifare.mad

import bios9.util.HexUtils.hexToUByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class Crc8MadTest {
  @Test
  fun `crc should return correct value`() {
    // Test cases created by generating random sets of bytes with length of MAD v1 sector 0 data
    // length (31 bytes), and MAD v2 sector 16 data length (47 bytes)
    // and then running each set through the Proxmark3 CRC8Mad code in
    // https://github.com/RfidResearchGroup/proxmark3/blob/master/common/crc.c
    // The first test case is an example from the MAD spec
    // https://www.nxp.com/docs/en/application-note/AN10787.pdf
    val testCases =
        listOf(
            "01 01 08 01 08 01 08 00 00 00 00 00 00 04 00 03 10 03 10 02 10 02 10 00 00 00 00 00 00 11 30"
                .hexToUByteArray() to 0x89u,
            "5D 0A A9 C6 2A E2 BD 2D F1 CD B2 6C E1 9D F6 89 38 DA 1D 91 C6 76 32 CA C6 48 4A A4 75 B7 46"
                .hexToUByteArray() to 0x05u,
            "3A 83 0D E7 B0 FF 77 66 B3 ED 0F E5 D2 55 55 34 13 8A 7A B0 5E 5E 6A BD E3 FD F3 BA A3 05 85"
                .hexToUByteArray() to 0x3Bu,
            "03 3F A2 F6 C0 80 41 55 AE 74 74 45 38 D3 DF CF EA E7 EA 9B CE AD 5A EF 7B 07 81 E4 1B 09 44"
                .hexToUByteArray() to 0x64u,
            "CD 2C DC 1C CC C1 C5 AB 85 A1 99 8B D4 10 00 11 9E 03 A1 8A CC 85 C8 8C E0 00 B7 45 17 07 F6"
                .hexToUByteArray() to 0xE7u,
            "3C 36 B2 2C 5C D3 BC 2D 99 BD 8C FF B2 2E 30 A0 E2 DF 4E 70 CE BF 8F 82 35 43 65 CF 13 06 C2"
                .hexToUByteArray() to 0x78u,
            "EB B8 3C 69 E9 CE 8E 40 38 EA FF AC 11 C4 D9 67 2F 12 E3 2E 98 BF 67 E4 C5 61 1A 5A AA A3 BA"
                .hexToUByteArray() to 0x13u,
            "2A D8 DE 0B 5C C3 70 B5 0E D2 6C 3F D3 C8 D9 5B FC 83 77 09 C3 10 F6 B9 23 B9 44 73 FA 27 55"
                .hexToUByteArray() to 0xDEu,
            "74 3B D3 86 3F 76 3A BE E9 6C 6D 80 04 88 FB 55 73 E2 6D 97 21 A1 AE CB FD 66 DF CC BD 0D 07"
                .hexToUByteArray() to 0x6Du,
            "60 EA 81 4D 3E 8F 05 FE F1 AB 52 44 D3 30 FA 76 8C F1 3D CE D4 50 57 10 B1 7D 10 55 93 E3 79"
                .hexToUByteArray() to 0x74u,
            "8D 2B 76 BF 9D 47 8E C6 91 19 E8 AA ED B3 01 89 BB 9D DA DA 70 3E F9 E0 E7 51 C0 36 F1 44 8A"
                .hexToUByteArray() to 0x31u,
            "54 3D 2B 50 C7 0B F7 0B 2B 80 94 5D BB 07 7E D3 BB AF E1 63 BA 98 D6 4D 64 5E 51 2C 58 08 0E 47 3E 52 A5 8D 92 B2 43 3B 6D 53 02 8C 12 D0 C4"
                .hexToUByteArray() to 0xC8u,
            "77 EE CF 65 1E 46 9C DB 6B C3 06 16 B4 F7 63 1C 6B 07 FD CA 44 19 31 19 7E 87 94 26 F8 D1 DA AD D3 A3 1D 5A 5D 99 A7 DA D0 A4 97 A4 BE 34 4F"
                .hexToUByteArray() to 0x02u,
            "B1 4E 34 69 6C A2 5D 83 A5 F6 A6 4B B1 10 7A 1D 11 BE 15 91 31 3E FE D7 A1 88 B5 54 0F F2 C1 AB FF D8 6D 75 A1 D2 E8 9C 66 E4 9F 0B 35 09 29"
                .hexToUByteArray() to 0x99u,
            "66 DB 7A 27 C7 06 4A ED E4 E0 48 C4 04 38 F5 65 BA 5A B4 FC D6 54 A0 BC A5 B8 70 7E E7 F3 3A 38 37 FC D7 E4 3E E6 9D F1 48 87 E5 8E 81 81 CB"
                .hexToUByteArray() to 0x6Du,
            "58 7A B6 D5 C0 16 2B 29 4B A4 4D D4 42 B0 89 D4 CA C8 29 91 AF BD 7D EE E6 E3 7D C0 17 7B 09 6F 33 6A 47 4C 30 26 A9 46 34 97 12 1C 7D 80 85"
                .hexToUByteArray() to 0xB1u,
            "72 93 F4 F1 D9 27 A2 50 30 2D 7C 98 02 05 BE 13 50 DA 9B 09 12 E3 A6 23 29 A5 F4 80 70 62 7B 61 9F 15 DE 5F 9E CA 36 DE 0C CA FA 63 13 8A A2"
                .hexToUByteArray() to 0x11u,
            "9B 41 39 95 AA C0 7C 55 71 87 48 B8 A0 28 7A 12 73 07 9A 3A CB C0 49 78 92 E5 24 82 7A 57 80 94 24 5B E9 C9 28 BF 05 AE 76 D7 B2 3F F2 26 14"
                .hexToUByteArray() to 0xD0u,
            "20 1C F6 9D A3 EB 4B 85 0C C1 B4 39 C4 64 5B 16 61 14 DC EA F3 B6 9D 40 31 E9 3B 22 2C D5 52 52 21 A4 DC E7 16 0C 48 30 86 2C A4 92 44 92 53"
                .hexToUByteArray() to 0x87u,
            "46 87 A7 B7 19 A2 76 A6 53 1F 8D 8C DD 67 9B 1B AC 35 0E AC B2 82 92 25 47 AA 68 51 09 CA EB C5 20 8F 2E C2 97 F7 03 72 D9 C6 5B 5B 2F 04 BB"
                .hexToUByteArray() to 0xE8u,
            "6E F1 9C 0D CC F4 73 67 BE 62 C4 BA 37 4B AF 0D 8A E6 A1 A7 C5 C8 B9 C7 87 F3 80 EC 42 46 5A B7 06 2A 33 C8 30 92 E8 7E E4 73 FC 1A 5C DA FA"
                .hexToUByteArray() to 0x14u,
        )

    for ((data, expectedCrc) in testCases) {
      assertEquals(expectedCrc.toUByte(), Crc8Mad.compute(data))
    }
  }
}
