package bios9.rfid.gallagher

import bios9.util.HexUtils.hexToUByteArray
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

@OptIn(ExperimentalUnsignedTypes::class)
class Crc16CadTest {
  @Test
  fun `crc should return correct value`() {
    // Tests based on https://github.com/megabug/gallagher-research/blob/master/formats/cad.md
    val testCases =
        listOf(
            "00".hexToUByteArray() to 0x127Bu,
            // Examples from real card and the GitHb page.
            "00 01 C1 33 70 FD 13 38 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                .hexToUByteArray() to 0x1B58u,
            "00 01 00 0D E0 F0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                .hexToUByteArray() to 0x108Eu,
            // Randomly generated and rn throgh python example on GitHb.
            "00 01 C1 33 70 FD 13 38 0D 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
                .hexToUByteArray() to 0x1B58u,
            "BA 7B A7 93 3C 8C 02 76 C0 1C AF 92 44 CB 96 59 5E 6B F3 A1 63 EB FB 17 82 96 D8 BE AE D9 FF 15 5D D0 43 A9 F3 EC 0B 76 E9 C5 40 2A 0C 8D"
                .hexToUByteArray() to 0x199Eu,
            "99 08 8C 9E EA AE 70 B7 19 CE 69 16 23 1D 53 3D B6 04 EC F3 02 8A FE 97 B9 21 23 A1 D1 2E 5F 98 35 B9 DF 70 EB 01 79 5C E6 DD 44 5A 47 97"
                .hexToUByteArray() to 0x0976u,
            "A1 D5 C8 06 CE E8 E1 10 36 FD 54 9A 45 6C CC 02 9B 15 A6 E6 1D 0F F6 44 EB 59 03 3C 47 57 14 A9 7C 88 0A 54 4F 96 83 78 46 5A B7 DC 4C BF"
                .hexToUByteArray() to 0x1E40u,
            "03 B4 ED EA 8B 71 FD 44 56 40 AD F4 B6 B4 F5 DC 0C 04 BD 5D 7B 81 0A 0A 3D 73 AF EF D6 60 CF FA 86 17 FE 65 80 20 F4 58 25 7B DD 29 53 65"
                .hexToUByteArray() to 0x036Eu,
            "F8 C5 75 36 3A 5E 31 84 FE 9B 93 39 0D 11 7B 02 C9 09 FE 63 58 24 07 33 83 FE 7E 2D CE D4 C8 50 07 44 8E A6 B1 72 05 81 7D E9 CA 3F AF E9"
                .hexToUByteArray() to 0x026Du,
            "D9 5C CF 5C 58 2F 4D 2D F7 C9 E3 8E 0E A0 3E 3B 3B 9F 8B 9C 55 13 C2 F0 76 A1 54 96 53 04 F6 F9 78 AF 7A 9E E9 3D 3F BF 69 A3 2B 0C 4B 81"
                .hexToUByteArray() to 0x1B6Cu,
            "E9 A3 CD 12 ED 2F 80 0C 2C 76 52 0A 34 65 FC 3F F7 C3 3E A5 EB DE 1B 7D EE 84 8F C6 3E 6D A6 28 3C 92 57 F8 FF A0 82 15 11 59 61 6B 2D D4"
                .hexToUByteArray() to 0x1DE0u,
            "60 E1 02 3B AC 65 5E AD 01 77 24 A8 96 9A CD 0D A2 8A 14 FC 4B 23 07 E5 4A 16 D0 64 52 FF 10 4E 96 70 08 C4 6C F8 84 CD FC 8C B6 B4 10 E1"
                .hexToUByteArray() to 0x04E2u,
            "20 08 47 8A 53 20 49 29 50 A9 62 57 17 16 67 89 C4 37 B0 96 45 63 42 C8 CD EB CE 00 71 26 FA DD F2 3F E4 B3 5C D6 55 71 7C 8A EC 06 37 90"
                .hexToUByteArray() to 0x0880u,
            "9D B8 41 10 53 42 4B AA DD 3C 67 21 22 A1 D7 1D FB 17 10 2F 47 11 04 37 3B DB 41 9D 71 B9 CA 4D C3 2F E0 52 C4 F1 2B BA 5F E4 CF B6 0A DB"
                .hexToUByteArray() to 0x064Au)

    for ((data, expectedCrc) in testCases) {
      assertEquals(expectedCrc.toUShort(), Crc16Cad.compute(data))
    }
  }
}
