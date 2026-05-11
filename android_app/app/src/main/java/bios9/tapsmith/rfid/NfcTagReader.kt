package bios9.tapsmith.rfid

import android.nfc.Tag
import android.nfc.tech.IsoDep
import android.nfc.tech.MifareClassic

data class ReadBlock(
    val sector: Int,
    val block: Int,
    val data: ByteArray,
) {
    override fun equals(other: Any?): Boolean =
        other is ReadBlock &&
            sector == other.sector &&
            block == other.block &&
            data.contentEquals(other.data)

    override fun hashCode(): Int =
        31 * (31 * sector + block) + data.contentHashCode()
}

data class TagReadResult(
    val id: ByteArray,
    val techList: List<String>,
    val type: String,
    val sizeBytes: Int?,
    val blocks: List<ReadBlock>,
    val message: String?,
) {
    val credentialCandidates: List<ByteArray> =
        blocks.mapNotNull { block ->
            if (block.sector != DEFAULT_GALLAGHER_CREDENTIAL_SECTOR || !block.hasInvertedCredentialPrefix()) {
                null
            } else {
                block.data.copyOfRange(0, GALLAGHER_CREDENTIAL_LENGTH)
            }
        }
}

class NfcTagReader {
    fun read(tag: Tag): TagReadResult {
        val techList = tag.techList.map { tech -> tech.substringAfterLast('.') }
        val mifare = MifareClassic.get(tag)
        if (mifare == null) {
            return TagReadResult(
                id = tag.id,
                techList = techList,
                type = if (IsoDep.get(tag) != null) "ISO-DEP" else "Unsupported",
                sizeBytes = null,
                blocks = emptyList(),
                message = "This tag does not expose MIFARE Classic through Android NFC.",
            )
        }

        return runCatching {
            mifare.connect()
            val blocks = mutableListOf<ReadBlock>()
            for (sector in 0 until mifare.sectorCount) {
                val authenticated =
                    mifare.authenticateSectorWithKeyA(sector, MifareClassic.KEY_DEFAULT) ||
                        mifare.authenticateSectorWithKeyA(
                            sector,
                            MifareClassic.KEY_MIFARE_APPLICATION_DIRECTORY,
                        ) ||
                        mifare.authenticateSectorWithKeyA(sector, MifareClassic.KEY_NFC_FORUM)

                if (authenticated) {
                    val firstBlock = mifare.sectorToBlock(sector)
                    for (offset in 0 until mifare.getBlockCountInSector(sector)) {
                        val block = firstBlock + offset
                        blocks += ReadBlock(
                            sector = sector,
                            block = block,
                            data = mifare.readBlock(block),
                        )
                    }
                }
            }

            TagReadResult(
                id = tag.id,
                techList = techList,
                type = mifareTypeName(mifare.type),
                sizeBytes = mifare.size,
                blocks = blocks,
                message = if (blocks.isEmpty()) {
                    "No sectors could be authenticated with common keys."
                } else {
                    null
                },
            )
        }.getOrElse { error ->
            TagReadResult(
                id = tag.id,
                techList = techList,
                type = mifareTypeName(mifare.type),
                sizeBytes = mifare.size,
                blocks = emptyList(),
                message = error.message ?: "Failed to read tag.",
            )
        }.also {
            runCatching { mifare.close() }
        }
    }

    private fun mifareTypeName(type: Int): String =
        when (type) {
            MifareClassic.TYPE_CLASSIC -> "MIFARE Classic"
            MifareClassic.TYPE_PLUS -> "MIFARE Plus"
            MifareClassic.TYPE_PRO -> "MIFARE Pro"
            else -> "MIFARE Classic compatible"
        }
}

private const val DEFAULT_GALLAGHER_CREDENTIAL_SECTOR = 15
private const val GALLAGHER_CREDENTIAL_LENGTH = 8

private fun ReadBlock.hasInvertedCredentialPrefix(): Boolean =
    data.size >= GALLAGHER_CREDENTIAL_LENGTH * 2 &&
        (0 until GALLAGHER_CREDENTIAL_LENGTH).all { index ->
            data[index].toInt() == data[index + GALLAGHER_CREDENTIAL_LENGTH].toInt().inv().toByte().toInt()
        }
