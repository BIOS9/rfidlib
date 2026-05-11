package bios9.tapsmith.rfid

import android.nfc.Tag
import android.nfc.tech.IsoDep

data class TagReadResult(
    val id: ByteArray,
    val techList: List<String>,
    val type: String,
    val credentials: DecodeResult?,
    val message: String?,
)

class NfcTagReader {
    fun read(tag: Tag): TagReadResult {
        val techList = tag.techList.map { tech -> tech.substringAfterLast('.') }
        val isoDep = IsoDep.get(tag)
        if (isoDep == null) {
            return TagReadResult(
                id = tag.id,
                techList = techList,
                type = "Unsupported",
                credentials = null,
                message = "This tag does not expose ISO-DEP through Android NFC.",
            )
        }

        val credentials = runCatching {
            isoDep.connect()
            isoDep.timeout = maxOf(isoDep.timeout, ISO_DEP_TIMEOUT_MS)
            TapSmithNative.readGallagherDesfire(isoDep)
        }.getOrElse { error ->
            DecodeResult.Error(message = error.message ?: "Failed to read DESFire tag.")
        }.also {
            runCatching { isoDep.close() }
        }

        return TagReadResult(
            id = tag.id,
            techList = techList,
            type = "MIFARE DESFire",
            credentials = credentials,
            message = when (credentials) {
                is DecodeResult.Success -> null
                DecodeResult.Unavailable -> "Rust FFI library is not bundled yet."
                is DecodeResult.Error -> credentials.message ?: "Gallagher credential not found."
            },
        )
    }
}

private const val ISO_DEP_TIMEOUT_MS = 1_500
