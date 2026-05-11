package bios9.tapsmith

import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import bios9.tapsmith.rfid.DecodeResult
import bios9.tapsmith.rfid.NfcTagReader
import bios9.tapsmith.rfid.ReadBlock
import bios9.tapsmith.rfid.TagReadResult
import bios9.tapsmith.rfid.TapSmithNative
import bios9.tapsmith.rfid.toHexString
import bios9.tapsmith.ui.theme.TapSmithTheme

class MainActivity : ComponentActivity(), NfcAdapter.ReaderCallback {
    private val tagReader = NfcTagReader()
    private var nfcAdapter: NfcAdapter? = null
    private var screenState by mutableStateOf(AppState())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        screenState = screenState.copy(
            nfcStatus = when {
                nfcAdapter == null -> "NFC is not available on this device."
                nfcAdapter?.isEnabled == false -> "NFC is disabled."
                else -> "Hold a tag near the phone to read it."
            },
            nativeStatus = if (TapSmithNative.isAvailable) {
                "Rust FFI loaded (ABI ${TapSmithNative.abiVersion()})"
            } else {
                "Rust FFI library is not bundled yet."
            },
        )

        enableEdgeToEdge()
        setContent {
            TapSmithTheme {
                TapSmithApp(screenState)
            }
        }
    }

    override fun onResume() {
        super.onResume()
        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or
                NfcAdapter.FLAG_READER_NFC_B or
                NfcAdapter.FLAG_READER_NFC_F or
                NfcAdapter.FLAG_READER_NFC_V or
                NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null,
        )
    }

    override fun onPause() {
        nfcAdapter?.disableReaderMode(this)
        super.onPause()
    }

    override fun onTagDiscovered(tag: Tag) {
        val result = tagReader.read(tag)
        val decodedCredentials = result.credentialCandidates
            .map { candidate -> candidate.toHexString() to TapSmithNative.decodeGallagher(candidate) }
            .filter { (_, decoded) -> decoded is DecodeResult.Success }

        runOnUiThread {
            screenState = screenState.copy(
                nfcStatus = "Read ${result.type} tag.",
                lastTag = result,
                decodedCredentials = decodedCredentials,
            )
        }
    }
}

data class AppState(
    val nfcStatus: String = "Checking NFC...",
    val nativeStatus: String = "Checking Rust FFI...",
    val lastTag: TagReadResult? = null,
    val decodedCredentials: List<Pair<String, DecodeResult>> = emptyList(),
)

@Composable
fun TapSmithApp(state: AppState) {
    Scaffold(modifier = Modifier.fillMaxSize()) { innerPadding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 20.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Header(state)
            }

            val tag = state.lastTag
            if (tag == null) {
                item {
                    EmptyState()
                }
            } else {
                item {
                    TagSummary(tag)
                }
                if (state.decodedCredentials.isNotEmpty()) {
                    item {
                        CredentialList(state.decodedCredentials)
                    }
                }
                if (tag.message != null) {
                    item {
                        StatusCard("Read note", tag.message)
                    }
                }
                items(tag.blocks.take(32)) { block ->
                    BlockRow(block)
                }
            }
        }
    }
}

@Composable
private fun Header(state: AppState) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = "TapSmith",
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.SemiBold,
        )
        StatusCard("NFC", state.nfcStatus)
        StatusCard("Native decoder", state.nativeStatus)
    }
}

@Composable
private fun EmptyState() {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        color = MaterialTheme.colorScheme.surfaceVariant,
        shape = MaterialTheme.shapes.medium,
    ) {
        Text(
            text = "Waiting for a tag",
            modifier = Modifier.padding(20.dp),
            style = MaterialTheme.typography.titleMedium,
        )
    }
}

@Composable
private fun StatusCard(title: String, body: String) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.labelLarge)
            Spacer(Modifier.height(4.dp))
            Text(body, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
private fun TagSummary(tag: TagReadResult) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Tag", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            DetailRow("UID", tag.id.toHexString(":"))
            DetailRow("Type", tag.type)
            DetailRow("Size", tag.sizeBytes?.let { "$it bytes" } ?: "Unknown")
            DetailRow("Tech", tag.techList.joinToString(", "))
            DetailRow("Blocks read", tag.blocks.size.toString())
        }
    }
}

@Composable
private fun CredentialList(credentials: List<Pair<String, DecodeResult>>) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                "Decoded credentials",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
            )
            credentials.forEachIndexed { index, (source, result) ->
                if (index > 0) {
                    HorizontalDivider()
                }
                when (result) {
                    is DecodeResult.Success -> {
                        val credential = result.credential
                        Text(source, fontFamily = FontFamily.Monospace, style = MaterialTheme.typography.bodySmall)
                        DetailRow("Region", "${credential.regionCode} (${credential.regionCodeLetter})")
                        DetailRow("Facility", credential.facilityCode.toString())
                        DetailRow("Card", credential.cardNumber.toString())
                        DetailRow("Issue", credential.issueLevel.toString())
                    }
                    is DecodeResult.Error -> Text("Decode failed: ${result.status}")
                    DecodeResult.Unavailable -> Text("Native decoder unavailable")
                }
            }
        }
    }
}

@Composable
private fun BlockRow(block: ReadBlock) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = "Sector ${block.sector}, block ${block.block}",
                style = MaterialTheme.typography.labelLarge,
            )
            Text(
                text = block.data.toHexString(" "),
                fontFamily = FontFamily.Monospace,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = FontWeight.Medium,
        )
    }
}

@Preview(showBackground = true)
@Composable
fun TapSmithPreview() {
    TapSmithTheme {
        TapSmithApp(
            AppState(
                nfcStatus = "Hold a tag near the phone to read it.",
                nativeStatus = "Rust FFI loaded (ABI 1)",
            )
        )
    }
}
