import bios9.pm3wsl.Pm3WslWrapper
import com.nxp.nfclib.LibraryManager
import com.nxp.nfclib.ProtocolDetails
import com.nxp.nfclib.desfire.DESFireFactory
import com.nxp.nfclib.interfaces.IApduHandler
import com.nxp.nfclib.interfaces.IReader

/*

NOTES:

The goal here is to make __MODULAR__ bits that handle each part of this complex system.

Gallagher lib:
    Depends on:
        A Mifare Classic provider
        A Mifare Desfire provider
        A LF prox provider
        A Mifare Plus provider
    Those dependencies are meant to be abstract. I don't want gallagher lib to depend on TapLinx or anything because that will make it hard af to swap out later,
    and taplinx seems to be a bit funky with licences and stuff. Might not want to use it.
    Another thing, I could actually directly use the proxmark 3 as both a reader AND a provider.

Mifare Desfire provider:
    Could be implemented by any of the following:
        TapLinx with some underlying reader
        TapLinx android
        Proxmark3 directly with "hf mfdes" commands
    Again, try to avoid making these modules depend directly on a specific reader.

Reader:
    Could be implemented by any of the following:
        Remote ESP32 with a PN532
        Proxmark
        ACR122u
        Android phone
        Networked android phone B-)
    Obviously some readers will support more features. E.g. android can only send ISO wrapped commands and no LF etc.

None of these bits should depend on a concrete implementation of another bit. They should all depend on an abstract implementation! (Dependency inversion)
I want to be able to plug any bit into any other bit later. Like lets read a gallagher desfire card with TapLinx through the proxmark, or lets read a gallagher mifare plus card with a networked android phone using libfreefare etc.

TODO: Clean up proxmark wrapper and make it faster. It doesn't need to close the whole WSL and PM3 connection for each command. It can just open it once.
TODO: Implement my own reader interface that does NOT have anything to do with taplinx. I'll make concrete implementations for proxmark, acr122u, android local and android remote.
TODO: Implement some other readers ^
TODO: Create interfaces for different credential types. E.g. mifare classic, desfire, plus, HID prox, etc.
TODO: implement concrete class (wrapper in the case of taplinx) for credential types. E.g. taplinx desfire, or libfreefare desfire, or my own desfire etc. These should depend on my own reader interface.
TODO: make gallagher stuff depend on those abstract interfaces for credential types. So it can operate completely oblivious to what underlying library or reader it's using!
TODO: probably add some logging and better error handling or something
TODO: add tests. Can easily mock the reader and the ensure that whatever desfire implementation works the same as taplinx.
 */



@OptIn(ExperimentalStdlibApi::class)
fun main() {
    val pm3 = bios9.pm3wsl.Pm3WslWrapper(wslDistro = "Ubuntu-24.04")
   // val res = pm3.tranceive(byteArrayOf(0x90.toByte(), 0x60, 0x00, 0x00, 0x00))

    val libraryManager = LibraryManager()
    libraryManager.registerJavaApp("InspireJavaLicense.txt")

    libraryManager.setApduHandler(test())
    val des = DESFireFactory.getInstance().getDESFireEV2(libraryManager.supportModules)
    val reader = des.reader.connect()
    println("Uid: ${des.uid.toHexString()}")
//    val sig = des.readSignature()
//    println("Signature ${sig.toHexString()}")

    des.selectApplication(0)
    val ids = des.applicationIDs
    println("Application IDs: ${ids.joinToString("\n") { it.toHexString() }}")
}

class test (
    private val reader : Pm3TaplinxReader = Pm3TaplinxReader()
) : IApduHandler {
    override fun apduExchange(p0: ByteArray?): ByteArray {
        return reader.transceive(p0);
    }

    override fun getReader(): IReader {
        return reader
    }
}

class Pm3TaplinxReader (
    val pm3: Pm3WslWrapper = Pm3WslWrapper(wslDistro = "Ubuntu-24.04")
): IReader {
    override fun connect() {
        pm3.ping()
    }

    override fun close() {

    }

    override fun isConnected(): Boolean {
        try {
            pm3.ping()
            return true
        } catch (_: Exception) {
            return false
        }
    }

    override fun setTimeout(p0: Long) {
        TODO("Not yet implemented")
    }

    override fun getTimeout(): Long {
        TODO("Not yet implemented")
    }

    override fun transceive(p0: ByteArray?): ByteArray {
        if (p0 == null) {
            return byteArrayOf()
        }
        val result = pm3.tranceive(p0) ?: return byteArrayOf()
        return result
    }

    override fun getProtocolDetails(): ProtocolDetails {
        val details = pm3.getTagDetails()

        val protocolDetails = ProtocolDetails()
        protocolDetails.uid = details.uid
        protocolDetails.atqa = details.atqa
        protocolDetails.sak = details.sak.toShort()

        return protocolDetails
    }

}