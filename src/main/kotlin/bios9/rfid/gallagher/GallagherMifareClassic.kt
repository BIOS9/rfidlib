 package bios9.rfid.gallagher

 import bios9.rfid.gallagher.CardAppliationDirectory
 import bios9.rfid.gallagher.exceptions.CredentialNotFoundException
 import bios9.rfid.mifare.classic.MifareClassic
 import bios9.rfid.mifare.mad.MifareApplicationDirectory
 import co.touchlab.kermit.Logger

class GallagherMifareClassic private constructor () {
    companion object {
        const val GALLAGHER_CAD_AID = 0x4811u // MAD Application ID of Gallagher Card Application Directory.
        const val GALLAGHER_CREDENTIAL_AID = 0x4812u // MAD Application ID of Gallagher Credential.

//        /**
//         * @param mifareApplicationDirectory Existing MAD data, null if none exists. This must be
// provided if overwriting existing MAD applications is not intended.
//         */
//        fun create(mifareApplicationDirectory: MifareApplicationDirectory?, something map of creds
// and the associated sectors): GallagherMifareClassic {
//            // Maybe should use builder pattern for this? instead of factory method like it is ^
//            GallagherMifareClassicBuilder
//                .useTagSize(4k)
//                .useMad(true)
//                .useMad(true, madVersion)
//                .useMad(true, existingMad, madVersion) // or
//                .addExistingMad(myMad) //or
//                .useCad(true)
//                .useCad(true, customCadSector) //or
//                .addCredential(myCred1) // Add it where ever fits
//                .addCredential(myCred1, keya, keyb, accessRights?) // Custom keys
//                .addMes(sector, mesKey) // ? or maybey add a MES class with keys and shit
//                .addCredential(myCred1, sector15, keya, keyb, accessRights?) // Custom sector and
// keys
//                .addExistingSectorKey(15, 0x123456, 0x123213123)
//                .useSectorWriteKey(15, 0x123456, KeyB) // Seems a bit better than ^
//                .useSectorWriteKey(14, 0x123456, KeyB) // Seems a bit better than ^
//        }

        fun readFromTag(mifareClassic: MifareClassic): GallagherMifareClassic {
            Logger.d { "Reading Gallagher credential from Mifare Classic" }

            val mad = MifareApplicationDirectory.readFromMifareClassic(mifareClassic)
            Logger.d { "Valid Mifare Application Directory (MAD) found on tag $mad" }



            val cadSector = mad.applications.entries.firstOrNull { (_, aid) -> aid.rawValue == GALLAGHER_CAD_AID.toUShort() }?.key
            if (cadSector != null) {
                // There is a CAD so we can use it to figure out where the credentials are.
                val cad = CardAppliationDirectory.readFromMifareClassic(mifareClassic, cadSector)
                Logger.d { "Valid Card Application Directory (CAD) found in sector $cadSector - $cad" }

                if (cad.credentials.isEmpty()) {
                    throw CredentialNotFoundException()
                }

            } else {
                // There is no CAD, so we must try to find the credentials in the MAD.
                Logger.d { "Card Application Directory (CAD) not found. Searching for credentials in MAD..." }
                val credentialSectors = mad.applications.entries
                    .filter { (_, app) -> app.rawValue == GALLAGHER_CREDENTIAL_AID.toUShort() }
                    .map { (sector, _) -> sector }
                    .toSet()
                Logger.d { "Found ${credentialSectors.size} Gallagher credentials in MAD. Sectors: $credentialSectors" }

                if (credentialSectors.isEmpty()) {
                    throw CredentialNotFoundException()
                }
            }

            return GallagherMifareClassic()
        }
    }
//    // Need to think about how I want to do this...
//    // Do I want to put methods inside GallagherCredentials like readFromMifareClassic
// writeToMifareClassic readFromMifareDesfire .....
//    // or do I want a class for each credential type. <- probably this one in some way, it's gonna
// end up HUGE if I put all the mifare classic, desfire, prox stuff in one class.
//    // I just need to decide if those classes should actually be objects or just static.
//    // Like should it just be `cred: GallagherCredential = GallagherMifareClassic.read(tag)
//    // or like `cred: GallagherCredential = GallagherMifareClassic(tag).read()
//    // Probably neither actually. If I do it that way, I'll lose all information about how the
// card is laid out since GallagherCredential doesn't store any of that. + One mifare classic can
// have multiple gallagher credentials in it.
//
//    // I think I actually need to do factory methods in here for create() and
// fromTag()/fromMifareClassic()
//    // This class needs to store a set of credentials, which sectors those credentials were in so
// I can regenerate the MAD the same way.
//    // It should also not overwrite other stuff on the card. Like if you read a tag with gallagher
// and NDEF, and then add or update gallagher cred, it should not overwrite the NDEF record and it
// should still be marked in the MAD.
//    // MUST consider that when creating this class from scratch, overwriting MAD would be super
// easy.
//
//    fun writeToTag(mifareClassic: MifareClassic, existing keys) {
//        // Should existing keys be added in the builder?
//        // Kind of nice to be able to write to multiple different tags with different keys without
// having to recreate the object, or is it needed?
//
//        // Check keys and access permissions of all relevant sectors before trying to write pls.
//    }
 }
