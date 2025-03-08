# rfidlib

A library for interfacing with RFID and access control technologies.

This library was created with Android NFC in mind, but should also work on desktop operating systems.

## Technology Layers

There are several layers of technology in this project, and the idea is that you can combine them to make it easy to perform high level operations on something like an access control RFID card, or you can use each layer separately e.g. if you just want to encode and decode credential data in software.

### RFID Interface

To interact with a real-world RFID tag, an RFID reader/writer is needed. This can be something like a Proxmark3, ACR122u or an Android phone.
My intention is for higher level code to have no dependence on any specific RFID reader/writer. Some parts of the code will require readers/writers that support 125KHz, or 13.56MHz etc., but those are standard technologies and can be implemented by many different readers/writers.
In future I plan to implement concrete reader implementations for the following:
* Proxmark3 (WSL or ProxSpace for Windows)
* ACR122u
* Android Phone
* ESP32 with PN532 or something over the network or serial

I have currently only implemented a small and janky version of the Proxmark3 WSL interface for development.

Note some readers support 13.56MHz, but don't support sending arbitrary data to a tag and only support sending something like ISO 7816-4 APDUs. This is the case for Android and means it won't be possible to talk to all HF cards with an Android phone, but we should be able to do everything that supports ISO 7816-4 APDU either natively like PIV or wrapped like DesFire/Plus. We can also still do Mifare Classic since Android has a separate API for that.

### Card Technology

There are many card technologies like Mifare Classic, Mifare DesFire, HID Prox, PIV, etc.
Even if you have a reader/writer than can physically communicate with the RFID tag, you need to know what data to send to the tag, and how to interpret the data returned from the tag, that's what this layer is for.

NXP provides a library called TapLinx which gives you a high level code API for each of their card technologies like Mifare Plus/Desfire/Classic etc.
The TapLinx library makes it easy to do something like creating a file on a DesFire tag, and have it generate the neccesary bytes to send the card, and also interpret the result.
The TapLinx library is not open-source, and requires a licence. It also doesn't support card technologies that are not from NXP. You can get a copy of the library from NXP and import it into the project if you wish, but due to licencing issues I can't include any of the library resources in this repo.

My goal is to use TapLinx for now, but I'll probably swap it out for something else like libfreefare or nfcjlib.

As a side note, this layer can also be implemented by the RFID interface itself. For example, the proxmark3 already implements a high level interface for most credential types, which removes the need for something TapLinx when using it, but that of course makes this layer reliant on actual hardware so it's still neccesary to have software implementations.

### Application

Applications are the things that actually do something with card technologies. For example, door access control or bus ticketing systems might use DesFire cards.
These applications usually have their own format of how they store data. This layer is intended to provide a high level API for interacting with this application data.

I'm mainly focusing on the Gallagher access control system right now but I'll probably add more later.
I want an easy way to view and create Gallagher credentials on various technologies including Mifare Classic, DesFire, Plus, HID Prox.

## Ramblings

This readme was really hastily written and I'm just trying to get ideas on paper so I can fix it all up later.
This project in general is still very much a work in progress, and doesn't actually do much yet.

## Acknowledgements

* [Proxmark3 Iceman Fork](https://github.com/RfidResearchGroup/proxmark3) - I've used a lot of this code as reference materal for my Kotlin implementation, and I've also been using it as a test oracle (I hope there are no bugs :]).
* [Megabug Gallagher Research](https://github.com/megabug/gallagher-research) - I've based my implementation of the Gallagher stuff on this fantastic research.
