# Proxmark Commands

This is a list of useful Proxmark3 commands which were used to modify tags and produce test oracle data.
This file is more of a quick reference for copying and pasting commands quickly while developing this library rather than something that will be useful in isolation.

## Desfire

hf mfdes lsapp -n 0 -t aes

hf mfdes lsfile -n 0 -t aes

hf mfdes auth -n 0 -t aes
hf mfdes auth -n 0 -t aes --aid 112233

hf mfdes createapp --aid 223344 -n 0 -t aes --dstalgo aes --numkeys 1
hf mfdes deleteapp --aid 223344 -n 0 -t aes


hf mfdes createfile --aid 112233 --fid 02 --amode encrypt --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000


hf mfdes createfile --aid 223344 --fid 01 --amode encrypt --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000
hf mfdes createfile --aid 223344 --fid 02 --amode mac --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000
hf mfdes createfile --aid 223344 --fid 03 --amode plain --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000

hf mfdes write --aid 223344 --fid 01 -d 112233445566778899AABBCCDDEEFF --keyno 0 --algo aes --apdu --verbose
hf mfdes write --aid 223344 --fid 02 -d 0102030405060708090A0B0C0D0E0F --keyno 0 --algo aes --apdu --verbose
hf mfdes write --aid 223344 --fid 03 -d F0E0D0C0B0A0908070605040302010 --keyno 0 --algo aes --apdu --verbose

