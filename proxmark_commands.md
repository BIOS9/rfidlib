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


hf mfdes createfile --aid 222222 --fid 01 --amode encrypt --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes --apdu --verbose


hf mfdes createfile --aid 223344 --fid 01 --amode encrypt --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000
hf mfdes createfile --aid 223344 --fid 02 --amode mac --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000
hf mfdes createfile --aid 223344 --fid 03 --amode plain --rrights key0 --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes -k 00000000000000000000000000000000

hf mfdes write --aid 223344 --fid 01 -d 112233445566778899AABBCCDDEEFF --keyno 0 --algo aes --apdu --verbose
hf mfdes write --aid 223344 --fid 02 -d 0102030405060708090A0B0C0D0E0F --keyno 0 --algo aes --apdu --verbose
hf mfdes write --aid 223344 --fid 03 -d F0E0D0C0B0A0908070605040302010 --keyno 0 --algo aes --apdu --verbose


hf mfdes createapp --aid 333333 --dstalgo aes --numkeys 1 -n 0 -t aes --apdu --verbose                                                                                                                                                    
hf mfdes createfile --aid 333333 --fid 01 --type backup --amode plain --rrights free --wrights key0 --rwrights key0 --chrights key0 --size 000010 -n 0 -t aes --apdu --verbose
                                                                                                                                                                                                                                            
  # Write to backup file — trace should show WriteData then CommitTransaction (0xC7)                                                                                                                                                        
hf mfdes write --aid 333333 --fid 01 -n 0 -t aes -d 00010203040506070809101112131415 --apdu --verbose
                                                                              

hf mfdes chfilesettings --aid 111111 --fid 00 --amode encrypt --rrights free --wrights free --rwrights free --chrights key0 --verbose --apdu --algo aes --keyno 0                                   