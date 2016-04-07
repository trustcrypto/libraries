Arduino-Teensy3-Flash
=====================

WARNING:
BE VERY CAREFUL, AND BE SURE TO HAVE SOME SPARE TEENSY 3.X. IT'S LIKELY THAT YOU WILL NEED THEM. THIS IS MEANT VERY SERIOUSLY.


Program the Teensy-Flash
========================

Check sector is erased:
flashCheckSectorErased()

Erase a sector:
flashEraseSector()
Before erasing, the function checks the sector if it is empty. If so, it does nothing.
This is to prevent unnecessary stress.

Program with unsigned int:
flashProgramWord().
The locations 0x400-0x40f are not written. This is to protect YOU from unnecessary stress.



Please see the example.

The size of a sector is 2048 Bytes.
