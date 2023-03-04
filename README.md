# croskeyboard4
Windows keyboard filter driver with function key override support for Chromebooks

# Compatibility
Works on the Chromebook Pixel and any chromebook released after the Pixel, though works best on chromebooks that support Vivaldi

# Installation
First you need to install croskeyboard4 on top of the existing keyboard device (ACPI\GOOG000A)

If your chromebook supports Vivaldi, you should also install https://github.com/coolstar/crosecvivaldi to ACPI\GOOG0007
Also make sure to install croskbhidremapper to CROSKB\HID0000 in order to get support for brightness keys and settings

# Settings

Settings are loaded from C:\Windows\system32\drivers\croskbsettings.bin

A sample binary has been provided here https://github.com/coolstar/croskeyboard4/blob/master/croskbsettings.bin with settings matching croskeyboard3 / croskbremap. To load settings, drag the binary in and either reboot, or run croskbreload to hot-reload settings.

To create your own settings, you may use https://github.com/coolstar/VivaldiKeyboardTester and search for croskbsettings.bin in VivaldiKeyboardTester.cpp.

A GUI tool will be coming soon to support generating your own remap files.