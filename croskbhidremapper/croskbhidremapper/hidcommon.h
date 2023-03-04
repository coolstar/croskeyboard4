#if !defined(_CROSKBHIDREMAPPER_COMMON_H_)
#define _CROSKBHIDREMAPPER_COMMON_H_

//
//These are the device attributes returned by vmulti in response
// to IOCTL_HID_GET_DEVICE_ATTRIBUTES.
//

#define CROSKBHIDREMAPPER_PID              0x0303
#define CROSKBHIDREMAPPER_VID              0x18D1
#define CROSKBHIDREMAPPER_VERSION          0x0004

//
// These are the report ids
//

#define REPORTID_KEYBOARD       0x07
#define REPORTID_MEDIA          0x08
#define REPORTID_SETTINGS		0x09

//
// Keyboard specific report infomation
//

#define KBD_LCONTROL_BIT     1
#define KBD_LSHIFT_BIT       2
#define KBD_LALT_BIT         4
#define KBD_LGUI_BIT         8
#define KBD_RCONTROL_BIT     16
#define KBD_RSHIFT_BIT       32
#define KBD_RALT_BIT         64
#define KBD_RGUI_BIT         128

#define KBD_KEY_CODES        6

#pragma pack(1)
typedef struct _CROSKBHIDREMAPPER_KEYBOARD_REPORT
{

	BYTE      ReportID;

	// Left Control, Left Shift, Left Alt, Left GUI
	// Right Control, Right Shift, Right Alt, Right GUI
	BYTE      ShiftKeyFlags;

	BYTE      Reserved;

	// See http://www.usb.org/developers/devclass_docs/Hut1_11.pdf
	// for a list of key codes
	BYTE      KeyCodes[KBD_KEY_CODES];

} CrosKBHIDRemapperKeyboardReport;

#pragma pack()

#pragma pack(1)
typedef struct _CROSKBHIDREMAPPER_MEDIA_REPORT
{

	BYTE      ReportID;

	BYTE	  ControlCode;

	BYTE	  Reserved;

} CrosKBHIDRemapperMediaReport;

#pragma pack()

#pragma pack()

//
// Feature report infomation
//

#define DEVICE_MODE_MOUSE        0x00
#define DEVICE_MODE_SINGLE_INPUT 0x01
#define DEVICE_MODE_MULTI_INPUT  0x02

#pragma pack(1)
typedef struct _CROSKBHIDREMAPPER_FEATURE_REPORT
{

	BYTE      ReportID;

	BYTE      DeviceMode;

	BYTE      DeviceIdentifier;

} CrosKBHIDRemapperFeatureReport;

#define SETTINGS_REG_RELOADSETTINGS 0x01

#pragma pack(1)
typedef struct _CROSKBHIDREMAPPER_SETTINGS_REPORT
{

	BYTE        ReportID;

	BYTE		SettingsRegister;

	BYTE		SettingsValue;

} CrosKBHIDRemapperSettingsReport;
#pragma pack()

#endif
#pragma once
