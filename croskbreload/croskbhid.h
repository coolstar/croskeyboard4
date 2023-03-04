#if !defined(_CROSKBHIDREMAPPER_COMMON_H_)
#define _CROSKBHIDREMAPPER_COMMON_H_

typedef struct _croskbhid_client_t* pcroskbhid_client;


//
//These are the device attributes returned by vmulti in response
// to IOCTL_HID_GET_DEVICE_ATTRIBUTES.
//

#define CROSKBHIDREMAPPER_PID              0x0303
#define CROSKBHIDREMAPPER_VID              0x18D1
#define CROSKBHIDREMAPPER_VERSION          0x0004

#define CROSKBLIGHT_PID              0x0002
#define CROSKBLIGHT_VID              0x18D1
#define CROSKBLIGHT_VERSION          0x0001

//
// These are the report ids
//

#define REPORTID_KBLIGHT       0x01

#define REPORTID_KEYBOARD       0x07
#define REPORTID_MEDIA          0x08
#define REPORTID_SETTINGS		0x09

#define SETTINGS_REG_RELOADSETTINGS 0x01

#pragma pack(1)
typedef struct _CROSKBHIDREMAPPER_SETTINGS_REPORT
{

	BYTE        ReportID;

	BYTE		SettingsRegister;

	BYTE		SettingsValue;

} CrosKBHIDRemapperSettingsReport;
#pragma pack()

pcroskbhid_client croskbhid_alloc(void);

void croskbhid_free(pcroskbhid_client vmulti);

BOOL croskbhid_connect(pcroskbhid_client vmulti);

void croskbhid_disconnect(pcroskbhid_client vmulti);

BOOL croskblight_connect(pcroskbhid_client croskbhid);
void croskblight_disconnect(pcroskbhid_client croskbhid);

BOOL croskbhid_read_keyboard(pcroskbhid_client vmulti, CrosKBHIDRemapperSettingsReport* pReport);
BOOL croskbhid_write_keyboard(pcroskbhid_client vmulti, CrosKBHIDRemapperSettingsReport* pReport);

#endif
#pragma once
