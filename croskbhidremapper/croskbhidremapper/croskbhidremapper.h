#if !defined(_CROSKBHIDREMAPPER_H_)
#define _CROSKBHIDREMAPPER_H_

#pragma warning(disable:4200)  // suppress nameless struct/union warning
#pragma warning(disable:4201)  // suppress nameless struct/union warning
#pragma warning(disable:4214)  // suppress bit field types other than int warning
#include <initguid.h>
#include <wdm.h>

#pragma warning(default:4200)
#pragma warning(default:4201)
#pragma warning(default:4214)
#include <wdf.h>

#pragma warning(disable:4201)  // suppress nameless struct/union warning
#pragma warning(disable:4214)  // suppress bit field types other than int warning
#include <hidport.h>

#include "hidcommon.h"
#include "spb.h"

extern "C"

NTSTATUS
DriverEntry(
	_In_  PDRIVER_OBJECT   pDriverObject,
	_In_  PUNICODE_STRING  pRegistryPath
	);

EVT_WDF_DRIVER_DEVICE_ADD       OnDeviceAdd;
EVT_WDF_OBJECT_CONTEXT_CLEANUP  OnDriverCleanup;

//
// String definitions
//

#define DRIVERNAME                 "croskbhidremapper.sys: "

#define CROSKBHIDREMAPPER_POOL_TAG            (ULONG) 'bkrC'
#define CROSKBHIDREMAPPER_HARDWARE_IDS        L"CoolStar\\CrosKBHIDRemapper\0\0"
#define CROSKBHIDREMAPPER_HARDWARE_IDS_LENGTH sizeof(CROSKBHIDREMAPPER_HARDWARE_IDS)

#define NTDEVICE_NAME_STRING       L"\\Device\\CrosKBHIDRemapper"
#define SYMBOLIC_NAME_STRING       L"\\DosDevices\\CrosKBHIDRemapper"
//
// This is the default report descriptor for the Hid device provided
// by the mini driver in response to IOCTL_HID_GET_REPORT_DESCRIPTOR.
// 

typedef UCHAR HID_REPORT_DESCRIPTOR, *PHID_REPORT_DESCRIPTOR;

#ifdef DESCRIPTOR_DEF
HID_REPORT_DESCRIPTOR DefaultReportDescriptor[] = {
	//
	// Keyboard report starts here
	//    
	0x05, 0x01,                         // USAGE_PAGE (Generic Desktop)
	0x09, 0x06,                         // USAGE (Keyboard)
	0xa1, 0x01,                         // COLLECTION (Application)
	0x85, REPORTID_KEYBOARD,            //   REPORT_ID (Keyboard)    
	0x05, 0x07,                         //   USAGE_PAGE (Keyboard)
	0x19, 0xe0,                         //   USAGE_MINIMUM (Keyboard LeftControl)
	0x29, 0xe7,                         //   USAGE_MAXIMUM (Keyboard Right GUI)
	0x15, 0x00,                         //   LOGICAL_MINIMUM (0)
	0x25, 0x01,                         //   LOGICAL_MAXIMUM (1)
	0x75, 0x01,                         //   REPORT_SIZE (1)
	0x95, 0x08,                         //   REPORT_COUNT (8)
	0x81, 0x02,                         //   INPUT (Data,Var,Abs)
	0x95, 0x01,                         //   REPORT_COUNT (1)
	0x75, 0x08,                         //   REPORT_SIZE (8)
	0x81, 0x03,                         //   INPUT (Cnst,Var,Abs)
	0x95, 0x05,                         //   REPORT_COUNT (5)
	0x75, 0x01,                         //   REPORT_SIZE (1)
	0x05, 0x08,                         //   USAGE_PAGE (LEDs)
	0x19, 0x01,                         //   USAGE_MINIMUM (Num Lock)
	0x29, 0x05,                         //   USAGE_MAXIMUM (Kana)
	0x91, 0x02,                         //   OUTPUT (Data,Var,Abs)
	0x95, 0x01,                         //   REPORT_COUNT (1)
	0x75, 0x03,                         //   REPORT_SIZE (3)
	0x91, 0x03,                         //   OUTPUT (Cnst,Var,Abs)
	0x95, 0x06,                         //   REPORT_COUNT (6)
	0x75, 0x08,                         //   REPORT_SIZE (8)
	0x15, 0x00,                         //   LOGICAL_MINIMUM (0)
	0x25, 0x65,                         //   LOGICAL_MAXIMUM (101)
	0x05, 0x07,                         //   USAGE_PAGE (Keyboard)
	0x19, 0x00,                         //   USAGE_MINIMUM (Reserved (no event indicated))
	0x29, 0x65,                         //   USAGE_MAXIMUM (Keyboard Application)
	0x81, 0x00,                         //   INPUT (Data,Ary,Abs)
	0xc0,                               // END_COLLECTION

	0x05, 0x0C, /*		Usage Page (Consumer Devices)		*/
	0x09, 0x01, /*		Usage (Consumer Control)			*/
	0xA1, 0x01, /*		Collection (Application)			*/
	0x85, REPORTID_MEDIA,	/*		Report ID=2							*/
	0x05, 0x0C, /*		Usage Page (Consumer Devices)		*/
	0x15, 0x00, /*		Logical Minimum (0)					*/
	0x25, 0x01, /*		Logical Maximum (1)					*/
	0x75, 0x01, /*		Report Size (1)						*/
	0x95, 0x05, /*		Report Count (5)					*/
	0x09, 0x6F, /*		Usage (Brightess Up)				*/
	0x09, 0x70, /*		Usage (Brightness Down)				*/
	0x09, 0x79, /*		Usage (Keyboard Brightness Up)		*/
	0x09, 0x7A, /*		Usage (Keyboard Brightness Down)	*/
	0x09, 0xEC, /*		Usage (Keyboard Backlight Toggle)	*/
	0x81, 0x02, /*		Input (Data, Variable, Absolute)	*/
	0x95, 0x03, /*		Report Count (3)					*/
	0x81, 0x01, /*		Input (Constant)					*/
	0xC0,        /*        End Collection                        */

	0x06, 0x00, 0xff,                    // USAGE_PAGE (Vendor Defined Page 1)
	0x09, 0x03,                          // USAGE (Vendor Usage 3)
	0xa1, 0x01,                          // COLLECTION (Application)
	0x85, REPORTID_SETTINGS,              //   REPORT_ID (Settings)
	0x15, 0x00,                          //   LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00,                    //   LOGICAL_MAXIMUM (256)
	0x75, 0x08,                          //   REPORT_SIZE  (8)   - bits
	0x95, 0x01,                          //   REPORT_COUNT (1)  - Bytes
	0x09, 0x02,                          //   USAGE (Vendor Usage 1)
	0x91, 0x02,                          //   OUTPUT (Data,Var,Abs)
	0x09, 0x03,                          //   USAGE (Vendor Usage 2)
	0x91, 0x02,                          //   OUTPUT (Data,Var,Abs)
	0xc0,                                // END_COLLECTION
};


//
// This is the default HID descriptor returned by the mini driver
// in response to IOCTL_HID_GET_DEVICE_DESCRIPTOR. The size
// of report descriptor is currently the size of DefaultReportDescriptor.
//

CONST HID_DESCRIPTOR DefaultHidDescriptor = {
	0x09,   // length of HID descriptor
	0x21,   // descriptor type == HID  0x21
	0x0100, // hid spec release
	0x00,   // country code == Not Specified
	0x01,   // number of HID class descriptors
	{ 0x22,   // descriptor type 
	sizeof(DefaultReportDescriptor) }  // total length of report descriptor
};
#endif

#define true 1
#define false 0

typedef NTSTATUS
(*PPROCESS_HID_REPORT)(
	IN PVOID Context,
	IN PVOID ReportBuffer,
	IN ULONG ReportBufferLen,
	OUT size_t* BytesWritten
	);

typedef BOOLEAN
(*PREGISTER_CALLBACK)(
	IN PVOID Context,
	IN PVOID HIDContext,
	IN PPROCESS_HID_REPORT HidReportProcessCallback
	);

typedef BOOLEAN
(*PUNREGISTER_CALLBACK)(
	IN PVOID Context
	);

typedef void
(*PRELOAD_SETTINGS)(
	IN PVOID Context
	);

DEFINE_GUID(GUID_CROSKBHID_INTERFACE_STANDARD,
	0x74a15a7c, 0x82b5, 0x11ed, 0x8c, 0xd5, 0x00, 0x15, 0x5d, 0xa4, 0x4e, 0x91);

typedef struct _CROSKBHID_INTERFACE_STANDARD {
	INTERFACE InterfaceHeader;
	PREGISTER_CALLBACK     RegisterCallback;
	PUNREGISTER_CALLBACK   UnregisterCallback;
	PRELOAD_SETTINGS       ReloadSettings;
} CROSKBHID_INTERFACE_STANDARD, * PCROSKBHID_INTERFACE_STANDARD;

typedef struct _CROSKBHIDREMAPPER_CONTEXT
{
	WDFDEVICE FxDevice;

	WDFQUEUE ReportQueue;

	WDFQUEUE IdleQueue;

	BYTE DeviceMode;

	CROSKBHID_INTERFACE_STANDARD CrosKBHidInterface;

} CROSKBHIDREMAPPER_CONTEXT, *PCROSKBHIDREMAPPER_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(CROSKBHIDREMAPPER_CONTEXT, GetDeviceContext)

//
// Power Idle Workitem context
// 
typedef struct _IDLE_WORKITEM_CONTEXT
{
	// Handle to a WDF device object
	WDFDEVICE FxDevice;

	// Handle to a WDF request object
	WDFREQUEST FxRequest;

} IDLE_WORKITEM_CONTEXT, * PIDLE_WORKITEM_CONTEXT;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(IDLE_WORKITEM_CONTEXT, GetIdleWorkItemContext)

//
// Function definitions
//

DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_UNLOAD CrosKBHIDRemapperDriverUnload;

EVT_WDF_DRIVER_DEVICE_ADD CrosKBHIDRemapperEvtDeviceAdd;

EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL CrosKBHIDRemapperEvtInternalDeviceControl;

NTSTATUS
CrosKBHIDRemapperGetHidDescriptor(
	IN WDFDEVICE Device,
	IN WDFREQUEST Request
	);

NTSTATUS
CrosKBHIDRemapperGetReportDescriptor(
	IN WDFDEVICE Device,
	IN WDFREQUEST Request
	);

NTSTATUS
CrosKBHIDRemapperGetDeviceAttributes(
	IN WDFREQUEST Request
	);

NTSTATUS
CrosKBHIDRemapperGetString(
	IN WDFREQUEST Request
	);

NTSTATUS
CrosKBHIDRemapperWriteReport(
	IN PCROSKBHIDREMAPPER_CONTEXT DevContext,
	IN WDFREQUEST Request
	);

NTSTATUS
CrosKBHIDRemapperProcessVendorReport(
	IN PCROSKBHIDREMAPPER_CONTEXT DevContext,
	IN PVOID ReportBuffer,
	IN ULONG ReportBufferLen,
	OUT size_t* BytesWritten
	);

NTSTATUS
CrosKBHIDRemapperReadReport(
	IN PCROSKBHIDREMAPPER_CONTEXT DevContext,
	IN WDFREQUEST Request,
	OUT BOOLEAN* CompleteRequest
	);

NTSTATUS
CrosKBHIDRemapperSetFeature(
	IN PCROSKBHIDREMAPPER_CONTEXT DevContext,
	IN WDFREQUEST Request,
	OUT BOOLEAN* CompleteRequest
	);

NTSTATUS
CrosKBHIDRemapperGetFeature(
	IN PCROSKBHIDREMAPPER_CONTEXT DevContext,
	IN WDFREQUEST Request,
	OUT BOOLEAN* CompleteRequest
	);

PCHAR
DbgHidInternalIoctlString(
	IN ULONG        IoControlCode
	);

VOID
CrosKBHIDRemapperCompleteIdleIrp(
	IN PCROSKBHIDREMAPPER_CONTEXT FxDeviceContext
);

//
// Helper macros
//

#define DEBUG_LEVEL_ERROR   1
#define DEBUG_LEVEL_INFO    2
#define DEBUG_LEVEL_VERBOSE 3

#define DBG_INIT  1
#define DBG_PNP   2
#define DBG_IOCTL 4

#if DBG
#define CrosKBHIDRemapperPrint(dbglevel, dbgcatagory, fmt, ...) {          \
    if (CrosKBHIDRemapperDebugLevel >= dbglevel &&                         \
        (CrosKBHIDRemapperDebugCatagories && dbgcatagory))                 \
	    {                                                           \
        DbgPrint(DRIVERNAME);                                   \
        DbgPrint(fmt, __VA_ARGS__);                             \
	    }                                                           \
}
#else
#define CrosKBHIDRemapperPrint(dbglevel, fmt, ...) {                       \
}
#endif

#endif
#pragma once
