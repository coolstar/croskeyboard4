/*++
Copyright (c) 1997  Microsoft Corporation

Module Name:

    kbfilter.h

Abstract:

    This module contains the common private declarations for the keyboard
    packet filter

Environment:

    kernel mode only

--*/

#ifndef KBFILTER_H
#define KBFILTER_H

#pragma warning(disable:4201)

#include "ntddk.h"
#include "kbdmou.h"
#include <ntddkbd.h>
#include <ntdd8042.h>

#pragma warning(default:4201)

#include <wdf.h>

#define NTSTRSAFE_LIB
#include <ntstrsafe.h>

#include <initguid.h>
#include <devguid.h>
#include <acpiioct.h>

#include "public.h"

#define KBFILTER_POOL_TAG (ULONG) 'tlfK'

#if DBG

#define TRAP()                      DbgBreakPoint()

#define DebugPrint(_x_) DbgPrint _x_

#else   // DBG

#define TRAP()

#define DebugPrint(_x_)

#endif

#define MIN(_A_,_B_) (((_A_) < (_B_)) ? (_A_) : (_B_))

#define REPORTID_MEDIA          0x08

#define CROSKBHID_BRIGHTNESS_UP 0x01
#define CROSKBHID_BRIGHTNESS_DN 0x02
#define CROSKBHID_KBLT_UP       0x04
#define CROSKBHID_KBLT_DN       0x08
#define CROSKBHID_KBLT_TOGGLE   0x10

#pragma pack(1)
typedef struct _CROSKBHIDREMAPPER_MEDIA_REPORT
{

    BYTE      ReportID;

    BYTE	  ControlCode;

    BYTE	  Reserved;

} CrosKBHIDRemapperMediaReport;

#pragma pack()

typedef struct KeySetting {
    USHORT MakeCode;
    USHORT Flags;
} KeySetting, *PKeySetting;

typedef enum {
    CSVivaldiRequestEndpointRegister,
    CSVivaldiRequestLoadSettings,
    CSVivaldiRequestUpdateTabletMode = 0x102
} CSVivaldiRequest;

#include <pshpack1.h>
typedef struct CSVivaldiSettingsArg {
    UINT32 argSz;
    CSVivaldiRequest settingsRequest;
    union args {
        struct {
            UINT8 functionRowCount;
            KeySetting functionRowKeys[16];
        } settings;
        struct {
            UINT8 tabletmode;
        } tabletmode;
    } args;
} CSVivaldiSettingsArg, *PCSVivaldiSettingsArg;
#include <poppack.h>

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
} CROSKBHID_INTERFACE_STANDARD, *PCROSKBHID_INTERFACE_STANDARD;

#define INTFLAG_NEW 0x1
#define INTFLAG_REMOVED 0x2

#include <pshpack1.h>

typedef struct RemapCfgKey {
    USHORT MakeCode;
    USHORT Flags;
} RemapCfgKey, * PRemapCfgKey;

typedef enum RemapCfgOverride {
    RemapCfgOverrideAutoDetect,
    RemapCfgOverrideEnable,
    RemapCfgOverrideDisable
} RemapCfgOverride, *PRemapCfgOverride;

typedef enum RemapCfgKeyState {
    RemapCfgKeyStateNoDetect,
    RemapCfgKeyStateEnforce,
    RemapCfgKeyStateEnforceNot
} RemapCfgKeyState, *PRemapCfgKeyState;

typedef struct RemapCfg {
    RemapCfgKeyState LeftCtrl;
    RemapCfgKeyState LeftAlt;
    RemapCfgKeyState Search;
    RemapCfgKeyState Assistant;
    RemapCfgKeyState LeftShift;
    RemapCfgKeyState RightCtrl;
    RemapCfgKeyState RightAlt;
    RemapCfgKeyState RightShift;
    RemapCfgKey originalKey;
    BOOLEAN remapVivaldiToFnKeys;
    RemapCfgKey remappedKey;
    RemapCfgKey additionalKeys[8];
} RemapCfg, * PRemapCfg;

typedef struct RemapCfgs {
    UINT32 magic;
    UINT32 remappings;
    BOOLEAN FlipSearchAndAssistantOnPixelbook;
    RemapCfgOverride HasAssistantKey;
    RemapCfgOverride IsNonChromeEC;
    RemapCfg cfg[1];
} RemapCfgs, * PRemapCfgs;
#include <poppack.h>

typedef struct KeyStruct {
    USHORT MakeCode;
    USHORT Flags;
    USHORT InternalFlags;
} KeyStruct, * PKeyStruct;

typedef struct RemappedKeyStruct {
    struct KeyStruct origKey;
    struct KeyStruct remappedKey;
} RemappedKeyStruct, * PRemappedKeyStruct;

#define MAX_CURRENT_KEYS 20

typedef struct _DEVICE_EXTENSION
{
    WDFDEVICE WdfDevice;

    //
    // Queue for handling requests that come from the rawPdo
    //
    WDFQUEUE rawPdoQueue;

    //
    // Number of creates sent down
    //
    LONG EnableCount;

    //
    // The real connect data that this driver reports to
    //
    CONNECT_DATA UpperConnectData;

    //
    // Previous initialization and hook routines (and context)
    //
    PVOID UpperContext;
    PI8042_KEYBOARD_INITIALIZATION_ROUTINE UpperInitializationRoutine;
    PI8042_KEYBOARD_ISR UpperIsrHook;

    //
    // Write function from within KbFilter_IsrHook
    //
    IN PI8042_ISR_WRITE_PORT IsrWritePort;

    //
    // Queue the current packet (ie the one passed into KbFilter_IsrHook)
    //
    IN PI8042_QUEUE_PACKET QueueKeyboardPacket;

    //
    // Context for IsrWritePort, QueueKeyboardPacket
    //
    IN PVOID CallContext;

    //
    // Cached Keyboard Attributes
    //
    KEYBOARD_ATTRIBUTES KeyboardAttributes;

    BOOLEAN tabletMode;
    BOOLEAN hasAssistantKey;
    BOOLEAN isNonChromeEC;

    UINT8 legacyTopRowKeys[10];
    UINT8 legacyVivaldi[10];

    UINT8 functionRowCount;
    KeySetting functionRowKeys[16];

    PRemapCfgs remapCfgs;

    BOOLEAN LeftCtrlPressed;
    BOOLEAN LeftAltPressed;
    BOOLEAN LeftShiftPressed;
    BOOLEAN AssistantPressed;
    BOOLEAN SearchPressed;

    BOOLEAN RightCtrlPressed;
    BOOLEAN RightAltPressed;
    BOOLEAN RightShiftPressed;

    KeyStruct currentKeys[MAX_CURRENT_KEYS];
    KeyStruct lastKeyPressed;
    int numKeysPressed;

    RemappedKeyStruct remappedKeys[MAX_CURRENT_KEYS];
    int numRemaps;

    PCALLBACK_OBJECT CSSettingsCallback;
    PVOID CSSettingsCallbackObj;

    PVOID HIDContext;
    PPROCESS_HID_REPORT HidReportProcessCallback;
} DEVICE_EXTENSION, *PDEVICE_EXTENSION;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_EXTENSION,
                                        FilterGetData)


typedef struct _WORKER_ITEM_CONTEXT {

    WDFREQUEST  Request;
    WDFIOTARGET IoTarget;

} WORKER_ITEM_CONTEXT, *PWORKER_ITEM_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(WORKER_ITEM_CONTEXT, GetWorkItemContext)

//
// Prototypes
//
DRIVER_INITIALIZE DriverEntry;

EVT_WDF_DRIVER_DEVICE_ADD KbFilter_EvtDeviceAdd;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL KbFilter_EvtIoDeviceControlForRawPdo;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL KbFilter_EvtIoDeviceControlFromRawPdo;
EVT_WDF_IO_QUEUE_IO_INTERNAL_DEVICE_CONTROL KbFilter_EvtIoInternalDeviceControl;

NTSTATUS
KbFilter_InitializationRoutine(
    IN PVOID                           InitializationContext,
    IN PVOID                           SynchFuncContext,
    IN PI8042_SYNCH_READ_PORT          ReadPort,
    IN PI8042_SYNCH_WRITE_PORT         WritePort,
    OUT PBOOLEAN                       TurnTranslationOn
    );

BOOLEAN
KbFilter_IsrHook(
    PVOID                  IsrContext,
    PKEYBOARD_INPUT_DATA   CurrentInput,
    POUTPUT_PACKET         CurrentOutput,
    UCHAR                  StatusByte,
    PUCHAR                 DataByte,
    PBOOLEAN               ContinueProcessing,
    PKEYBOARD_SCAN_STATE   ScanState
    );

VOID
KbFilter_ServiceCallback(
    IN PDEVICE_OBJECT DeviceObject,
    IN PKEYBOARD_INPUT_DATA InputDataStart,
    IN PKEYBOARD_INPUT_DATA InputDataEnd,
    IN OUT PULONG InputDataConsumed
    );

EVT_WDF_REQUEST_COMPLETION_ROUTINE
KbFilterRequestCompletionRoutine;


//
// IOCTL Related defintions
//

//
// Used to identify kbfilter bus. This guid is used as the enumeration string
// for the device id.
DEFINE_GUID(GUID_BUS_KBFILTER,
0xa65c87f9, 0xbe02, 0x4ed9, 0x92, 0xec, 0x1, 0x2d, 0x41, 0x61, 0x69, 0xfa);
// {A65C87F9-BE02-4ed9-92EC-012D416169FA}

DEFINE_GUID(GUID_DEVINTERFACE_KBFILTER,
0x3fb7299d, 0x6847, 0x4490, 0xb0, 0xc9, 0x99, 0xe0, 0x98, 0x6a, 0xb8, 0x86);
// {3FB7299D-6847-4490-B0C9-99E0986AB886}


#define  KBFILTR_DEVICE_ID L"{A65C87F9-BE02-4ed9-92EC-012D416169FA}\\KeyboardFilter\0"


typedef struct _RPDO_DEVICE_DATA
{

    ULONG InstanceNo;

    //
    // Queue of the parent device we will forward requests to
    //
    WDFQUEUE ParentQueue;

} RPDO_DEVICE_DATA, *PRPDO_DEVICE_DATA;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(RPDO_DEVICE_DATA, PdoGetData)


NTSTATUS
KbFiltr_CreateRawPdo(
    WDFDEVICE       Device,
    ULONG           InstanceNo
);

NTSTATUS
KbFiltr_CreateHIDPdo(
    WDFDEVICE       Device,
    ULONG           InstanceNo
);



#endif  // KBFILTER_H

