/*--

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.


Module Name:

    croskeyboard.c

Abstract: This is an upper device filter driver sample for PS/2 keyboard. This
        driver layers in between the KbdClass driver and i8042prt driver and
        hooks the callback routine that moves keyboard inputs from the port
        driver to class driver. With this filter, you can remove or insert
        additional keys into the stream. This sample also creates a raw
        PDO and registers an interface so that application can talk to
        the filter driver directly without going thru the PS/2 devicestack.
        The reason for providing this additional interface is because the keyboard
        device is an exclusive secure device and it's not possible to open the
        device from usermode and send custom ioctls.

        If you want to filter keyboard inputs from all the keyboards (ps2, usb)
        plugged into the system then you can install this driver as a class filter
        and make it sit below the kbdclass filter driver by adding the service
        name of this filter driver before the kbdclass filter in the registry at
        " HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Class\
        {4D36E96B-E325-11CE-BFC1-08002BE10318}\UpperFilters"


Environment:

    Kernel mode only.

--*/

#include "croskeyboard.h"
#include <stdlib.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text (INIT, DriverEntry)
#pragma alloc_text (PAGE, KbFilter_EvtDeviceAdd)
#pragma alloc_text (PAGE, KbFilter_EvtIoInternalDeviceControl)
#endif

ULONG InstanceNo = 0;

NTSTATUS
DriverEntry(
    IN PDRIVER_OBJECT  DriverObject,
    IN PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    Installable driver initialization entry point.
    This entry point is called directly by the I/O system.

Arguments:

    DriverObject - pointer to the driver object

    RegistryPath - pointer to a unicode string representing the path,
                   to driver-specific key in the registry.

Return Value:

    STATUS_SUCCESS if successful,
    STATUS_UNSUCCESSFUL otherwise.

--*/
{
    WDF_DRIVER_CONFIG               config;
    NTSTATUS                        status;

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    DebugPrint(("Keyboard Filter Driver Sample - Driver Framework Edition.\n"));
    DebugPrint(("Built %s %s\n", __DATE__, __TIME__));

    //
    // Initialize driver config to control the attributes that
    // are global to the driver. Note that framework by default
    // provides a driver unload routine. If you create any resources
    // in the DriverEntry and want to be cleaned in driver unload,
    // you can override that by manually setting the EvtDriverUnload in the
    // config structure. In general xxx_CONFIG_INIT macros are provided to
    // initialize most commonly used members.
    //

    WDF_DRIVER_CONFIG_INIT(
        &config,
        KbFilter_EvtDeviceAdd
    );

    //
    // Create a framework driver object to represent our driver.
    //
    status = WdfDriverCreate(DriverObject,
                            RegistryPath,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &config,
                            WDF_NO_HANDLE); // hDriver optional
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDriverCreate failed with status 0x%x\n", status));
    }

    return status;
}

const UINT8 fnKeys_set1[] = {
    0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58,

    //F13 - F16
    0x64, 0x64, 0x66, 0x67
};

#define KEY_TYPES (KEY_E0 | KEY_E1 | KEY_RIM_VKEY | KEY_FROM_KEYBOARD_OVERRIDER)

#define K_LCTRL     0x1D
#define K_LALT      0x38
#define K_LSHFT     0x2A
#define K_ASSISTANT 0x58
#define WILCO_ASSISTANT 0x54
#define K_LWIN      0x5B

#define K_RCTRL     0x1D
#define K_RALT      0x38
#define K_RSHFT     0x36

#define K_BACKSP    0xE
#define K_DELETE    0x53
#define K_LOCK      0x5D

#define K_UP        0x48
#define K_DOWN      0x50
#define K_LEFT      0x4B
#define K_RIGHT     0x4D

#define K_PGUP      0x49
#define K_HOME      0x47
#define K_END       0x4F
#define K_PGDN      0x51

//ALL VIVALDI USES KEY_E0

//values from https://github.com/coreboot/chrome-ec/blob/1b359bdd91da15ea25aaffd0d940ff63b9d72bc5/include/keyboard_8042_sharedlib.h#L116
#define VIVALDI_BACK                0x6A
#define VIVALDI_FWD                 0x69
#define VIVALDI_REFRESH             0x67
#define VIVALDI_FULLSCREEN          0x11
#define VIVALDI_OVERVIEW            0x12
#define VIVALDI_SNAPSHOT            0x13
#define VIVALDI_BRIGHTNESSDN        0x14
#define VIVALDI_BRIGHTNESSUP        0x15
#define VIVALDI_PRIVACY_TOGGLE      0x16
#define VIVALDI_KBD_BKLIGHT_DOWN    0x17
#define VIVALDI_KBD_BKLIGHT_UP      0x18
#define VIVALDI_KBD_BKLIGHT_TOGGLE  0x1e
#define VIVALDI_PLAYPAUSE           0x1A
#define VIVALDI_MUTE                0x20
#define VIVALDI_VOLDN               0x2e
#define VIVALDI_VOLUP               0x30
#define VIVALDI_NEXT_TRACK          0x19
#define VIVALDI_PREV_TRACK          0x10
#define VIVALDI_MICMUTE             0x1b

//Wilco uses slightly different keys. Just here for reference as it has a dedicated Fn key
#define WILCO_FULLSCREEN 0x55
#define WILCO_OVERVIEW 0x56
#define WILCO_BRIGHTNESSDN 0x15
#define WILCO_BRIGHTNESSUP 0x11
#define WILCO_PROJECT 0xb

#define REMAP_CFG_MAGIC 'CrKB'

const UINT8 legacyVivaldi[] = {
    VIVALDI_BACK, VIVALDI_FWD, VIVALDI_REFRESH, VIVALDI_FULLSCREEN, VIVALDI_OVERVIEW, VIVALDI_BRIGHTNESSDN, VIVALDI_BRIGHTNESSUP, VIVALDI_MUTE, VIVALDI_VOLDN, VIVALDI_VOLUP
};

const UINT8 legacyVivaldiPixelbook[] = {
    VIVALDI_BACK, VIVALDI_REFRESH, VIVALDI_FULLSCREEN, VIVALDI_OVERVIEW, VIVALDI_BRIGHTNESSDN, VIVALDI_BRIGHTNESSUP, VIVALDI_PLAYPAUSE, VIVALDI_MUTE, VIVALDI_VOLDN, VIVALDI_VOLUP
};

int CSVivaldiArg2;

void garbageCollect(PDEVICE_EXTENSION devExt);

VOID CSVivaldiRegisterEndpoint(PDEVICE_EXTENSION  pDevice) {
    CSVivaldiSettingsArg newArg;
    RtlZeroMemory(&newArg, sizeof(CSVivaldiSettingsArg));
    newArg.argSz = sizeof(CSVivaldiSettingsArg);
    newArg.settingsRequest = CSVivaldiRequestEndpointRegister;
    ExNotifyCallback(pDevice->CSSettingsCallback, &newArg, &CSVivaldiArg2);
}

VOID CsVivaldiCallbackFunction(
    PDEVICE_EXTENSION pDevice,
    CSVivaldiSettingsArg* arg,
    PVOID Argument2
) {
    if (!pDevice) {
        return;
    }
    if (Argument2 == &CSVivaldiArg2) {
        return;
    }

    CSVivaldiSettingsArg localArg;
    RtlZeroMemory(&localArg, sizeof(CSVivaldiSettingsArg));
    RtlCopyMemory(&localArg, arg, min(arg->argSz, sizeof(CSVivaldiSettingsArg)));

    if (localArg.settingsRequest == CSVivaldiRequestEndpointRegister) {
        CSVivaldiRegisterEndpoint(pDevice);
    } else if (localArg.settingsRequest == CSVivaldiRequestLoadSettings) {
        pDevice->functionRowCount = localArg.args.settings.functionRowCount;
        RtlZeroMemory(&pDevice->functionRowKeys, sizeof(pDevice->functionRowKeys));
        for (int i = 0; i < pDevice->functionRowCount; i++) {
            pDevice->functionRowKeys[i] = localArg.args.settings.functionRowKeys[i];
        }
    }
    else if (localArg.settingsRequest == CSVivaldiRequestUpdateTabletMode) {
        pDevice->tabletMode = (localArg.args.tabletmode.tabletmode != 0);
    }
}

#define MAX_DEVICE_REG_VAL_LENGTH 0x100
NTSTATUS GetSmbiosName(WCHAR systemProductName[MAX_DEVICE_REG_VAL_LENGTH]) {
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE parentKey = NULL;
    UNICODE_STRING ParentKeyName;
    OBJECT_ATTRIBUTES  ObjectAttributes;
    RtlInitUnicodeString(&ParentKeyName, L"\\Registry\\Machine\\Hardware\\DESCRIPTION\\System\\BIOS");

    InitializeObjectAttributes(&ObjectAttributes,
        &ParentKeyName,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL,    // handle
        NULL);

    status = ZwOpenKey(&parentKey, KEY_READ, &ObjectAttributes);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    ULONG ResultLength;
    PKEY_VALUE_PARTIAL_INFORMATION KeyValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ExAllocatePoolZero(NonPagedPool, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_DEVICE_REG_VAL_LENGTH, KBFILTER_POOL_TAG);
    if (!KeyValueInfo) {
        status = STATUS_NO_MEMORY;
        goto exit;
    }

    UNICODE_STRING SystemProductNameValue;
    RtlInitUnicodeString(&SystemProductNameValue, L"SystemProductName");
    status = ZwQueryValueKey(parentKey, &SystemProductNameValue, KeyValuePartialInformation, KeyValueInfo, sizeof(KEY_VALUE_PARTIAL_INFORMATION) + MAX_DEVICE_REG_VAL_LENGTH, &ResultLength);
    if (!NT_SUCCESS(status)) {
        goto exit;
    }

    if (KeyValueInfo->DataLength > MAX_DEVICE_REG_VAL_LENGTH) {
        status = STATUS_BUFFER_OVERFLOW;
        goto exit;
    }

    RtlZeroMemory(systemProductName, sizeof(systemProductName));
    RtlCopyMemory(systemProductName, &KeyValueInfo->Data, KeyValueInfo->DataLength);

exit:
    if (KeyValueInfo) {
        ExFreePoolWithTag(KeyValueInfo, KBFILTER_POOL_TAG);
    }
    return status;
}

#include <stddef.h>
#include "firmware.h"

void LoadSettings(PDEVICE_EXTENSION filterExt) {
    if (filterExt->remapCfgs) {
        ExFreePoolWithTag(filterExt->remapCfgs, KBFILTER_POOL_TAG);
        filterExt->remapCfgs = NULL;
    }

    const struct firmware* fw;
    if (!NT_SUCCESS(request_firmware(&fw, L"\\SystemRoot\\system32\\DRIVERS\\croskbsettings.bin"))) {
        DbgPrint("Error: failed to find croskbsettings.bin!");
        return;
    }

    if (fw->size < offsetof(RemapCfgs, cfg)) {
        DbgPrint("Error: croskbsettings.bin is too small!");
        goto out;
    }
    else {
        PRemapCfgs initialCfgs = fw->data;
        if (initialCfgs->magic != REMAP_CFG_MAGIC) {
            DbgPrint("Error: croskbsettings.bin has invalid file magic!\n");
            goto out;
        }
        else if (fw->size < (offsetof(RemapCfgs, cfg) + sizeof(RemapCfg) * initialCfgs->remappings)) {
            DbgPrint("Error: croskbsettings.bin is too small for %d remappings!\n", initialCfgs->remappings);
            goto out;
        }
        else {
            size_t cfgSize = offsetof(RemapCfgs, cfg) + sizeof(RemapCfg) * initialCfgs->remappings;
            PRemapCfgs remapCfgs = (PRemapCfgs)ExAllocatePoolZero(NonPagedPool, cfgSize, KBFILTER_POOL_TAG);
            if (!remapCfgs) {
                DbgPrint("Error: Failed to allocate memory for croskbsettings.bin!\n");
                goto out;
            }

            RtlCopyMemory(remapCfgs, fw->data, cfgSize);
            filterExt->remapCfgs = remapCfgs;
        }
    }

out:
    free_firmware(fw);

    if (!filterExt->remapCfgs) {
        return;
    }

    PRemapCfgs remapCfgs = filterExt->remapCfgs;
    if (remapCfgs->HasAssistantKey == RemapCfgOverrideEnable) {
        filterExt->hasAssistantKey = TRUE;
    } else if (remapCfgs->HasAssistantKey == RemapCfgOverrideDisable) {
        filterExt->hasAssistantKey = FALSE;
    }

    if (remapCfgs->IsNonChromeEC == RemapCfgOverrideEnable) {
        filterExt->isNonChromeEC = TRUE;
    }
    else if (remapCfgs->IsNonChromeEC == RemapCfgOverrideDisable) {
        filterExt->isNonChromeEC = FALSE;
    }
}

NTSTATUS AutoDetectSettings(PDEVICE_EXTENSION filterExt) {
    NTSTATUS status = STATUS_SUCCESS;

    WCHAR SmbiosName[MAX_DEVICE_REG_VAL_LENGTH] = { 0 };
    status = GetSmbiosName(SmbiosName);
    if (!NT_SUCCESS(status)) {
        DebugPrint(("GetSmbiosName failed 0x%x\n", status));
        return status;
    }

    filterExt->hasAssistantKey = FALSE;
    filterExt->isNonChromeEC = FALSE;
    if (wcscmp(SmbiosName, L"Eve") == 0 || (wcscmp(SmbiosName, L"Atlas") == 0)) {
        RtlCopyMemory(&filterExt->legacyVivaldi, &legacyVivaldiPixelbook, sizeof(filterExt->legacyVivaldi));
        filterExt->hasAssistantKey = TRUE;
    }
    else if (wcscmp(SmbiosName, L"Arcada") == 0 || (wcscmp(SmbiosName, L"Sarien") == 0) || (wcscmp(SmbiosName, L"Drallion") == 0)) {
        filterExt->hasAssistantKey = TRUE;
        filterExt->isNonChromeEC = TRUE;
    }

    return status;
}

NTSTATUS
OnSelfManagedIoInit(
    _In_
    WDFDEVICE FxDevice
) {
    PDEVICE_EXTENSION       filterExt;
    filterExt = FilterGetData(FxDevice);

    NTSTATUS status = STATUS_SUCCESS;

    status = AutoDetectSettings(filterExt);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    for (int i = 0; i < sizeof(filterExt->legacyVivaldi); i++) {
        filterExt->functionRowKeys[i].MakeCode = filterExt->legacyVivaldi[i];
        filterExt->functionRowKeys[i].Flags |= KEY_E0;
    }

    // CS Keyboard Callback

    UNICODE_STRING CSKeyboardSettingsCallbackAPI;
    RtlInitUnicodeString(&CSKeyboardSettingsCallbackAPI, L"\\CallBack\\CsKeyboardSettingsCallbackAPI");


    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(&attributes,
        &CSKeyboardSettingsCallbackAPI,
        OBJ_KERNEL_HANDLE | OBJ_OPENIF | OBJ_CASE_INSENSITIVE | OBJ_PERMANENT,
        NULL,
        NULL
    );
    status = ExCreateCallback(&filterExt->CSSettingsCallback, &attributes, TRUE, TRUE);
    if (!NT_SUCCESS(status)) {

        return status;
    }

    filterExt->CSSettingsCallbackObj = ExRegisterCallback(filterExt->CSSettingsCallback,
        CsVivaldiCallbackFunction,
        filterExt
    );
    if (!filterExt->CSSettingsCallbackObj) {
        return STATUS_NO_CALLBACK_ACTIVE;
    }
    CSVivaldiRegisterEndpoint(filterExt);

    LoadSettings(filterExt);

    return status;
}

NTSTATUS
OnReleaseHardware(
    _In_  WDFDEVICE     FxDevice,
    _In_  WDFCMRESLIST  FxResourcesTranslated
)
{
    PDEVICE_EXTENSION       filterExt;
    UNREFERENCED_PARAMETER(FxResourcesTranslated);

    filterExt = FilterGetData(FxDevice);

    if (filterExt->remapCfgs) {
        ExFreePoolWithTag(filterExt->remapCfgs, KBFILTER_POOL_TAG);
        filterExt->remapCfgs = NULL;
    }

    if (filterExt->CSSettingsCallbackObj) {
        ExUnregisterCallback(filterExt->CSSettingsCallbackObj);
        filterExt->CSSettingsCallbackObj = NULL;
    }

    if (filterExt->CSSettingsCallback) {
        ObfDereferenceObject(filterExt->CSSettingsCallback);
        filterExt->CSSettingsCallback = NULL;
    }
    return STATUS_SUCCESS;
}

NTSTATUS
KbFilter_EvtDeviceAdd(
    IN WDFDRIVER        Driver,
    IN PWDFDEVICE_INIT  DeviceInit
    )
/*++
Routine Description:

    EvtDeviceAdd is called by the framework in response to AddDevice
    call from the PnP manager. Here you can query the device properties
    using WdfFdoInitWdmGetPhysicalDevice/IoGetDeviceProperty and based
    on that, decide to create a filter device object and attach to the
    function stack.

    If you are not interested in filtering this particular instance of the
    device, you can just return STATUS_SUCCESS without creating a framework
    device.

Arguments:

    Driver - Handle to a framework driver object created in DriverEntry

    DeviceInit - Pointer to a framework-allocated WDFDEVICE_INIT structure.

Return Value:

    NTSTATUS

--*/
{
    WDF_OBJECT_ATTRIBUTES   deviceAttributes;
    NTSTATUS                status;
    WDFDEVICE               hDevice;
    WDFQUEUE                hQueue;
    PDEVICE_EXTENSION       filterExt;
    WDF_IO_QUEUE_CONFIG     ioQueueConfig;

    UNREFERENCED_PARAMETER(Driver);

    PAGED_CODE();

    DebugPrint(("Enter FilterEvtDeviceAdd \n"));

    //
    // Tell the framework that you are filter driver. Framework
    // takes care of inherting all the device flags & characterstics
    // from the lower device you are attaching to.
    //
    WdfFdoInitSetFilter(DeviceInit);

    WdfDeviceInitSetDeviceType(DeviceInit, FILE_DEVICE_KEYBOARD);

    {
        WDF_PNPPOWER_EVENT_CALLBACKS pnpCallbacks;
        WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&pnpCallbacks);

        pnpCallbacks.EvtDeviceReleaseHardware = OnReleaseHardware;
        pnpCallbacks.EvtDeviceSelfManagedIoInit = OnSelfManagedIoInit;

        WdfDeviceInitSetPnpPowerEventCallbacks(DeviceInit, &pnpCallbacks);
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&deviceAttributes, DEVICE_EXTENSION);

    //
    // Create a framework device object.  This call will in turn create
    // a WDM deviceobject, attach to the lower stack and set the
    // appropriate flags and attributes.
    //
    status = WdfDeviceCreate(&DeviceInit, &deviceAttributes, &hDevice);
    if (!NT_SUCCESS(status)) {
        DebugPrint(("WdfDeviceCreate failed with status code 0x%x\n", status));
        return status;
    }

    filterExt = FilterGetData(hDevice);

    //
    // Configure the default queue to be Parallel. Do not use sequential queue
    // if this driver is going to be filtering PS2 ports because it can lead to
    // deadlock. The PS2 port driver sends a request to the top of the stack when it
    // receives an ioctl request and waits for it to be completed. If you use a
    // a sequential queue, this request will be stuck in the queue because of the 
    // outstanding ioctl request sent earlier to the port driver.
    //
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&ioQueueConfig,
                             WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoInternalDeviceControl = KbFilter_EvtIoInternalDeviceControl;

    status = WdfIoQueueCreate(hDevice,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            WDF_NO_HANDLE // pointer to default queue
                            );
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    //
    // Create a new queue to handle IOCTLs that will be forwarded to us from
    // the rawPDO. 
    //
    WDF_IO_QUEUE_CONFIG_INIT(&ioQueueConfig,
                             WdfIoQueueDispatchParallel);

    //
    // Framework by default creates non-power managed queues for
    // filter drivers.
    //
    ioQueueConfig.EvtIoDeviceControl = KbFilter_EvtIoDeviceControlFromRawPdo;

    status = WdfIoQueueCreate(hDevice,
                            &ioQueueConfig,
                            WDF_NO_OBJECT_ATTRIBUTES,
                            &hQueue
                            );
    if (!NT_SUCCESS(status)) {
        DebugPrint( ("WdfIoQueueCreate failed 0x%x\n", status));
        return status;
    }

    filterExt->rawPdoQueue = hQueue;

    filterExt->numKeysPressed = 0;
    RtlZeroMemory(&filterExt->currentKeys, sizeof(filterExt->currentKeys));
    RtlZeroMemory(&filterExt->lastKeyPressed, sizeof(filterExt->lastKeyPressed));

    RtlZeroMemory(&filterExt->remappedKeys, sizeof(filterExt->remappedKeys));
    filterExt->numRemaps = 0;

    filterExt->functionRowCount = 0;
    RtlZeroMemory(&filterExt->functionRowKeys, sizeof(filterExt->functionRowKeys));

    RtlCopyMemory(&filterExt->legacyTopRowKeys, &fnKeys_set1, sizeof(filterExt->legacyTopRowKeys));
    RtlCopyMemory(&filterExt->legacyVivaldi, &legacyVivaldi, sizeof(filterExt->legacyVivaldi));
    filterExt->hasAssistantKey = FALSE;

    filterExt->functionRowCount = sizeof(filterExt->legacyVivaldi);
    for (int i = 0; i < sizeof(filterExt->legacyVivaldi); i++) {
        filterExt->functionRowKeys[i].MakeCode = filterExt->legacyVivaldi[i];
        filterExt->functionRowKeys[i].Flags |= KEY_E0;
    }

    // Create a HID pdo
    status = KbFiltr_CreateHIDPdo(hDevice, ++InstanceNo);

    //
    // Create a RAW pdo so we can provide a sideband communication with
    // the application. Please note that not filter drivers desire to
    // produce such a communication and not all of them are contrained
    // by other filter above which prevent communication thru the device
    // interface exposed by the main stack. So use this only if absolutely
    // needed. Also look at the toaster filter driver sample for an alternate
    // approach to providing sideband communication.
    //
    //status = KbFiltr_CreateRawPdo(hDevice, ++InstanceNo);

    return status;
}

VOID
KbFilter_EvtIoDeviceControlFromRawPdo(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for device control requests.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    NTSTATUS status = STATUS_SUCCESS;
    WDFDEVICE hDevice;
    WDFMEMORY outputMemory;
    PDEVICE_EXTENSION devExt;
    size_t bytesTransferred = 0;

    UNREFERENCED_PARAMETER(InputBufferLength);

    DebugPrint(("Entered KbFilter_EvtIoInternalDeviceControl\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    //
    // Process the ioctl and complete it when you are done.
    //

    switch (IoControlCode) {
    case IOCTL_KBFILTR_GET_KEYBOARD_ATTRIBUTES:
        
        //
        // Buffer is too small, fail the request
        //
        if (OutputBufferLength < sizeof(KEYBOARD_ATTRIBUTES)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory);
        
        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed %x\n", status));
            break;
        }
        
        status = WdfMemoryCopyFromBuffer(outputMemory,
                                    0,
                                    &devExt->KeyboardAttributes,
                                    sizeof(KEYBOARD_ATTRIBUTES));

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfMemoryCopyFromBuffer failed %x\n", status));
            break;
        }

        bytesTransferred = sizeof(KEYBOARD_ATTRIBUTES);
        
        break;    
    default:
        status = STATUS_NOT_IMPLEMENTED;
        break;
    }
    
    WdfRequestCompleteWithInformation(Request, status, bytesTransferred);

    return;
}

VOID
KbFilter_EvtIoInternalDeviceControl(
    IN WDFQUEUE      Queue,
    IN WDFREQUEST    Request,
    IN size_t        OutputBufferLength,
    IN size_t        InputBufferLength,
    IN ULONG         IoControlCode
    )
/*++

Routine Description:

    This routine is the dispatch routine for internal device control requests.
    There are two specific control codes that are of interest:

    IOCTL_INTERNAL_KEYBOARD_CONNECT:
        Store the old context and function pointer and replace it with our own.
        This makes life much simpler than intercepting IRPs sent by the RIT and
        modifying them on the way back up.

    IOCTL_INTERNAL_I8042_HOOK_KEYBOARD:
        Add in the necessary function pointers and context values so that we can
        alter how the ps/2 keyboard is initialized.

    NOTE:  Handling IOCTL_INTERNAL_I8042_HOOK_KEYBOARD is *NOT* necessary if
           all you want to do is filter KEYBOARD_INPUT_DATAs.  You can remove
           the handling code and all related device extension fields and
           functions to conserve space.

Arguments:

    Queue - Handle to the framework queue object that is associated
            with the I/O request.
    Request - Handle to a framework request object.

    OutputBufferLength - length of the request's output buffer,
                        if an output buffer is available.
    InputBufferLength - length of the request's input buffer,
                        if an input buffer is available.

    IoControlCode - the driver-defined or system-defined I/O control code
                    (IOCTL) that is associated with the request.

Return Value:

   VOID

--*/
{
    PDEVICE_EXTENSION               devExt;
    PINTERNAL_I8042_HOOK_KEYBOARD   hookKeyboard = NULL;
    PCONNECT_DATA                   connectData = NULL;
    NTSTATUS                        status = STATUS_SUCCESS;
    size_t                          length;
    WDFDEVICE                       hDevice;
    BOOLEAN                         forwardWithCompletionRoutine = FALSE;
    BOOLEAN                         ret = TRUE;
    WDFCONTEXT                      completionContext = WDF_NO_CONTEXT;
    WDF_REQUEST_SEND_OPTIONS        options;
    WDFMEMORY                       outputMemory;
    UNREFERENCED_PARAMETER(OutputBufferLength);
    UNREFERENCED_PARAMETER(InputBufferLength);


    PAGED_CODE();

    DebugPrint(("Entered KbFilter_EvtIoInternalDeviceControl\n"));

    hDevice = WdfIoQueueGetDevice(Queue);
    devExt = FilterGetData(hDevice);

    switch (IoControlCode) {

    //
    // Connect a keyboard class device driver to the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_CONNECT:
        //
        // Only allow one connection.
        //
        if (devExt->UpperConnectData.ClassService != NULL) {
            status = STATUS_SHARING_VIOLATION;
            break;
        }

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer).
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                                    sizeof(CONNECT_DATA),
                                    &connectData,
                                    &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        NT_ASSERT(length == InputBufferLength);

        devExt->UpperConnectData = *connectData;

        //
        // Hook into the report chain.  Everytime a keyboard packet is reported
        // to the system, KbFilter_ServiceCallback will be called
        //

        connectData->ClassDeviceObject = WdfDeviceWdmGetDeviceObject(hDevice);

#pragma warning(disable:4152)  //nonstandard extension, function/data pointer conversion

        connectData->ClassService = KbFilter_ServiceCallback;

#pragma warning(default:4152)

        break;

    //
    // Disconnect a keyboard class device driver from the port driver.
    //
    case IOCTL_INTERNAL_KEYBOARD_DISCONNECT:

        //
        // Clear the connection parameters in the device extension.
        //
        // devExt->UpperConnectData.ClassDeviceObject = NULL;
        // devExt->UpperConnectData.ClassService = NULL;

        status = STATUS_NOT_IMPLEMENTED;
        break;

    //
    // Attach this driver to the initialization and byte processing of the
    // i8042 (ie PS/2) keyboard.  This is only necessary if you want to do PS/2
    // specific functions, otherwise hooking the CONNECT_DATA is sufficient
    //
    case IOCTL_INTERNAL_I8042_HOOK_KEYBOARD:

        DebugPrint(("hook keyboard received!\n"));

        //
        // Get the input buffer from the request
        // (Parameters.DeviceIoControl.Type3InputBuffer)
        //
        status = WdfRequestRetrieveInputBuffer(Request,
                            sizeof(INTERNAL_I8042_HOOK_KEYBOARD),
                            &hookKeyboard,
                            &length);
        if(!NT_SUCCESS(status)){
            DebugPrint(("WdfRequestRetrieveInputBuffer failed %x\n", status));
            break;
        }

        NT_ASSERT(length == InputBufferLength);

        //
        // Enter our own initialization routine and record any Init routine
        // that may be above us.  Repeat for the isr hook
        //
        devExt->UpperContext = hookKeyboard->Context;

        //
        // replace old Context with our own
        //
        hookKeyboard->Context = (PVOID) devExt;

        if (hookKeyboard->InitializationRoutine) {
            devExt->UpperInitializationRoutine =
                hookKeyboard->InitializationRoutine;
        }
        hookKeyboard->InitializationRoutine =
            (PI8042_KEYBOARD_INITIALIZATION_ROUTINE)
            KbFilter_InitializationRoutine;

        if (hookKeyboard->IsrRoutine) {
            devExt->UpperIsrHook = hookKeyboard->IsrRoutine;
        }
        hookKeyboard->IsrRoutine = (PI8042_KEYBOARD_ISR) KbFilter_IsrHook;

        //
        // Store all of the other important stuff
        //
        devExt->IsrWritePort = hookKeyboard->IsrWritePort;
        devExt->QueueKeyboardPacket = hookKeyboard->QueueKeyboardPacket;
        devExt->CallContext = hookKeyboard->CallContext;

        status = STATUS_SUCCESS;
        break;


    case IOCTL_KEYBOARD_QUERY_ATTRIBUTES:
        forwardWithCompletionRoutine = TRUE;
        completionContext = devExt;
        break;
        
    //
    // Might want to capture these in the future.  For now, then pass them down
    // the stack.  These queries must be successful for the RIT to communicate
    // with the keyboard.
    //
    case IOCTL_KEYBOARD_QUERY_INDICATOR_TRANSLATION:
    case IOCTL_KEYBOARD_QUERY_INDICATORS:
    case IOCTL_KEYBOARD_SET_INDICATORS:
    case IOCTL_KEYBOARD_QUERY_TYPEMATIC:
    case IOCTL_KEYBOARD_SET_TYPEMATIC:
        break;
    }

    if (!NT_SUCCESS(status)) {
        WdfRequestComplete(Request, status);
        return;
    }

    //
    // Forward the request down. WdfDeviceGetIoTarget returns
    // the default target, which represents the device attached to us below in
    // the stack.
    //

    if (forwardWithCompletionRoutine) {

        //
        // Format the request with the output memory so the completion routine
        // can access the return data in order to cache it into the context area
        //
        
        status = WdfRequestRetrieveOutputMemory(Request, &outputMemory); 

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfRequestRetrieveOutputMemory failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }

        status = WdfIoTargetFormatRequestForInternalIoctl(WdfDeviceGetIoTarget(hDevice),
                                                         Request,
                                                         IoControlCode,
                                                         NULL,
                                                         NULL,
                                                         outputMemory,
                                                         NULL);

        if (!NT_SUCCESS(status)) {
            DebugPrint(("WdfIoTargetFormatRequestForInternalIoctl failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
            return;
        }
    
        // 
        // Set our completion routine with a context area that we will save
        // the output data into
        //
        WdfRequestSetCompletionRoutine(Request,
                                    KbFilterRequestCompletionRoutine,
                                    completionContext);

        ret = WdfRequestSend(Request,
                             WdfDeviceGetIoTarget(hDevice),
                             WDF_NO_SEND_OPTIONS);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint( ("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }

    }
    else
    {

        //
        // We are not interested in post processing the IRP so 
        // fire and forget.
        //
        WDF_REQUEST_SEND_OPTIONS_INIT(&options,
                                      WDF_REQUEST_SEND_OPTION_SEND_AND_FORGET);

        ret = WdfRequestSend(Request, WdfDeviceGetIoTarget(hDevice), &options);

        if (ret == FALSE) {
            status = WdfRequestGetStatus (Request);
            DebugPrint(("WdfRequestSend failed: 0x%x\n", status));
            WdfRequestComplete(Request, status);
        }
        
    }

    return;
}

NTSTATUS
KbFilter_InitializationRoutine(
    IN PVOID                           InitializationContext,
    IN PVOID                           SynchFuncContext,
    IN PI8042_SYNCH_READ_PORT          ReadPort,
    IN PI8042_SYNCH_WRITE_PORT         WritePort,
    OUT PBOOLEAN                       TurnTranslationOn
    )
/*++

Routine Description:

    This routine gets called after the following has been performed on the kb
    1)  a reset
    2)  set the typematic
    3)  set the LEDs

    i8042prt specific code, if you are writing a packet only filter driver, you
    can remove this function

Arguments:

    DeviceObject - Context passed during IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

    SynchFuncContext - Context to pass when calling Read/WritePort

    Read/WritePort - Functions to synchronoulsy read and write to the kb

    TurnTranslationOn - If TRUE when this function returns, i8042prt will not
                        turn on translation on the keyboard

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION   devExt;
    NTSTATUS            status = STATUS_SUCCESS;

    devExt = (PDEVICE_EXTENSION)InitializationContext;

    //
    // Do any interesting processing here.  We just call any other drivers
    // in the chain if they exist.  Make sure Translation is turned on as well
    //
    if (devExt->UpperInitializationRoutine) {
        status = (*devExt->UpperInitializationRoutine) (
                        devExt->UpperContext,
                        SynchFuncContext,
                        ReadPort,
                        WritePort,
                        TurnTranslationOn
                        );

        if (!NT_SUCCESS(status)) {
            return status;
        }
    }

    *TurnTranslationOn = TRUE;
    return status;
}

BOOLEAN
KbFilter_IsrHook(
    PVOID                  IsrContext,
    PKEYBOARD_INPUT_DATA   CurrentInput,
    POUTPUT_PACKET         CurrentOutput,
    UCHAR                  StatusByte,
    PUCHAR                 DataByte,
    PBOOLEAN               ContinueProcessing,
    PKEYBOARD_SCAN_STATE   ScanState
    )
/*++

Routine Description:

    This routine gets called at the beginning of processing of the kb interrupt.

    i8042prt specific code, if you are writing a packet only filter driver, you
    can remove this function

Arguments:

    DeviceObject - Our context passed during IOCTL_INTERNAL_I8042_HOOK_KEYBOARD

    CurrentInput - Current input packet being formulated by processing all the
                    interrupts

    CurrentOutput - Current list of bytes being written to the keyboard or the
                    i8042 port.

    StatusByte    - Byte read from I/O port 60 when the interrupt occurred

    DataByte      - Byte read from I/O port 64 when the interrupt occurred.
                    This value can be modified and i8042prt will use this value
                    if ContinueProcessing is TRUE

    ContinueProcessing - If TRUE, i8042prt will proceed with normal processing of
                         the interrupt.  If FALSE, i8042prt will return from the
                         interrupt after this function returns.  Also, if FALSE,
                         it is this functions responsibilityt to report the input
                         packet via the function provided in the hook IOCTL or via
                         queueing a DPC within this driver and calling the
                         service callback function acquired from the connect IOCTL

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION devExt;
    BOOLEAN           retVal = TRUE;

    devExt = (PDEVICE_EXTENSION)IsrContext;

    if (devExt->UpperIsrHook) {
        retVal = (*devExt->UpperIsrHook) (
                        devExt->UpperContext,
                        CurrentInput,
                        CurrentOutput,
                        StatusByte,
                        DataByte,
                        ContinueProcessing,
                        ScanState
                        );

        if (!retVal || !(*ContinueProcessing)) {
            return retVal;
        }
    }

    *ContinueProcessing = TRUE;
    return retVal;
}

void updateKey(PDEVICE_EXTENSION devExt, KeyStruct data) {
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (devExt->currentKeys[i].InternalFlags & INTFLAG_REMOVED) {
            RtlZeroMemory(&devExt->currentKeys[i], sizeof(devExt->currentKeys[0])); //Remove any keys marked to be removed
        }
    }

    KeyStruct origData = data;
    //Apply any remaps if they were done
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (devExt->remappedKeys[i].origKey.MakeCode == data.MakeCode &&
            devExt->remappedKeys[i].origKey.Flags == (data.Flags & KEY_TYPES)) {
            data.MakeCode = devExt->remappedKeys[i].remappedKey.MakeCode;
            data.Flags = devExt->remappedKeys[i].remappedKey.Flags | (data.Flags & ~KEY_TYPES);
            break;
        }
    }

    garbageCollect(devExt);

    data.Flags = data.Flags & (KEY_TYPES | KEY_BREAK);
    if (data.Flags & KEY_BREAK) { //remove
        data.Flags = data.Flags & KEY_TYPES;
        origData.Flags = origData.Flags & KEY_TYPES;
        if (devExt->lastKeyPressed.MakeCode == data.MakeCode &&
            devExt->lastKeyPressed.Flags == data.Flags) {
            RtlZeroMemory(&devExt->lastKeyPressed, sizeof(devExt->lastKeyPressed));
        }

        for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
            if (devExt->currentKeys[i].MakeCode == data.MakeCode &&
                devExt->currentKeys[i].Flags == data.Flags) {
                for (int j = 0; j < MAX_CURRENT_KEYS; j++) { //Remove any remaps if the original key is to be removed
                    if (devExt->remappedKeys[j].origKey.MakeCode == origData.MakeCode &&
                        devExt->remappedKeys[j].origKey.Flags == origData.Flags) {
                        RtlZeroMemory(&devExt->remappedKeys[j], sizeof(devExt->remappedKeys[0]));
                    }
                }

                devExt->currentKeys[i].InternalFlags |= INTFLAG_REMOVED;
            }
        }
    }
    else if (!devExt->tabletMode) {
        for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
            if (devExt->currentKeys[i].Flags == 0x00 && devExt->currentKeys[i].MakeCode == 0x00) {
                devExt->currentKeys[i] = data;
                devExt->currentKeys[i].InternalFlags |= INTFLAG_NEW;
                devExt->numKeysPressed++;
                devExt->lastKeyPressed = data;
                break;
            }
            else if (devExt->currentKeys[i].Flags == data.Flags && devExt->currentKeys[i].MakeCode == data.MakeCode) {
                break;
            }
        }
    }
}

BOOLEAN addRemap(PDEVICE_EXTENSION devExt, RemappedKeyStruct remap) {
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (devExt->remappedKeys[i].origKey.MakeCode == remap.origKey.MakeCode &&
            devExt->remappedKeys[i].origKey.Flags == remap.remappedKey.Flags) {
            if (memcmp(&devExt->remappedKeys[i], &remap, sizeof(remap)) == 0) {
                return TRUE; //already exists
            }
            else {
                return FALSE; //existing remap exists but not the same
            }
        }
    }

    garbageCollect(devExt);

    const RemappedKeyStruct emptyStruct = { 0 };
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (memcmp(&devExt->remappedKeys[i], &emptyStruct, sizeof(emptyStruct)) == 0) {
            devExt->remappedKeys[i] = remap;


            //Now apply remap
            for (int j = 0; j < MAX_CURRENT_KEYS; j++) {
                if (devExt->currentKeys[j].MakeCode == remap.origKey.MakeCode &&
                    devExt->currentKeys[j].Flags == remap.origKey.Flags) {
                    devExt->currentKeys[j].MakeCode = remap.remappedKey.MakeCode;
                    devExt->currentKeys[j].Flags = remap.remappedKey.Flags;
                    break;
                }
            }

            return TRUE;
        }
    }
    return FALSE; //no slot found
}

void garbageCollect(PDEVICE_EXTENSION devExt) {
    //Clear out any empty remap slots
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        RemappedKeyStruct keyRemaps[MAX_CURRENT_KEYS] = { 0 };
        const RemappedKeyStruct emptyStruct = { 0 };
        int j = 0;
        for (int k = 0; k < MAX_CURRENT_KEYS; k++) {
            if (memcmp(&devExt->remappedKeys[k], &emptyStruct, sizeof(emptyStruct)) != 0) {
                keyRemaps[j] = devExt->remappedKeys[k];
                j++;
            }
        }
        devExt->numRemaps = j;
        RtlCopyMemory(&devExt->remappedKeys, keyRemaps, sizeof(keyRemaps));
    }

    //Clear out any empty key slots
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        KeyStruct keyCodes[MAX_CURRENT_KEYS] = { 0 };
        int j = 0;
        for (int k = 0; k < MAX_CURRENT_KEYS; k++) {
            if (devExt->currentKeys[k].Flags != 0 ||
                devExt->currentKeys[k].MakeCode != 0) {
                keyCodes[j] = devExt->currentKeys[k];
                j++;
            }
        }
        devExt->numKeysPressed = j;
        RtlCopyMemory(&devExt->currentKeys, keyCodes, sizeof(keyCodes));
    }
}

UINT8 MapHIDKeys(KEYBOARD_INPUT_DATA report[MAX_CURRENT_KEYS], int* reportSize) {
    UINT8 flag = 0;
    for (int i = 0; i < *reportSize; i++) {
        if ((report[i].Flags & KEY_TYPES) == KEY_E0) {
            switch (report->MakeCode) {
            case VIVALDI_BRIGHTNESSDN:
                if (!(report[i].Flags & KEY_BREAK))
                    flag |= CROSKBHID_BRIGHTNESS_DN;
                break;
            case VIVALDI_BRIGHTNESSUP:
                if (!(report[i].Flags & KEY_BREAK))
                    flag |= CROSKBHID_BRIGHTNESS_UP;
                break;
            case VIVALDI_KBD_BKLIGHT_DOWN:
                if (!(report[i].Flags & KEY_BREAK))
                    flag |= CROSKBHID_KBLT_DN;
                break;
            case VIVALDI_KBD_BKLIGHT_UP:
                if (!(report[i].Flags & KEY_BREAK))
                    flag |= CROSKBHID_KBLT_UP;
                break;
            case VIVALDI_KBD_BKLIGHT_TOGGLE:
                if (!(report[i].Flags & KEY_BREAK))
                    flag |= CROSKBHID_KBLT_TOGGLE;
                break;
            default:
                continue;
            }
            report[i].MakeCode = 0;
            report[i].Flags = 0;
        }
    }

    //GC the new Report
    KEYBOARD_INPUT_DATA newReport[MAX_CURRENT_KEYS];
    int newSize = 0;
    for (int i = 0; i < *reportSize; i++) {
        if (report[i].Flags != 0 || report[i].MakeCode != 0) {
            newReport[newSize] = report[i];
            newSize++;
        }
    }

    RtlCopyMemory(report, newReport, sizeof(newReport[0]) * newSize);
    *reportSize = newSize;

    return flag;
}

BOOLEAN checkKey(KEYBOARD_INPUT_DATA key, KeyStruct report[MAX_CURRENT_KEYS]) {
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (report[i].MakeCode == key.MakeCode &&
            report[i].Flags == (key.Flags & KEY_TYPES)) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN addKey(KEYBOARD_INPUT_DATA key, KEYBOARD_INPUT_DATA data[MAX_CURRENT_KEYS]) {
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (data[i].MakeCode == key.MakeCode &&
            data[i].Flags == (key.Flags & KEY_TYPES)) {
            return data[i].Flags == key.Flags; //If both contain the same bit value of BREAK, we're ok. Otherwise we're not
        }
        else if (data[i].MakeCode == 0 && data[i].Flags == 0) {
            data[i] = key;
            return TRUE;
        }
    }
    return FALSE;
}

int CompareKeys(const void* raw1, const void* raw2) {
    PKEYBOARD_INPUT_DATA data1 = (PKEYBOARD_INPUT_DATA)raw1;
    PKEYBOARD_INPUT_DATA data2 = (PKEYBOARD_INPUT_DATA)raw2;
    return ((data1->MakeCode - data2->MakeCode) << 4) +
        ((data2->Flags & (KEY_E0 | KEY_E1) - (data1->Flags & (KEY_E0 | KEY_E1))));
}

static BOOLEAN validateBool(RemapCfgKeyState keyState, BOOLEAN containerBOOL) {
    if (keyState == RemapCfgKeyStateNoDetect) {
        return TRUE;
    }

    if ((keyState == RemapCfgKeyStateEnforce && containerBOOL) ||
        (keyState == RemapCfgKeyStateEnforceNot && !containerBOOL)) {
        return TRUE;
    }

    return FALSE;
}

static  INT32 IdxOfFnKey(PDEVICE_EXTENSION devExt, RemapCfgKey originalKey) {
    if (originalKey.Flags != KEY_E0) {
        return -1;
    }

    for (int i = 0; i < devExt->functionRowCount; i++) {
        if (devExt->functionRowKeys[i].MakeCode == originalKey.MakeCode) {
            return i;
        }
    }

    return -1;
}

//Use configuration loaded from settings
void RemapLoaded(PDEVICE_EXTENSION devExt, KEYBOARD_INPUT_DATA data[MAX_CURRENT_KEYS], KEYBOARD_INPUT_DATA dataBefore[MAX_CURRENT_KEYS], KEYBOARD_INPUT_DATA dataAfter[MAX_CURRENT_KEYS]) {
    if (!devExt->remapCfgs || devExt->remapCfgs->magic != REMAP_CFG_MAGIC)
        return;

    for (int i = 0; i < devExt->numKeysPressed; i++) {
        for (UINT32 j = 0; j < devExt->remapCfgs->remappings; j++) {
            RemapCfg cfg = devExt->remapCfgs->cfg[j];

            if (!validateBool(cfg.LeftCtrl, devExt->LeftCtrlPressed))
                continue;
            if (!validateBool(cfg.LeftAlt, devExt->LeftAltPressed))
                continue;
            if (!validateBool(cfg.LeftShift, devExt->LeftShiftPressed))
                continue;
            if (!validateBool(cfg.Assistant, devExt->AssistantPressed))
                continue;
            if (!validateBool(cfg.Search, devExt->SearchPressed))
                continue;
            if (!validateBool(cfg.RightCtrl, devExt->RightCtrlPressed))
                continue;
            if (!validateBool(cfg.RightAlt, devExt->RightAltPressed))
                continue;
            if (!validateBool(cfg.RightShift, devExt->RightShiftPressed))
                continue;

            if (data[i].MakeCode == cfg.originalKey.MakeCode &&
                (cfg.originalKey.Flags & KEY_TYPES) == (data[i].Flags & KEY_TYPES)) {

                RemappedKeyStruct remappedStruct = { 0 };
                remappedStruct.origKey.MakeCode = data[i].MakeCode;
                remappedStruct.origKey.Flags = data[i].Flags;

                INT32 fnKeyIdx = IdxOfFnKey(devExt, cfg.originalKey);
                if (cfg.remapVivaldiToFnKeys && fnKeyIdx != -1) {
                    remappedStruct.remappedKey.MakeCode = fnKeys_set1[fnKeyIdx];
                    remappedStruct.remappedKey.Flags = 0;
                    if (addRemap(devExt, remappedStruct)) {
                        data[i].Flags &= ~KEY_TYPES;
                        data[i].MakeCode = fnKeys_set1[fnKeyIdx];
                    }
                }
                else {
                    remappedStruct.remappedKey.MakeCode = cfg.remappedKey.MakeCode;
                    remappedStruct.remappedKey.Flags = (cfg.remappedKey.Flags & KEY_TYPES);
                    if (addRemap(devExt, remappedStruct)) {
                        data[i].Flags = (cfg.remappedKey.Flags & KEY_TYPES);
                        data[i].MakeCode = cfg.remappedKey.MakeCode;
                    }

                    for (int k = 0; k < sizeof(cfg.additionalKeys) / sizeof(cfg.additionalKeys[0]); k++) {
                        if ((cfg.additionalKeys[k].Flags & (KEY_TYPES | KEY_BREAK)) == 0 && cfg.additionalKeys[k].MakeCode == 0) {
                            break;
                        }

                        KEYBOARD_INPUT_DATA addData = { 0 };
                        addData.MakeCode = cfg.additionalKeys[k].MakeCode;
                        addData.Flags = cfg.additionalKeys[k].Flags & (KEY_TYPES | KEY_BREAK);
                        addKey(addData, dataBefore);

                        KEYBOARD_INPUT_DATA removeData = { 0 };
                        removeData.MakeCode = addData.MakeCode;
                        removeData.Flags = cfg.additionalKeys[k].Flags & KEY_TYPES;
                        if ((addData.Flags & KEY_BREAK) == 0) {
                            removeData.Flags |= KEY_BREAK;
                        }
                        addKey(removeData, dataAfter);
                    }
                }

                break;
            }
        }
    }
}

VOID
KbFilter_ServiceCallback(
    IN PDEVICE_OBJECT  DeviceObject,
    IN PKEYBOARD_INPUT_DATA InputDataStart,
    IN PKEYBOARD_INPUT_DATA InputDataEnd,
    IN OUT PULONG InputDataConsumed
    )
/*++

Routine Description:

    Called when there are keyboard packets to report to the Win32 subsystem.
    You can do anything you like to the packets.  For instance:

    o Drop a packet altogether
    o Mutate the contents of a packet
    o Insert packets into the stream

Arguments:

    DeviceObject - Context passed during the connect IOCTL

    InputDataStart - First packet to be reported

    InputDataEnd - One past the last packet to be reported.  Total number of
                   packets is equal to InputDataEnd - InputDataStart

    InputDataConsumed - Set to the total number of packets consumed by the RIT
                        (via the function pointer we replaced in the connect
                        IOCTL)

Return Value:

    Status is returned.

--*/
{
    PDEVICE_EXTENSION   devExt;
    WDFDEVICE   hDevice;

    hDevice = WdfWdmDeviceGetWdfDeviceHandle(DeviceObject);

    devExt = FilterGetData(hDevice);

    PKEYBOARD_INPUT_DATA pData;
    for (pData = InputDataStart; pData != InputDataEnd; pData++) { //First loop -> Refresh Modifier Keys and Change Legacy Keys to vivaldi bindings
        if (pData->MakeCode == WILCO_ASSISTANT && (pData->Flags & KEY_TYPES) == KEY_E0) { //Wilco uses different Assistant Key
            pData->MakeCode = K_ASSISTANT;
        }
        if (devExt->hasAssistantKey && devExt->remapCfgs != NULL && devExt->remapCfgs->FlipSearchAndAssistantOnPixelbook) {
            if (pData->MakeCode == K_ASSISTANT && (pData->Flags & KEY_TYPES) == KEY_E0) {
                pData->MakeCode = K_LWIN;
            }
            else if (pData->MakeCode == K_LWIN && (pData->Flags & KEY_TYPES) == KEY_E0) {
                pData->MakeCode = K_ASSISTANT;
            }
        }

        if ((pData->Flags & KEY_TYPES) == 0) {
            switch (pData->MakeCode)
            {
            case K_LCTRL: //L CTRL
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->LeftCtrlPressed = TRUE;
                }
                else {
                    devExt->LeftCtrlPressed = FALSE;
                }
                break;
            case K_LALT: //L Alt
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->LeftAltPressed = TRUE;
                }
                else {
                    devExt->LeftAltPressed = FALSE;
                }
                break;
            case K_LSHFT: //L Shift
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->LeftShiftPressed = TRUE;
                }
                else {
                    devExt->LeftShiftPressed = FALSE;
                }
                break;
            default:
                if (!devExt->isNonChromeEC) {
                    for (int i = 0; i < sizeof(devExt->legacyTopRowKeys); i++) {
                        if (pData->MakeCode == devExt->legacyTopRowKeys[i]) {
                            pData->MakeCode = devExt->legacyVivaldi[i];
                            pData->Flags |= KEY_E0; //All legacy vivaldi upgrades use E0 modifier
                        }
                    }
                }

                break;
            }
        }
        if ((pData->Flags & KEY_TYPES) == KEY_E0) {
            switch (pData->MakeCode)
            {
            case K_ASSISTANT: //Assistant Key
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->AssistantPressed = TRUE;
                }
                else {
                    devExt->AssistantPressed = FALSE;
                }
                break;
            case K_LWIN: //Search Key
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->SearchPressed = TRUE;
                }
                else {
                    devExt->SearchPressed = FALSE;
                }
                break;
            case K_RCTRL: //R CTRL
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->RightCtrlPressed = TRUE;
                }
                else {
                    devExt->RightCtrlPressed = FALSE;
                }
                break;
            case K_RALT: //R Alt
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->RightAltPressed = TRUE;
                }
                else {
                    devExt->RightAltPressed = FALSE;
                }
                break;

            }
        }
    }

    {
        //Now make the data HID-like for easier handling
        ULONG i = 0;
        for (i = 0; i < (InputDataEnd - InputDataStart); i++) {
            KeyStruct key = { 0 };
            key.MakeCode = InputDataStart[i].MakeCode;
            key.Flags = InputDataStart[i].Flags;
            updateKey(devExt, key);
        }
        *InputDataConsumed = i;
    }

    KEYBOARD_INPUT_DATA newReport[MAX_CURRENT_KEYS] = { 0 };
    //Add new keys
    for (int i = 0, j = 0; i < devExt->numKeysPressed; i++) { //Prepare new report for remapper to sort through
        if (devExt->currentKeys[i].InternalFlags & INTFLAG_NEW) {
            newReport[j].MakeCode = devExt->currentKeys[i].MakeCode;
            newReport[j].Flags = devExt->currentKeys[i].Flags;
            devExt->currentKeys[i].InternalFlags &= ~INTFLAG_NEW;
            j++;
        }
    }

    KEYBOARD_INPUT_DATA preReport[MAX_CURRENT_KEYS] = { 0 };
    KEYBOARD_INPUT_DATA postReport[MAX_CURRENT_KEYS] = { 0 };

    //Do whichever remap was chosen
    RemapLoaded(devExt, newReport, preReport, postReport);

    //Remove any empty keys
    int newReportKeysPresent = 0;
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (newReport[i].Flags != 0 ||
            newReport[i].MakeCode != 0) {
            newReport[newReportKeysPresent] = newReport[i];
            newReportKeysPresent++;
        }
    }

    for (int i = newReportKeysPresent; i < MAX_CURRENT_KEYS; i++) {
        RtlZeroMemory(&newReport[i], sizeof(newReport[i]));
    }

    //Now add all the removed keys
    int reportSize = newReportKeysPresent;
    for (int i = 0; i < devExt->numKeysPressed; i++) { //Prepare new report for remapper to sort through
        if (devExt->currentKeys[i].InternalFlags & INTFLAG_REMOVED) {
            newReport[reportSize].MakeCode = devExt->currentKeys[i].MakeCode;
            newReport[reportSize].Flags = devExt->currentKeys[i].Flags | KEY_BREAK;
            reportSize++;
        }
    }

    //If empty report keys, add the last key (if present)
    if (reportSize == 0 && (devExt->lastKeyPressed.MakeCode != 0 || devExt->lastKeyPressed.Flags != 0)) {
        newReport[reportSize].MakeCode = devExt->lastKeyPressed.MakeCode;
        newReport[reportSize].Flags = devExt->lastKeyPressed.Flags;

        for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
            if (devExt->remappedKeys[i].origKey.MakeCode == devExt->lastKeyPressed.MakeCode &&
                devExt->remappedKeys[i].origKey.Flags == (devExt->lastKeyPressed.Flags & KEY_TYPES)) {
                newReport[reportSize].MakeCode = devExt->remappedKeys[i].remappedKey.MakeCode;
                newReport[reportSize].Flags = devExt->remappedKeys[i].remappedKey.Flags | (newReport[reportSize].Flags & ~KEY_TYPES);
                break;
            }
        }

        reportSize++;
    }

    //Now prepare the report
    for (int i = 0; i < reportSize; i++) {
        newReport[i].UnitId = InputDataStart[0].UnitId;

        //Always override Vivaldi Play/Pause to Windows native equivalent
        if (newReport[i].MakeCode == VIVALDI_PLAYPAUSE &&
            (newReport[i].Flags & KEY_TYPES) == KEY_E0) {
            newReport[i].MakeCode = 0x22; //Windows native Play / Pause Code
        }
    }

    UINT8 HIDFlag = MapHIDKeys(newReport, &reportSize);
    if (devExt->HidReportProcessCallback) {
        CrosKBHIDRemapperMediaReport mediaReport = { 0 };
        mediaReport.ReportID = REPORTID_MEDIA;
        mediaReport.ControlCode = HIDFlag;
        size_t bytesWritten;
        (*devExt->HidReportProcessCallback)(devExt->HIDContext, &mediaReport, sizeof(mediaReport), &bytesWritten);
    }

    ULONG DataConsumed;

    {
        int preReportSize = 0;
        for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
            if (preReport[i].Flags != 0 || preReport[i].MakeCode != 0) {
                preReportSize++;
            }
        }

        if (preReportSize > 0) {
            (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
                devExt->UpperConnectData.ClassDeviceObject,
                preReport,
                preReport + preReportSize,
                &DataConsumed);
        }
    }

    if (reportSize > 0) {
        (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
            devExt->UpperConnectData.ClassDeviceObject,
            newReport,
            newReport + reportSize,
            &DataConsumed);
    }

    {
        int postReportSize = 0;
        for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
            if (postReport[i].Flags != 0 || postReport[i].MakeCode != 0) {
                postReportSize++;
            }
        }

        if (postReportSize > 0) {
            (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
                devExt->UpperConnectData.ClassDeviceObject,
                postReport,
                postReport + postReportSize,
                &DataConsumed);
        }
    }
}

VOID
KbFilterRequestCompletionRoutine(
    WDFREQUEST                  Request,
    WDFIOTARGET                 Target,
    PWDF_REQUEST_COMPLETION_PARAMS CompletionParams,
    WDFCONTEXT                  Context
   )
/*++

Routine Description:

    Completion Routine

Arguments:

    Target - Target handle
    Request - Request handle
    Params - request completion params
    Context - Driver supplied context


Return Value:

    VOID

--*/
{
    WDFMEMORY   buffer = CompletionParams->Parameters.Ioctl.Output.Buffer;
    NTSTATUS    status = CompletionParams->IoStatus.Status;

    UNREFERENCED_PARAMETER(Target);
 
    //
    // Save the keyboard attributes in our context area so that we can return
    // them to the app later.
    //
    if (NT_SUCCESS(status) && 
        CompletionParams->Type == WdfRequestTypeDeviceControlInternal &&
        CompletionParams->Parameters.Ioctl.IoControlCode == IOCTL_KEYBOARD_QUERY_ATTRIBUTES) {

        if( CompletionParams->Parameters.Ioctl.Output.Length >= sizeof(KEYBOARD_ATTRIBUTES)) {
            
            status = WdfMemoryCopyToBuffer(buffer,
                                           CompletionParams->Parameters.Ioctl.Output.Offset,
                                           &((PDEVICE_EXTENSION)Context)->KeyboardAttributes,
                                            sizeof(KEYBOARD_ATTRIBUTES)
                                          );
        }
    }

    WdfRequestComplete(Request, status);

    return;
}


