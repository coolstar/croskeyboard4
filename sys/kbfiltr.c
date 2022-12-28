/*--

Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.


Module Name:

    kbfiltr.c

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

#include "kbfiltr.h"
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
    0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x57, 0x58
};

#define K_LCTRL     0x1D
#define K_LALT      0x38
#define K_LSHFT     0x2A

#define K_BACKSP    0xE
#define K_DELETE    0x53

#define K_UP        0x48
#define K_DOWN      0x50
#define K_LEFT      0x4B
#define K_RIGHT     0x4D

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
#define VIVALDI_KBD_BKLIGHT_DOWN    0x17
#define VIVALDI_KBD_BKLIGHT_UP      0x18
#define VIVALDI_KBD_BKLIGHT_TOGGLE  0x1e
#define VIVALDI_PLAYPAUSE           0x1A
#define VIVALDI_MUTE                0x20
#define VIVALDI_VOLDN               0x2e
#define VIVALDI_VOLUP               0x30

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
        DbgPrint("Loaded vivaldi settings with %d keys\n", pDevice->functionRowCount);
        for (int i = 0; i < pDevice->functionRowCount; i++) {
            DbgPrint("Key %d: 0x%x %d\n", i, pDevice->functionRowKeys[i].MakeCode, pDevice->functionRowKeys[i].Flags);
        }
    }
}

NTSTATUS
OnSelfManagedIoInit(
    _In_
    WDFDEVICE FxDevice
) {
    PDEVICE_EXTENSION       filterExt;
    filterExt = FilterGetData(FxDevice);

    NTSTATUS status = STATUS_SUCCESS;

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
            devExt->remappedKeys[i].origKey.Flags == (data.Flags & (KEY_E0 | KEY_E1))) {
            data.MakeCode = devExt->remappedKeys[i].remappedKey.MakeCode;
            data.Flags = devExt->remappedKeys[i].remappedKey.Flags | (data.Flags & ~(KEY_E0 | KEY_E1));
            break;
        }
    }

    garbageCollect(devExt);

    data.Flags = data.Flags & (KEY_E0 | KEY_E1 | KEY_BREAK);
    if (data.Flags & KEY_BREAK) { //remove
        data.Flags = data.Flags & (KEY_E0 | KEY_E1);
        origData.Flags = origData.Flags & (KEY_E0 | KEY_E1);
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
    else {
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

BOOLEAN checkKey(KEYBOARD_INPUT_DATA key, KeyStruct report[MAX_CURRENT_KEYS]) {
    for (int i = 0; i < MAX_CURRENT_KEYS; i++) {
        if (report[i].MakeCode == key.MakeCode &&
            report[i].Flags == (key.Flags & (KEY_E0 | KEY_E1))) {
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

//Only add Ctrl + Alt Backspace (like old EC)
void RemapPassthrough(PDEVICE_EXTENSION devExt, KEYBOARD_INPUT_DATA data[MAX_CURRENT_KEYS]) {
    for (int i = 0; i < devExt->numKeysPressed; i++) {
        for (int j = 0; j < devExt->functionRowCount; j++) { //Set back to F1 -> F12 for passthrough
            if (data[i].MakeCode == devExt->functionRowKeys[j].MakeCode &&
                data[i].Flags == devExt->functionRowKeys->Flags) {
                RemappedKeyStruct remappedStruct = { 0 }; //register remap
                remappedStruct.origKey.MakeCode = data[i].MakeCode;
                remappedStruct.origKey.Flags = data[i].Flags;
                remappedStruct.remappedKey.MakeCode = fnKeys_set1[j];

                if (addRemap(devExt, remappedStruct)) {
                    data[i].Flags &= ~(KEY_E0 | KEY_E1);
                    data[i].MakeCode = fnKeys_set1[j];
                }
            }
        }

        if (devExt->LeftCtrlPressed && devExt->LeftAltPressed &&
            data[i].MakeCode == K_BACKSP && data[i].Flags == 0) {
            RemappedKeyStruct remappedStruct = { 0 }; //register remap (Ctrl + Alt + Backspace => Ctrl + Alt + Delete)
            remappedStruct.origKey.MakeCode = data[i].MakeCode;
            remappedStruct.origKey.Flags = data[i].Flags;
            remappedStruct.remappedKey.MakeCode = K_DELETE;
            remappedStruct.remappedKey.Flags = KEY_E0;

            if (addRemap(devExt, remappedStruct)) {
                data[i].MakeCode = K_DELETE;
                data[i].Flags |= KEY_E0;
            }
        }
    }
}

//Behave like croskeyboard3 / croskbremap
void RemapLegacy(PDEVICE_EXTENSION devExt, KEYBOARD_INPUT_DATA data[MAX_CURRENT_KEYS]) {
    for (int i = 0; i < devExt->numKeysPressed; i++) {
        if (!devExt->LeftCtrlPressed) {
            for (int j = 0; j < devExt->functionRowCount; j++) { //Set back to F1 -> F12 for passthrough
                if (data[i].MakeCode == devExt->functionRowKeys[j].MakeCode &&
                    data[i].Flags == devExt->functionRowKeys->Flags) {
                    RemappedKeyStruct remappedStruct = { 0 }; //register remap
                    remappedStruct.origKey.MakeCode = data[i].MakeCode;
                    remappedStruct.origKey.Flags = data[i].Flags;
                    remappedStruct.remappedKey.MakeCode = fnKeys_set1[j];

                    if (addRemap(devExt, remappedStruct)) {
                        data[i].Flags &= ~(KEY_E0 | KEY_E1);
                        data[i].MakeCode = fnKeys_set1[j];
                    }
                }
            }
        }

        if (devExt->LeftCtrlPressed && devExt->LeftAltPressed &&
            data[i].MakeCode == K_BACKSP && data[i].Flags == 0) {
            RemappedKeyStruct remappedStruct = { 0 }; //register remap (Ctrl + Alt + Backspace => Ctrl + Alt + Delete)
            remappedStruct.origKey.MakeCode = data[i].MakeCode;
            remappedStruct.origKey.Flags = data[i].Flags;
            remappedStruct.remappedKey.MakeCode = K_DELETE;
            remappedStruct.remappedKey.Flags = KEY_E0;

            if (addRemap(devExt, remappedStruct)) {
                data[i].MakeCode = K_DELETE;
                data[i].Flags |= KEY_E0;
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
        if ((pData->Flags & (KEY_E0 | KEY_E1)) == 0) {
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
                for (int i = 0; i < sizeof(devExt->legacyTopRowKeys); i++) {
                    if (pData->MakeCode == devExt->legacyTopRowKeys[i]) {
                        pData->MakeCode = devExt->legacyVivaldi[i];
                        pData->Flags |= KEY_E0; //All legacy vivaldi upgrades use E0 modifier
                    }
                }

                break;
            }
        }
        if ((pData->Flags & (KEY_E0 | KEY_E1)) == KEY_E0) {
            if (pData->MakeCode == 0x5B) { //Search Key
                if ((pData->Flags & KEY_BREAK) == 0) {
                    devExt->SearchPressed = TRUE;
                }
                else {
                    devExt->SearchPressed = FALSE;
                }
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

    //Do whichever remap was chosen
    //RemapPassthrough(devExt, newReport);
    RemapLegacy(devExt, newReport);

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
        reportSize++;
    }

    //Now prepare the report
    for (int i = 0; i < reportSize; i++) {
        newReport[i].UnitId = InputDataStart[0].UnitId;
    }

    DbgPrint("HID -> PS/2 report size: %d. PS/2 report size: %d\n", reportSize, (ULONG)(InputDataEnd - InputDataStart));

    qsort(newReport, reportSize, sizeof(*newReport), CompareKeys);
    qsort(InputDataStart, InputDataEnd - InputDataStart, sizeof(*InputDataStart), CompareKeys);

    for (int i = 0; i < min(reportSize, InputDataEnd - InputDataStart); i++) {
        if (newReport[i].Flags != InputDataStart[i].Flags ||
            newReport[i].MakeCode != InputDataStart[i].MakeCode) {
            DbgPrint("\tExpected code 0x%x [flag %d]; Got code 0x%x [flag %d]\n", InputDataStart[i].MakeCode, InputDataStart[i].Flags, newReport[i].MakeCode, newReport[i].Flags);
        }
    }

    for (int i = 0; i < reportSize; i++) {
        BOOLEAN test = (newReport[i].MakeCode != newReport[i + 1].MakeCode ||
            (newReport[i].Flags & (KEY_E0 | KEY_E1)) != (newReport[i + 1].Flags & (KEY_E0 | KEY_E1)));
        if (!test) {
            DbgPrint("Found duplicate!!!. Flags? %d vs %d\n", newReport[i].Flags, newReport[i + 1].Flags);
        }
    }

    ULONG DataConsumed;

    if (reportSize > 0) {
        (*(PSERVICE_CALLBACK_ROUTINE)(ULONG_PTR)devExt->UpperConnectData.ClassService)(
            devExt->UpperConnectData.ClassDeviceObject,
            newReport,
            newReport + reportSize,
            &DataConsumed);
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


