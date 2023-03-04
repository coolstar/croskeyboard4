#include <windows.h>
#include <hidsdi.h>
#include <setupapi.h>
#include <stdio.h>
#include <stdlib.h>

#include "croskbhid.h"

#if __GNUC__
#define __in
#define __in_ecount(x)
typedef void* PVOID;
typedef PVOID HDEVINFO;
WINHIDSDI BOOL WINAPI HidD_SetOutputReport(HANDLE, PVOID, ULONG);
#endif

typedef struct _croskbhid_client_t
{
	HANDLE hSettings;
} croskbhid_client_t;

//
// Function prototypes
//

HANDLE
SearchMatchingHwID(
	USHORT vendorID,
	USHORT productID,
	USAGE myUsagePage,
	USAGE myUsage
);

HANDLE
OpenDeviceInterface(
	HDEVINFO HardwareDeviceInfo,
	PSP_DEVICE_INTERFACE_DATA DeviceInterfaceData,
	USHORT vendorID,
	USHORT productID,
	USAGE myUsagePage,
	USAGE myUsage
);

BOOLEAN
CheckIfOurDevice(
	HANDLE file,
	USHORT vendorID,
	USHORT productID,
	USAGE myUsagePage,
	USAGE myUsage
);

BOOL
HidOutput(
	BOOL useSetOutputReport,
	HANDLE file,
	PCHAR buffer,
	ULONG bufferSize
);

//
// Copied this structure from hidport.h
//

typedef struct _HID_DEVICE_ATTRIBUTES {

	ULONG           Size;
	//
	// sizeof (struct _HID_DEVICE_ATTRIBUTES)
	//
	//
	// Vendor ids of this hid device
	//
	USHORT          VendorID;
	USHORT          ProductID;
	USHORT          VersionNumber;
	USHORT          Reserved[11];

} HID_DEVICE_ATTRIBUTES, * PHID_DEVICE_ATTRIBUTES;

static USHORT TpVendorID = 0;

USHORT getVendorID() {
	return TpVendorID;
}

//
// Implementation
//

pcroskbhid_client croskbhid_alloc(void)
{
	return (pcroskbhid_client)malloc(sizeof(croskbhid_client_t));
}

void croskbhid_free(pcroskbhid_client croskbhid)
{
	free(croskbhid);
}

BOOL croskbhid_connect(pcroskbhid_client croskbhid)
{
	//
	// Find the HID devices
	//

	croskbhid->hSettings = SearchMatchingHwID(CROSKBHIDREMAPPER_VID, CROSKBHIDREMAPPER_PID, 0xff00, 0x0003);
	if (croskbhid->hSettings == INVALID_HANDLE_VALUE || croskbhid->hSettings == NULL)
	{
		croskbhid_disconnect(croskbhid);
		return FALSE;
	}

	//
	// Set the buffer count to 10 on the setting HID
	//

	if (!HidD_SetNumInputBuffers(croskbhid->hSettings, 10))
	{
		printf("failed HidD_SetNumInputBuffers %d\n", GetLastError());
		croskbhid_disconnect(croskbhid);
		return FALSE;
	}	
	return TRUE;
}

void croskbhid_disconnect(pcroskbhid_client croskbhid)
{
	if (croskbhid->hSettings != NULL)
		CloseHandle(croskbhid->hSettings);
	croskbhid->hSettings = NULL;
}

BOOL croskbhid_read_keyboard(pcroskbhid_client vmulti, CrosKBHIDRemapperSettingsReport* pReport)
{
	ULONG bytesRead;

	//
	// Read the report
	//

	if (!ReadFile(vmulti->hSettings, pReport, sizeof(CrosKBHIDRemapperSettingsReport), &bytesRead, NULL))
	{
		printf("failed ReadFile %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL croskbhid_write_keyboard(pcroskbhid_client croskbhid, CrosKBHIDRemapperSettingsReport* pReport)
{
	ULONG bytesWritten;

	//
	// Write the report
	//

	if (!WriteFile(croskbhid->hSettings, pReport, sizeof(CrosKBHIDRemapperSettingsReport), &bytesWritten, NULL))
	{
		printf("failed WriteFile %d\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

HANDLE
SearchMatchingHwID(
	USHORT vendorID,
	USHORT productID,
	USAGE myUsagePage,
	USAGE myUsage
)
{
	HDEVINFO                  hardwareDeviceInfo;
	SP_DEVICE_INTERFACE_DATA  deviceInterfaceData;
	SP_DEVINFO_DATA           devInfoData;
	GUID                      hidguid;
	int                       i;

	HidD_GetHidGuid(&hidguid);

	hardwareDeviceInfo =
		SetupDiGetClassDevs((LPGUID)&hidguid,
			NULL,
			NULL, // Define no
			(DIGCF_PRESENT |
				DIGCF_INTERFACEDEVICE));

	if (INVALID_HANDLE_VALUE == hardwareDeviceInfo)
	{
		printf("SetupDiGetClassDevs failed: %x\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	deviceInterfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

	devInfoData.cbSize = sizeof(SP_DEVINFO_DATA);

	//
	// Enumerate devices of this interface class
	//

	printf("\n....looking for our HID device (with UP=0x%x "
		"and Usage=0x%x)\n", myUsagePage, myUsage);

	for (i = 0; SetupDiEnumDeviceInterfaces(hardwareDeviceInfo,
		0, // No care about specific PDOs
		(LPGUID)&hidguid,
		i, //
		&deviceInterfaceData);
		i++)
	{

		//
		// Open the device interface and Check if it is our device
		// by matching the Usage page and Usage from Hid_Caps.
		// If this is our device then send the hid request.
		//

		HANDLE file = OpenDeviceInterface(hardwareDeviceInfo, &deviceInterfaceData, vendorID, productID, myUsagePage, myUsage);

		if (file != INVALID_HANDLE_VALUE)
		{
			SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);
			return file;
		}

		//
		//device was not found so loop around.
		//

	}

	printf("Failure: Could not find our HID device \n");

	SetupDiDestroyDeviceInfoList(hardwareDeviceInfo);

	return INVALID_HANDLE_VALUE;
}

HANDLE
OpenDeviceInterface(
	HDEVINFO hardwareDeviceInfo,
	PSP_DEVICE_INTERFACE_DATA deviceInterfaceData,
	USHORT vendorID,
	USHORT productID,
	USAGE myUsagePage,
	USAGE myUsage
)
{
	PSP_DEVICE_INTERFACE_DETAIL_DATA    deviceInterfaceDetailData = NULL;

	DWORD        predictedLength = 0;
	DWORD        requiredLength = 0;
	HANDLE       file = INVALID_HANDLE_VALUE;

	SetupDiGetDeviceInterfaceDetail(
		hardwareDeviceInfo,
		deviceInterfaceData,
		NULL, // probing so no output buffer yet
		0, // probing so output buffer length of zero
		&requiredLength,
		NULL
	); // not interested in the specific dev-node

	predictedLength = requiredLength;

	deviceInterfaceDetailData =
		(PSP_DEVICE_INTERFACE_DETAIL_DATA)malloc(predictedLength);

	if (!deviceInterfaceDetailData)
	{
		printf("Error: OpenDeviceInterface: malloc failed\n");
		goto cleanup;
	}

	deviceInterfaceDetailData->cbSize =
		sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA);

	if (!SetupDiGetDeviceInterfaceDetail(
		hardwareDeviceInfo,
		deviceInterfaceData,
		deviceInterfaceDetailData,
		predictedLength,
		&requiredLength,
		NULL))
	{
		printf("Error: SetupDiGetInterfaceDeviceDetail failed\n");
		free(deviceInterfaceDetailData);
		goto cleanup;
	}

	file = CreateFile(deviceInterfaceDetailData->DevicePath,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, // no SECURITY_ATTRIBUTES structure
		OPEN_EXISTING, // No special create flags
		0, // No special attributes
		NULL); // No template file

	if (INVALID_HANDLE_VALUE == file) {
		printf("Error: CreateFile failed: %d\n", GetLastError());
		goto cleanup;
	}

	if (CheckIfOurDevice(file, vendorID, productID, myUsagePage, myUsage)) {

		goto cleanup;

	}

	CloseHandle(file);

	file = INVALID_HANDLE_VALUE;

cleanup:

	free(deviceInterfaceDetailData);

	return file;

}


BOOLEAN
CheckIfOurDevice(
	HANDLE file,
	USHORT vendorID,
	USHORT productID,
	USAGE myUsagePage,
	USAGE myUsage)
{
	PHIDP_PREPARSED_DATA Ppd = NULL; // The opaque parser info describing this device
	HIDD_ATTRIBUTES                 Attributes; // The Attributes of this hid device.
	HIDP_CAPS                       Caps; // The Capabilities of this hid device.
	BOOLEAN                         result = FALSE;

	if (!HidD_GetPreparsedData(file, &Ppd))
	{
		printf("Error: HidD_GetPreparsedData failed \n");
		goto cleanup;
	}

	if (!HidD_GetAttributes(file, &Attributes))
	{
		printf("Error: HidD_GetAttributes failed \n");
		goto cleanup;
	}

	if (Attributes.VendorID == vendorID && Attributes.ProductID == productID)
	{
		TpVendorID = Attributes.VendorID;

		if (!HidP_GetCaps(Ppd, &Caps))
		{
			printf("Error: HidP_GetCaps failed \n");
			goto cleanup;
		}

		if ((Caps.UsagePage == myUsagePage) && (Caps.Usage == myUsage))
		{
			printf("Success: Found my device.. \n");
			result = TRUE;
		}
	}

cleanup:

	if (Ppd != NULL)
	{
		HidD_FreePreparsedData(Ppd);
	}

	return result;
}

BOOL
HidOutput(
	BOOL useSetOutputReport,
	HANDLE file,
	PCHAR buffer,
	ULONG bufferSize
)
{
	ULONG bytesWritten;
	if (useSetOutputReport)
	{
		//
		// Send Hid report thru HidD_SetOutputReport API
		//

		if (!HidD_SetOutputReport(file, buffer, bufferSize))
		{
			printf("failed HidD_SetOutputReport %d\n", GetLastError());
			return FALSE;
		}
	}
	else
	{
		if (!WriteFile(file, buffer, bufferSize, &bytesWritten, NULL))
		{
			printf("failed WriteFile %d\n", GetLastError());
			return FALSE;
		}
	}

	return TRUE;
}