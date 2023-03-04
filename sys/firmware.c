#include "firmware.h"
#include "croskeyboard.h"

NTSTATUS request_firmware(const struct firmware** img, PCWSTR path) {
	*img = NULL;

	struct firmware* fw = (struct firmware*)ExAllocatePoolZero(NonPagedPool, sizeof(struct firmware), KBFILTER_POOL_TAG);
	if (!fw) {
		return STATUS_NO_MEMORY;
	}
	RtlZeroMemory(fw, sizeof(struct firmware));

	NTSTATUS status;

	UNICODE_STRING     uniName;
	OBJECT_ATTRIBUTES  objAttr;

	RtlInitUnicodeString(&uniName, path);
	InitializeObjectAttributes(&objAttr, &uniName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	// Do not try to perform any file operations at higher IRQL levels.
	// Instead, you may use a work item or a system worker thread to perform file operations.

	if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
		status = STATUS_INVALID_DEVICE_STATE;
		free_firmware(fw);
		return status;
	}

	HANDLE   handle;
	IO_STATUS_BLOCK    ioStatusBlock;

	status = ZwCreateFile(&handle,
		GENERIC_READ,
		&objAttr, &ioStatusBlock, NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (!NT_SUCCESS(status)) {
		free_firmware(fw);
		return status;
	}

	FILE_STANDARD_INFORMATION fileInfo;
	status = ZwQueryInformationFile(
		handle,
		&ioStatusBlock,
		&fileInfo,
		sizeof(fileInfo),
		FileStandardInformation
	);
	if (!NT_SUCCESS(status)) {
		ZwClose(handle);
		free_firmware(fw);
		return status;
	}

	fw->size = fileInfo.EndOfFile.QuadPart;
	fw->data = ExAllocatePoolZero(NonPagedPool, fw->size, KBFILTER_POOL_TAG);
	if (!fw->data) {
		status = STATUS_NO_MEMORY;
		ZwClose(handle);
		free_firmware(fw);
		return status;
	}

	LARGE_INTEGER byteOffset;
	byteOffset.LowPart = byteOffset.HighPart = 0;
	status = ZwReadFile(handle, NULL, NULL, NULL, &ioStatusBlock, fw->data, (ULONG)fw->size, &byteOffset, NULL);
	if (!NT_SUCCESS(status)) {
		ZwClose(handle);
		free_firmware(fw);
		return status;
	}
	*img = fw;

	ZwClose(handle);
	return status;
}

void free_firmware(const struct firmware* fw) {
	if (fw->data) {
		ExFreePoolWithTag(fw->data, KBFILTER_POOL_TAG);
	}
	ExFreePoolWithTag((PVOID)fw, KBFILTER_POOL_TAG);
}