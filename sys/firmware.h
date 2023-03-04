#pragma once
#include <wdm.h>

struct firmware {
    void* data;
    size_t size;
};

NTSTATUS request_firmware(const struct firmware** img, PCWSTR path);
void free_firmware(struct firmware* fw);