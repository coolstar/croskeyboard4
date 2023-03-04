// crosecservice.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <cstdio>
#include <thread>
#include "croskbhid.h"

int main()
{
    pcroskbhid_client client = croskbhid_alloc();
    BOOL connect = croskbhid_connect(client);
    printf("Connected? %d\n", connect);

    CrosKBHIDRemapperSettingsReport report = { 0 };

    report.ReportID = REPORTID_SETTINGS;
    report.SettingsRegister = SETTINGS_REG_RELOADSETTINGS;
    report.SettingsValue = 0;

    croskbhid_write_keyboard(client, &report);

    croskbhid_disconnect(client);
}