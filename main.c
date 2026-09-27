#include <stdio.h>
#include <windows.h>
#include <winevt.h>
#include <stdlib.h>
#include <wchar.h>

void WINAPI ServiceMain(DWORD argc, LPSTR *argv);
void WINAPI ServiceControlHandler(DWORD controlCode);
DWORD WINAPI EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID context, EVT_HANDLE event);

HANDLE serviceStopEvent;
SERVICE_STATUS_HANDLE serviceStatusHandle;
SERVICE_STATUS serviceStatus = {0};
EVT_HANDLE eventSubscription;

int failedLogins = 0;
int successfulLogins = 0;

SERVICE_TABLE_ENTRYA serviceTable[] = {
    {"BootLogger", ServiceMain},
    {NULL, NULL}
};

int main() {

    StartServiceCtrlDispatcherA(serviceTable);

}

void WINAPI ServiceMain(DWORD argc, LPSTR *argv) {

    serviceStatusHandle = RegisterServiceCtrlHandlerA(
        "BootLogger",
        ServiceControlHandler
    );

    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    serviceStatus.dwWin32ExitCode = 0;
    serviceStatus.dwServiceSpecificExitCode = 0;
    serviceStatus.dwCheckPoint = 0;
    serviceStatus.dwWaitHint = 0;

    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    serviceStopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    if (serviceStopEvent == NULL) {

        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        serviceStatus.dwWin32ExitCode = GetLastError();

        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        return;
    }

    SYSTEMTIME systemTime;
    GetLocalTime(&systemTime);

    FILE *logFile = fopen(
        "C:\\Users\\igorm\\Documents\\BootLog.txt",
        "a+"
    );

    if (logFile != NULL) {

        fprintf(
            logFile,
            "Boot: %04d-%02d-%02d %02d:%02d:%02d\n",
            systemTime.wYear,
            systemTime.wMonth,
            systemTime.wDay,
            systemTime.wHour,
            systemTime.wMinute,
            systemTime.wSecond
        );

        fclose(logFile);
    }

    LPCWSTR query =
        L"<QueryList>"
        L"<Query Id=\"0\" Path=\"Security\">"
        L"<Select Path=\"Security\">"
        L"*[System[(EventID=4624 or EventID=4625)] and "
        L"EventData[Data[@Name='LogonType']='2']]"
        L"</Select>"
        L"</Query>"
        L"</QueryList>";

    eventSubscription = EvtSubscribe(
        NULL,
        NULL,
        NULL,
        query,
        NULL,
        NULL,
        EventCallback,
        EvtSubscribeToFutureEvents
    );

    if (eventSubscription == NULL) {

        DWORD error = GetLastError();

        WCHAR errorMessage[1024] = {0};
        DWORD errorMessageSize = sizeof(errorMessage);

        DWORD extendedStatus = EvtGetExtendedStatus(
            errorMessageSize,
            errorMessage,
            NULL
        );

        logFile = fopen(
            "C:\\Users\\igorm\\Documents\\BootLog.txt",
            "a+"
        );

        if (logFile != NULL) {

            fprintf(
                logFile,
                "EvtSubscribe failed: %lu\n",
                error
            );

            if (extendedStatus == ERROR_SUCCESS) {

                fwprintf(
                    stderr,
                    L"EvtSubscribe extended error: %ls\n",
                    errorMessage
                );

            }
            else {

                fprintf(
                    logFile,
                    "EvtGetExtendedStatus failed: %lu\n",
                    extendedStatus
                );

            }

            fclose(logFile);
        }

        serviceStatus.dwCurrentState = SERVICE_STOPPED;
        serviceStatus.dwWin32ExitCode = error;

        SetServiceStatus(serviceStatusHandle, &serviceStatus);

        return;
    }

    serviceStatus.dwCurrentState = SERVICE_RUNNING;

    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    WaitForSingleObject(serviceStopEvent, INFINITE);

    serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;

    SetServiceStatus(serviceStatusHandle, &serviceStatus);

    if (eventSubscription != NULL)
        EvtClose(eventSubscription);

    logFile = fopen(
        "C:\\Users\\igorm\\Documents\\BootLog.txt",
        "a+"
    );

    if (logFile != NULL) {

        fprintf(
            logFile,
            "Failed logins: %d\n",
            failedLogins
        );

        fprintf(
            logFile,
            "Successful logins: %d\n",
            successfulLogins
        );

        fclose(logFile);
    }

    serviceStatus.dwCurrentState = SERVICE_STOPPED;

    SetServiceStatus(serviceStatusHandle, &serviceStatus);
}

void WINAPI ServiceControlHandler(DWORD controlCode) {

    if (controlCode == SERVICE_CONTROL_STOP) {

        serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;

        SetServiceStatus(
            serviceStatusHandle,
            &serviceStatus
        );

        if (serviceStopEvent != NULL)
            SetEvent(serviceStopEvent);
    }
}

DWORD WINAPI EventCallback(
    EVT_SUBSCRIBE_NOTIFY_ACTION action,
    PVOID context,
    EVT_HANDLE event
) {

    if (action != EvtSubscribeActionDeliver)
        return ERROR_SUCCESS;

    DWORD bufferUsed = 0;
    DWORD propertyCount = 0;

    EvtRender(
        NULL,
        event,
        EvtRenderEventXml,
        0,
        NULL,
        &bufferUsed,
        &propertyCount
    );

    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        return ERROR_SUCCESS;

    WCHAR *xml = malloc(bufferUsed);

    if (xml == NULL)
        return ERROR_SUCCESS;

    if (!EvtRender(
        NULL,
        event,
        EvtRenderEventXml,
        bufferUsed,
        xml,
        &bufferUsed,
        &propertyCount
    )) {

        free(xml);

        return ERROR_SUCCESS;
    }

    SYSTEMTIME systemTime;
    GetLocalTime(&systemTime);

    FILE *logFile = fopen(
        "C:\\Users\\igorm\\Documents\\BootLog.txt",
        "a+"
    );

    if (logFile != NULL) {

        if (wcsstr(
            xml,
            L"<EventID>4625</EventID>"
        ) != NULL) {

            failedLogins++;

            fprintf(
                logFile,
                "Failed login #%d: %04d-%02d-%02d %02d:%02d:%02d\n",
                failedLogins,
                systemTime.wYear,
                systemTime.wMonth,
                systemTime.wDay,
                systemTime.wHour,
                systemTime.wMinute,
                systemTime.wSecond
            );
        }

        if (wcsstr(
            xml,
            L"<EventID>4624</EventID>"
        ) != NULL) {

            successfulLogins++;

            fprintf(
                logFile,
                "Successful login #%d: %04d-%02d-%02d %02d:%02d:%02d\n",
                successfulLogins,
                systemTime.wYear,
                systemTime.wMonth,
                systemTime.wDay,
                systemTime.wHour,
                systemTime.wMinute,
                systemTime.wSecond
            );

            fclose(logFile);

            SetEvent(serviceStopEvent);

            free(xml);

            return ERROR_SUCCESS;
        }

        fclose(logFile);
    }

    free(xml);

    return ERROR_SUCCESS;
}