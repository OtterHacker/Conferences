#include <stdio.h>
#include "loadlibrary.h"

int main() {
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;
    URL_COMPONENTS urlComp;
    WCHAR serverName[] = L"127.0.0.1";
    int serverPort = 8000;
    WCHAR objectName[] = L"/";

    printf("Press any key to load the DLL...\n");
    getchar();


    HMODULE winhttp = load_library_a("winhttp.dll");
    WIN32_DECL(WinHttpOpen) = get_proc_address(winhttp, FCT_WINHTTPOPEN);
    WIN32_DECL(WinHttpConnect) = get_proc_address(winhttp, FCT_WINHTTPCONNECT);
    WIN32_DECL(WinHttpOpenRequest) = get_proc_address(winhttp, FCT_WINHTTPOPENREQUEST);
    WIN32_DECL(WinHttpSendRequest) = get_proc_address(winhttp, FCT_WINHTTPSENDREQUEST);
    WIN32_DECL(WinHttpReceiveResponse) = get_proc_address(winhttp, FCT_WINHTTPRECEIVERESPONSE);
    WIN32_DECL(WinHttpQueryDataAvailable) = get_proc_address(winhttp, FCT_WINHTTPQUERYDATAAVAILABLE);
    WIN32_DECL(WinHttpReadData) = get_proc_address(winhttp, FCT_WINHTTPREADDATA);
    WIN32_DECL(WinHttpCloseHandle) = get_proc_address(winhttp, FCT_WINHTTPCLOSEHANDLE);


    // Initialize WinHTTP session
    hSession = win32_WinHttpOpen(L"A WinHTTP Example Program/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        printf("Error %lu in WinHttpOpen.\n", GetLastError());
        goto Cleanup;
    }

    // Specify HTTP server and port
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = serverName;
    urlComp.dwHostNameLength = lstrlenW(serverName);
    urlComp.nPort = serverPort;
    urlComp.lpszUrlPath = objectName;
    urlComp.dwUrlPathLength = lstrlenW(objectName);

    // Connect to HTTP server
    hConnect = win32_WinHttpConnect(hSession, urlComp.lpszHostName, urlComp.nPort, 0);
    if (!hConnect) {
        printf("Error %lu in WinHttpConnect.\n", GetLastError());
        goto Cleanup;
    }

    // Create HTTP GET request
    hRequest = win32_WinHttpOpenRequest(hConnect, L"GET", urlComp.lpszUrlPath, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        printf("Error %lu in WinHttpOpenRequest.\n", GetLastError());
        goto Cleanup;
    }

    // Send HTTP request
    bResults = win32_WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    if (!bResults) {
        printf("Error %lu in WinHttpSendRequest.\n", GetLastError());
        goto Cleanup;
    }

    // End the HTTP request
    bResults = win32_WinHttpReceiveResponse(hRequest, NULL);
    if (!bResults) {
        printf("Error %lu in WinHttpReceiveResponse.\n", GetLastError());
        goto Cleanup;
    }

    // Allocate memory for the response
    do {
        // Check for available data
        dwSize = 0;
        if (!win32_WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            printf("Error %lu in WinHttpQueryDataAvailable.\n", GetLastError());
            goto Cleanup;
        }

        // Allocate memory for the buffer
        pszOutBuffer = malloc(dwSize + 1);
        if (!pszOutBuffer) {
            printf("Out of memory.\n");
            dwSize = 0;
            goto Cleanup;
        }
        else {
            // Read the response data
            ZeroMemory(pszOutBuffer, dwSize + 1);
            if (!win32_WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                printf("Error %lu in WinHttpReadData.\n", GetLastError());
            }
            else {
                // Print the response
                printf("Response: %s\n", pszOutBuffer);
            }

            // Free the memory allocated to the buffer
            free(pszOutBuffer);
        }
    } while (dwSize > 0);

    Cleanup:
    // Clean up
    if (hRequest) win32_WinHttpCloseHandle(hRequest);
    if (hConnect) win32_WinHttpCloseHandle(hConnect);
    if (hSession) win32_WinHttpCloseHandle(hSession);
    printf("Press any key to close...\n");
    getchar();
    return 0;
}