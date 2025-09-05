#ifndef NIRVANASLEEP_UTILS_H
#define NIRVANASLEEP_UTILS_H
#include "common.h"

#define SIZE_MODULE_LIST 2
#define MAX_MODULE_NAME 100

BOOL        bCompare (const BYTE *pData, const BYTE *bMask, const char *szMask);
DWORD_PTR   findPattern (DWORD_PTR dwAddress, DWORD dwLen, PBYTE bMask, PCHAR szMask);
DWORD_PTR   findInModule (LPCSTR moduleName, PBYTE bMask, PCHAR szMask);
PVOID       findGadget (PBYTE hdrParserFuncB, PCHAR hdrParserFunctMask);

#endif //NIRVANASLEEP_UTILS_H
