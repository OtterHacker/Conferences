#ifndef NIRVANASLEEP_DEATHSLEEP_H
#define NIRVANASLEEP_DEATHSLEEP_H



VOID   awake (PVOID lpParam);

DWORD  WINAPI    mainProgram();

int InstallNirvana(PVOID hook);
DWORD64 getEpoch();

extern DWORD_PTR getRsp();
extern void      moveRsp(DWORD, DWORD);

#endif //NIRVANASLEEP_DEATHSLEEP_H
