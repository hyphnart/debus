#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
int main(){Sleep(1500);return 0;}
#else
int main(){return 0;}
#endif
