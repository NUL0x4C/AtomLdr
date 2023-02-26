#include <Windows.h>
#include "Debug.h"

#ifdef DEBUG

HANDLE g_hConsole = INVALID_HANDLE_VALUE;

/*
	function used to create/allocate a console - used only in debug mode
*/
HANDLE GetConsoleHandle() {


	if (g_hConsole != INVALID_HANDLE_VALUE)
		return g_hConsole;

	if (!SetConsoleTitleA("AtomLdr Debugging Console")) {
		if (!FreeConsole() || !AllocConsole())
			return NULL;
	}

	if ((g_hConsole = GetStdHandle(STD_OUTPUT_HANDLE)) == INVALID_HANDLE_VALUE)
		return NULL;

	return g_hConsole;
}

#endif // DEBUG
