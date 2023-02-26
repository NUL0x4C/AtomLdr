#ifndef DEBUG_H
#define DEBUG_H

// uncomment the following to enable debug mode
//\
#define DEBUG





#ifdef DEBUG

#include <Windows.h>


HANDLE   GetConsoleHandle();


#define PRINTW( STR, ... )                                                                      \
    if (1) {                                                                                    \
        HANDLE hConsole = NULL;                                                                 \
        if ((hConsole = GetConsoleHandle()) == NULL){}                                          \
        else{                                                                                   \
            LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
            if ( buf != NULL ) {                                                                \
                int len = wsprintfW( buf, STR, __VA_ARGS__ );                                   \
                WriteConsoleW( hConsole, buf, len, NULL, NULL );			                    \
                HeapFree( GetProcessHeap(), 0, buf );                                           \
            }                                                                                   \
        }                                                                                       \
    }


#define PRINTA( STR, ... )                                                                      \
    if (1) {                                                                                    \
        HANDLE hConsole = NULL;                                                                 \
        if ((hConsole = GetConsoleHandle()) == NULL){}                                          \
        else{                                                                                   \
            LPWSTR buf = (LPWSTR)HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, 1024 );         \
            if ( buf != NULL ) {                                                                \
                int len = wsprintfA( buf, STR, __VA_ARGS__ );                                   \
                WriteConsoleA( hConsole, buf, len, NULL, NULL );			                    \
                HeapFree( GetProcessHeap(), 0, buf );                                           \
            }                                                                                   \
        }                                                                                       \
    }

#endif // DEBUG







#endif // !DEBUG_H
