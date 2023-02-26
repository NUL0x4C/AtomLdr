#include <Windows.h>

#include "Structs.h"
#include "Common.h"
#include "Debug.h"


DWORD _CRC32b(unsigned char* str) 
{

    unsigned int   byte = 0x0,
        mask = 0x0,
        crc = 0xFFFFFFFF;
    int         i = 0x0,
        j = 0x0;

    while (str[i] != 0) {
        byte = str[i];
        crc = crc ^ byte;

        for (j = 7; j >= 0; j--) {
            mask = -1 * (crc & 1);
            crc = (crc >> 1) ^ (SEEDb & mask);
        }

        i++;
    }
    return ~crc;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//


unsigned reverse(unsigned x) {
    x = ((x & 0x55555555) << 1) | ((x >> 1) & 0x55555555);
    x = ((x & 0x33333333) << 2) | ((x >> 2) & 0x33333333);
    x = ((x & 0x0F0F0F0F) << 4) | ((x >> 4) & 0x0F0F0F0F);
    x = (x << 24) | ((x & 0xFF00) << 8) |
        ((x >> 8) & 0xFF00) | (x >> 24);
    return x;
}

DWORD _CRC32a(unsigned char* str) 
{
    int i, j;
    unsigned int byte, crc;

    i = 0;
    crc = 0xFFFFFFFF;
    while (str[i] != 0) {
        byte = str[i];
        byte = reverse(byte);
        for (j = 0; j <= 7; j++) {
            if ((int)(crc ^ byte) < 0)
                crc = (crc << 1) ^ SEEDa;
            else crc = crc << 1;
            byte = byte << 1;
        }
        i = i + 1;
    }
    return reverse(~crc);
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//


VOID _RtlInitUnicodeString(PUNICODE_STRING target, PCWSTR source)
{
    if ((target->Buffer = (PWSTR)source))
    {
        unsigned int length = wcslen(source) * sizeof(WCHAR);
        if (length > 0xfffc)
            length = 0xfffc;

        target->Length = length;
        target->MaximumLength = target->Length + sizeof(WCHAR);
    }
    else target->Length = target->MaximumLength = 0;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

PVOID _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
    PBYTE D = (PBYTE)Destination;
    PBYTE S = (PBYTE)Source;

    while (Length--)
        *D++ = *S++;

    return Destination;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

wchar_t* _strcpy(wchar_t* dest, const wchar_t* src)
{
    wchar_t* p;

    if ((dest == NULL) || (src == NULL))
        return dest;

    if (dest == src)
        return dest;

    p = dest;
    while (*src != 0) {
        *p = *src;
        p++;
        src++;
    }

    *p = 0;
    return dest;
}

//-----------------------------------------------------------------------------------------------------------------------------------------------------------------//

wchar_t* _strcat(wchar_t* dest, const wchar_t* src)
{
    if ((dest == NULL) || (src == NULL))
        return dest;

    while (*dest != 0)
        dest++;

    while (*src != 0) {
        *dest = *src;
        dest++;
        src++;
    }

    *dest = 0;
    return dest;
}