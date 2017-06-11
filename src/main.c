// -------------------------------------------------------------------------------------------------
//  File main.c
//
//  Copyright (c) 2016, 2017 DexLogic, Dirk Apitz
//
//  Permission is hereby granted, free of charge, to any person obtaining a copy
//  of this software and associated documentation files (the "Software"), to deal
//  in the Software without restriction, including without limitation the rights
//  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//  copies of the Software, and to permit persons to whom the Software is
//  furnished to do so, subject to the following conditions:
//
//  The above copyright notice and this permission notice shall be included in all
//  copies or substantial portions of the Software.
//
//  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//  SOFTWARE.
//
// -------------------------------------------------------------------------------------------------
//  Change History:
//
//  05/2016 Dirk Apitz, created
//  11/2016 Theo Dari, Windows port
//  06/2017 Dirk Apitz, Windows port, GitHub release
// -------------------------------------------------------------------------------------------------

// Standard libraries
#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <time.h>


// Platform includes
#if defined(_WIN32) || defined(WIN32)

    #include "plt-windows.h"

#else

    #include <stdlib.h>
    #include <ifaddrs.h>

    #include "plt-posix.h"

#endif


// Project headers
#include "idn-hello.h"


// -------------------------------------------------------------------------------------------------
//  Variables
// -------------------------------------------------------------------------------------------------

static uint8_t gbl_packetBuffer[0x10000];   // Work buffer


// -------------------------------------------------------------------------------------------------
//  Tools
// -------------------------------------------------------------------------------------------------

static char *vbufPrintf(char *bufPtr, char *limitPtr, const char *fmt, va_list arg_ptr)
{
    // Determine available space. Abort in case of invalid buffer.
    int len = limitPtr - bufPtr;
    if((bufPtr == (char *)0) || (len <= 0)) return (char *)0;

    // Print in case ellipsis would fit.
    if(len > 4) 
    {
        // Reserve margin and print string. Note: snprintf guarantees for a trailing '\0'.
        len -= 4;
        int rc = vsnprintf(bufPtr, len + 1, fmt, arg_ptr);

        if(rc > len) 
        {
            // String truncated (less characters available than needed). Append ellipsis.
            bufPtr = &bufPtr[len];
        }
        else if(rc >= 0)
        {
            // Printed string fits. Return new start pointer.
            return &bufPtr[rc];
        }
        else
        {
            // In case of error - ignore (make sure that the string is terminated).
            *bufPtr = '\0';
            return bufPtr;
        }
    }

    // In case of insufficient buffer: Append ellipsis.
    while((limitPtr - bufPtr) > 1) *bufPtr++ = '.';
    *bufPtr = '\0';

    return bufPtr;
}


static char *bufPrintf(char *bufPtr, char *limitPtr, const char *fmt, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, fmt);

    return vbufPrintf(bufPtr, limitPtr, fmt, arg_ptr);
}


void logError(const char *fmt, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, fmt);

//    printf("\x1B[1;31m");
    vprintf(fmt, arg_ptr);
//    printf("\x1B[0m");
    printf("\n");
    fflush(stdout);
}


void logInfo(const char *fmt, ...)
{
    va_list arg_ptr;
    va_start(arg_ptr, fmt);

    vprintf(fmt, arg_ptr);
    printf("\n");
    fflush(stdout);
}


// -------------------------------------------------------------------------------------------------
//  IDN-Hello server scan
// -------------------------------------------------------------------------------------------------

void idnHelloScan(const char *ifName, uint32_t ifIP4Addr)
{
    // Socket file descriptor
    int fdSocket = -1;

    do
    {
        // Print interface info
        char ifAddrString[20];
        if(inet_ntop(AF_INET, &ifIP4Addr, ifAddrString, sizeof(ifAddrString)) == (char *)0)
        {
            logError("inet_ntop() failed (error: %d)", plt_sockGetLastError());
            break;
        }
        logInfo("Scanning interface %s (IP4: %s)", ifName ? ifName : "<?>" , ifAddrString);

        // Create socket
        fdSocket = plt_sockOpen(AF_INET, SOCK_DGRAM, 0);
        if(fdSocket < 0)
        {
            logError("socket() failed (error: %d)", plt_sockGetLastError());
            break;
        }

        // Allow broadcast on socket
        if(plt_sockSetBroadcast(fdSocket) < 0)
        {
            logError("setsockopt(broadcast) failed (error: %d)", plt_sockGetLastError());
            break;
        }

        // Bind to local interface (any! port)
        // Note: This bind is needed to send the broadcast on the specific (virtual) interface,
        struct sockaddr_in bindSockAddr = { 0 };
        bindSockAddr.sin_family = AF_INET;
        bindSockAddr.sin_port = 0;
        bindSockAddr.sin_addr.s_addr = ifIP4Addr;

        if(bind(fdSocket, (struct sockaddr *)&bindSockAddr, sizeof(bindSockAddr)) < 0)
        {
            logError("bind() failed (error: %d)", plt_sockGetLastError());
            break;
        }

        // ----------------------------------------------------------------------------------------
        // Send request, use network broadcast address

        struct sockaddr_in sendSockAddr;
        sendSockAddr.sin_family      = AF_INET;
        sendSockAddr.sin_port        = htons(IDNVAL_HELLO_UDP_PORT);
        sendSockAddr.sin_addr.s_addr = INADDR_BROADCAST;

        IDNHDR_PACKET sendPacketHdr;
        sendPacketHdr.command = IDNCMD_SCAN_REQUEST;
        sendPacketHdr.flags = 0;
        sendPacketHdr.sequence = htons(rand() & 0xFFFF);

        if(sendto(fdSocket, (char *)&sendPacketHdr, sizeof(sendPacketHdr), 0, (struct sockaddr *)&sendSockAddr, sizeof(sendSockAddr)) < 0)
        {
            logError("sendto() failed (error: %d)", plt_sockGetLastError());
            break;
        }


        // ----------------------------------------------------------------------------------------
        // Receive response(s)

        fd_set rfdsPrm;
        FD_ZERO(&rfdsPrm);
        FD_SET(fdSocket, &rfdsPrm);

        unsigned msTimeout = 500;
        struct timeval tv;
        tv.tv_sec = msTimeout / 1000;
        tv.tv_usec = (msTimeout % 1000) * 1000;

        while(1)
        {
            fd_set rfdsResult = rfdsPrm;
            int numReady = select(fdSocket + 1, &rfdsResult, 0, 0, &tv);
            if(numReady < 0)
            {
                logError("select() failed (error: %d)", plt_sockGetLastError());
                break;
            }
            else if(numReady == 0)
            {
                break;
            }

            // Receive scan response
            struct sockaddr_in recvSockAddr;
            struct sockaddr *recvAddrPre = (struct sockaddr *)&recvSockAddr;
            socklen_t recvAddrSize = sizeof(recvSockAddr);

            int nBytes = recvfrom(fdSocket, gbl_packetBuffer, sizeof(gbl_packetBuffer), 0, recvAddrPre, &recvAddrSize);
            if(nBytes < 0)
            {
                logError("recvfrom() failed (error: %d)", plt_sockGetLastError());
                break;
            }

            char recvAddrString[20];
            if(inet_ntop(AF_INET, &recvSockAddr.sin_addr, recvAddrString, sizeof(recvAddrString)) == (char *)0)
            {
                logError("inet_ntop() failed (error: %d)", plt_sockGetLastError());
                break;
            }
            
            if(nBytes != (sizeof(IDNHDR_PACKET) + sizeof(IDNHDR_SCAN_RESPONSE)))
            {
                logError("%s: Invalid packet size %u\n", recvAddrString, nBytes);
                break;
            }

            // Check IDN-Hello packet header
            IDNHDR_PACKET *recvPacketHdr = (IDNHDR_PACKET *)gbl_packetBuffer;
            if(recvPacketHdr->command != IDNCMD_SCAN_RESPONSE) 
            {
                logError("%s: Invalid command 0x%02X\n", recvAddrString, recvPacketHdr->command);
                break;
            }
            if(recvPacketHdr->sequence != sendPacketHdr.sequence) 
            {
                logError("%s: Invalid sequence\n", recvAddrString);
                break;
            }

            // Check scan response header
            IDNHDR_SCAN_RESPONSE *scanResponseHdr = (IDNHDR_SCAN_RESPONSE *)&recvPacketHdr[1];
            if(scanResponseHdr->structSize != sizeof(IDNHDR_SCAN_RESPONSE))
            {
                logError("%s: Invalid scan response header size %u\n", recvAddrString, scanResponseHdr->structSize);
                break;
            }

            // Allocate log buffer
            char logString[200], *logPtr = logString, *logLimit = &logString[sizeof(logString)];

            // Print unitID as a string
            unsigned unitIDLen = scanResponseHdr->unitID[0];
            unsigned char *src = (unsigned char *)&scanResponseHdr->unitID[1];
            for(unsigned i = 0; i < unitIDLen; i++)
            {
                logPtr = bufPrintf(logPtr, logLimit, "%02X", *src++);
                if(i == 0) logPtr = bufPrintf(logPtr, logLimit, "-");
            }

            // Append host name (in case available)
            if(scanResponseHdr->hostName[0]) 
            {
                logPtr = bufPrintf(logPtr, logLimit, "(%s)", scanResponseHdr->hostName);
            }

            // Print server information
            logInfo("%s at %s", logString, recvAddrString);
        }
    }
    while(0);

    // Close socket
    if(fdSocket >= 0)
    {
        if(plt_sockClose(fdSocket)) logError("close() failed (error: %d)", plt_sockGetLastError());
    }
}


// -------------------------------------------------------------------------------------------------
//  Entry point
// -------------------------------------------------------------------------------------------------

int main(int argc, char **argv)
{
    printf("Scanning for IDN-Hello servers...\n");
    printf("------------------------------------------------------------\n");

    // Initialize random number generator (used to generate sequence numbers)
    srand((unsigned)time(NULL));

    do
    {
        // Initialize platform sockets
        int rcStartup = plt_sockStartup();
        if(rcStartup)
        {
            logError("Socket startup failed (error: %d)", rcStartup);
            break;
        }

        // Walk through all interfaces and find IDN-Hello servers
        if(plt_ifAddrListVisitor(idnHelloScan)) break;
    }
    while (0);

    // Platform sockets cleanup
    if(plt_sockCleanup()) logError("Socket cleanup failed (error: %d)", plt_sockGetLastError());

    return 0;
}
