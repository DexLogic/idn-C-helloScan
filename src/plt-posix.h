// -------------------------------------------------------------------------------------------------
//  File plt-posix.h
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
//  06/2017 Dirk Apitz, created
// -------------------------------------------------------------------------------------------------


#ifndef PLT_POSIX_H
#define PLT_POSIX_H


// Standard libraries
#include <unistd.h>
#include <errno.h>
#include <time.h>

// Platform headers
#include <arpa/inet.h>


// -------------------------------------------------------------------------------------------------
//  Typedefs
// -------------------------------------------------------------------------------------------------

typedef void (* IFADDR_CALLBACK_PFN)(const char *ifName, uint32_t ifIP4Addr);


// -------------------------------------------------------------------------------------------------
//  Inline functions
// -------------------------------------------------------------------------------------------------

inline static int plt_ifAddrListVisitor(IFADDR_CALLBACK_PFN pfnCallback)
{
    extern void logError(const char *fmt, ...);

    // Find all interfaces
    struct ifaddrs *ifaddr;
    if(getifaddrs(&ifaddr) == -1) 
    {
        logError("getifaddrs() failed (error = %d)", errno);
        return -1;
    }

    // Walk through all interfaces
    for(struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
    {
        if(ifa->ifa_addr == NULL) continue;
        if(ifa->ifa_addr->sa_family != AF_INET) continue;

        // Invoke callback on interface
        struct sockaddr_in *ifSockAddr = (struct sockaddr_in *)ifa->ifa_addr;
        pfnCallback(ifa->ifa_name, (uint32_t)(ifSockAddr->sin_addr.s_addr));
    }

    // Interface list is dynamically allocated and must be freed
    freeifaddrs(ifaddr);

    return 0;
}


inline static int plt_sockStartup()
{
    return 0;
}


inline static int plt_sockCleanup()
{
    return 0;
}


inline static int plt_sockGetLastError()
{
    return errno;
}


inline static int plt_sockOpen(int domain, int type, int protocol)
{
    return socket(domain, type, protocol);
}


inline static int plt_sockClose(int fdSocket)
{
    return close(fdSocket);
}


inline static int plt_sockSetBroadcast(int fdSocket)
{
    int bcastOpt = 1;
    return setsockopt(fdSocket, SOL_SOCKET, SO_BROADCAST, &bcastOpt, sizeof(bcastOpt));
}


#endif

