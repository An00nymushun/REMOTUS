#include <jni.h>
#include <errno.h>

#include <string.h>
#include <unistd.h>
#include <sys/resource.h>

#include <android/log.h>

#include <sys/socket.h>
#include <netinet/in.h>

#define NULL 0

typedef unsigned char BYTE;
typedef BYTE* POINTER;
typedef POINTER PTR;
typedef unsigned short USHORT;
typedef unsigned int UINT;
typedef long long LONG;
typedef unsigned long long ULONG;

#define STRSIZE(s) (sizeof(s) - 1)
#define ARRAYCOUNT(a) (sizeof(a) / sizeof(a[0]))


template<typename T>
struct is_pointer { static const bool value = false; };
template<typename T>
struct is_pointer<T*> { static const bool value = true; };

template<typename T>
struct is_array { static const bool value = false; };
template<typename T>
struct is_array<T[]> { static const bool value = true; };
template<typename T, size_t N>
struct is_array<T[N]> { static const bool value = true; };

template<bool B, class T = void>
struct enable_if {};
template<class T>
struct enable_if<true, T> { typedef T type; };
