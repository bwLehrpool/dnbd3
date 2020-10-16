#ifndef _CLIENTCONFIG_H_
#define _CLIENTCONFIG_H_

// Which is the minimum protocol version the client expects from the server
#define MIN_SUPPORTED_SERVER 2

// in seconds if not stated otherwise (MS = milliseconds)
#define SOCKET_TIMEOUT_CLIENT_DATA 2
#define SOCKET_TIMEOUT_CLIENT_DISCOVERY 1

#define RTT_THRESHOLD_FACTOR(us) (((us) * 2) / 3) // 2/3 = current to best must be 33% worse
#define RTT_ABSOLUTE_THRESHOLD (80000) // Or 80ms worse
#define RTT_UNREACHABLE 0x7FFFFFFul // Use this value for timeout/unreachable as RTT. Don't set too high or you might get overflows. 0x7FFFFFF = 134 seconds
// This must be a power of two:
#define RTT_BLOCK_SIZE 4096

#define STARTUP_MODE_DURATION 30
// Interval of several repeating tasks (in seconds)
#define TIMER_INTERVAL_PROBE_STARTUP 4
#define TIMER_INTERVAL_PROBE_NORMAL 22
#define TIMER_INTERVAL_PROBE_PANIC 2
#define TIMER_INTERVAL_KEEPALIVE_PACKET 6

// Expect a keepalive response every X seconds
#define SOCKET_KEEPALIVE_TIMEOUT 8

// Number of unsuccessful alt_server probes before read errors are reported to the block layer
// (ALL servers will be probed this many times)
// Set to 0 to disable
#define PROBE_COUNT_TIMEOUT 0

// ++ Kernel module ++
#define DEFAULT_READ_AHEAD_KB 512
#define NUMBER_DEVICES 8

#endif
