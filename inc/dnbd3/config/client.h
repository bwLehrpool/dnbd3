#ifndef _CLIENTCONFIG_H_
#define _CLIENTCONFIG_H_

// Which is the minimum protocol version the client expects from the server
#define MIN_SUPPORTED_SERVER 2

// Send keepalive every X seconds
#define KEEPALIVE_INTERVAL 10

// in seconds if not stated otherwise
#define SOCKET_TIMEOUT_SEND 2

// Socker receive timeout. Must be higher than keepalive interval, otherwise
// the connection might be aborted when idle
#define SOCKET_TIMEOUT_RECV 13

// During discovery, we use very short minimum timeouts (unless in panic mode)
#define SOCKET_TIMEOUT_DISCOVERY 1

// IO timeout for block layer
#define BLOCK_LAYER_TIMEOUT 10

#define RTT_THRESHOLD_FACTOR(us) (((us) * 3) / 4) // 3/4 = current to best must be 25% worse
#define RTT_ABSOLUTE_THRESHOLD (80000) // Or 80ms worse
#define RTT_UNREACHABLE 0x7FFFFFFul // Use this value for timeout/unreachable as RTT. Don't set too high or you might get overflows. 0x7FFFFFF = 134 seconds
// This must be a power of two:
#define RTT_BLOCK_SIZE 4096

// Interval of several repeating tasks (in seconds)
#define TIMER_INTERVAL_PROBE_STARTUP 2
#define TIMER_INTERVAL_PROBE_SWITCH 10
#define TIMER_INTERVAL_PROBE_PANIC 2
#define TIMER_INTERVAL_PROBE_MAX 45
// How many discover runs after setting up a device should be considered the startup phase
// during that phase, check all servers, before we start doing it selectively
// and also don't increase the discover interval during this period
#define DISCOVER_STARTUP_PHASE_COUNT 6
// How many servers should be tested at maximum after above
#define DISCOVER_REDUCED_SERVER_COUNT 3
// Number of RTT probes to keep in history and average the value over
#define DISCOVER_HISTORY_SIZE 4

// Number of unsuccessful alt_server probes before read errors are reported to the block layer
// (ALL servers will be probed this many times)
// Set to 0 to disable
#define PROBE_COUNT_TIMEOUT 0

// ++ Kernel module ++
#define DEFAULT_READ_AHEAD_KB 512
#define NUMBER_DEVICES 8

#endif
