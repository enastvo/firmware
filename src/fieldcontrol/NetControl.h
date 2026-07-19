#pragma once
#include "configuration.h"

#if HAS_WIFI

#include <cstddef>
#include <cstdint>

namespace fieldcontrol
{

struct PingResult {
    uint8_t sent;
    uint8_t received;
    uint16_t minMs;
    uint16_t avgMs;
    uint16_t maxMs;
};

/**
 * Thin wrapper over lwIP's ICMP ping API and Arduino's WiFiClient for
 * FieldControlModule, used once WifiControl has associated to a network.
 */
class NetControl
{
  public:
    /**
     * Blocking ping (roughly count * ~1.5s, capped internally). Returns false if
     * the host couldn't be resolved; on true, check result->received vs ->sent
     * for packet loss.
     */
    static bool ping(const char *host, uint8_t count, PingResult *result);

    /// Opens a TCP connection to host:port, replacing any existing one. Blocking,
    /// up to timeoutMs (default 5000; pass a shorter value - e.g. 200-500ms - for
    /// port-scan-style loops, since a refused port returns almost immediately but
    /// a filtered/dropped one blocks for the full timeout on every attempt).
    static bool tcpConnect(const char *host, uint16_t port, uint32_t timeoutMs = 5000);

    static void tcpClose();
    static bool tcpConnected();

    /// Sends on the currently open TCP connection. Returns bytes written.
    static int tcpSend(const uint8_t *data, size_t len);

    /// Reads up to outLen bytes, waiting up to timeoutMs for at least one byte.
    /// Returns bytes read (0 if none arrived in time, negative if not connected).
    static int tcpRecv(uint8_t *out, size_t outLen, uint32_t timeoutMs);
};

} // namespace fieldcontrol

#endif // HAS_WIFI
