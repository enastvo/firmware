#pragma once
#include "configuration.h"

#if HAS_WIFI

#include <cstddef>
#include <cstdint>

namespace fieldcontrol
{

struct WifiStatus {
    bool connected;
    int8_t rssiDbm;  // valid only if connected
    uint8_t ip[4];   // 0.0.0.0 if not connected
    char ssid[33];   // associated SSID, empty if not connected
};

/**
 * Thin wrapper over WiFi.h / esp_wifi_* for FieldControlModule. The Agent's own
 * network.wifiEnabled must stay false so Meshtastic's WiFiAPClient (src/mesh/wifi/)
 * never activates itself and contends for the radio - see docs/architecture.md.
 */
class WifiControl
{
  public:
    /**
     * Starts an async connection attempt (puts the radio into STA mode and calls
     * WiFi.begin()) and returns immediately - does not block waiting for the
     * handshake/DHCP to complete. Poll status() afterwards to see the result.
     */
    static bool associate(const char *ssid, const char *psk);

    /// Disconnects and powers the WiFi radio off. Fast, does not block.
    static void disassociate();

    /// Current connection state. Does not block.
    static WifiStatus status();

    /**
     * Blocking scan (typically a few seconds) for nearby SSIDs. Returns the number
     * of networks found (0 if none, negative on error). If any were found, the
     * strongest is copied into strongestSsid/strongestRssi.
     */
    static int scan(char *strongestSsid, size_t strongestSsidLen, int8_t *strongestRssi);
};

} // namespace fieldcontrol

#endif // HAS_WIFI
