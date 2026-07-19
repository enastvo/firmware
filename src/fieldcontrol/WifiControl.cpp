#include "fieldcontrol/WifiControl.h"

#if HAS_WIFI

#include "configuration.h"
#include <WiFi.h>
#include <cstring>

namespace fieldcontrol
{

bool WifiControl::associate(const char *ssid, const char *psk)
{
    if (!ssid || !ssid[0]) {
        return false;
    }

    WiFi.persistent(false); // Don't wear the flash - we hold credentials in RAM only
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, (psk && psk[0]) ? psk : NULL);
    return true;
}

void WifiControl::disassociate()
{
    WiFi.disconnect(true, false);
    WiFi.mode(WIFI_OFF);
}

WifiStatus WifiControl::status()
{
    WifiStatus s{};
    s.connected = (WiFi.status() == WL_CONNECTED);
    if (s.connected) {
        s.rssiDbm = (int8_t)WiFi.RSSI();
        IPAddress ip = WiFi.localIP();
        s.ip[0] = ip[0];
        s.ip[1] = ip[1];
        s.ip[2] = ip[2];
        s.ip[3] = ip[3];
        strncpy(s.ssid, WiFi.SSID().c_str(), sizeof(s.ssid) - 1);
    }
    return s;
}

int WifiControl::scan(char *strongestSsid, size_t strongestSsidLen, int8_t *strongestRssi)
{
    WiFi.mode(WIFI_STA);
    int n = WiFi.scanNetworks();

    if (n <= 0) {
        if (strongestSsid && strongestSsidLen) {
            strongestSsid[0] = '\0';
        }
        if (strongestRssi) {
            *strongestRssi = 0;
        }
        WiFi.scanDelete();
        return n < 0 ? 0 : n;
    }

    int bestIdx = 0;
    for (int i = 1; i < n; i++) {
        if (WiFi.RSSI(i) > WiFi.RSSI(bestIdx)) {
            bestIdx = i;
        }
    }

    if (strongestSsid && strongestSsidLen) {
        strncpy(strongestSsid, WiFi.SSID(bestIdx).c_str(), strongestSsidLen - 1);
        strongestSsid[strongestSsidLen - 1] = '\0';
    }
    if (strongestRssi) {
        *strongestRssi = (int8_t)WiFi.RSSI(bestIdx);
    }

    WiFi.scanDelete();
    return n;
}

} // namespace fieldcontrol

#endif // HAS_WIFI
