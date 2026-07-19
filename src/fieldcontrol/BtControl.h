#pragma once
#include "configuration.h"

#if HAS_BLUETOOTH

#include <cstddef>
#include <cstdint>

namespace fieldcontrol
{

struct BtScanResult {
    uint8_t addr[6];
    int8_t rssi;
    char name[32]; // empty if the device didn't advertise a name
};

/**
 * Thin wrapper over NimBLE's central-role API for FieldControlModule. Runs
 * alongside Meshtastic's own NimbleBluetooth peripheral (phone-pairing GATT
 * server, src/nimble/) rather than replacing it - NimBLEDevice::init() is a
 * no-op if already initialized (see NimBLEDevice.cpp), so this doesn't fight
 * with config.bluetooth.enabled/nimbleBluetooth for ownership of the BLE stack.
 */
class BtControl
{
  public:
    /**
     * Blocking scan (a few seconds) for nearby BLE devices. Returns the number
     * found (0 if none, negative on error). If any were found, the strongest by
     * RSSI is copied into *strongest.
     */
    static int scan(BtScanResult *strongest);

    /// Connects (blocking, with an internal timeout) to the given BLE address.
    static bool connect(const uint8_t addr[6]);

    /// Disconnects the current central-role connection, if any.
    static void disconnect();

    static bool isConnected();

    /**
     * Reads/writes a GATT characteristic (both UUIDs as strings, e.g.
     * "0000180f-0000-1000-8000-00805f9b34fb") on the currently connected device.
     * Returns bytes read (negative on failure) / true on write success.
     */
    static int gattRead(const char *serviceUuid, const char *charUuid, uint8_t *out, size_t outLen);
    static bool gattWrite(const char *serviceUuid, const char *charUuid, const uint8_t *data, size_t len);
};

} // namespace fieldcontrol

#endif // HAS_BLUETOOTH
