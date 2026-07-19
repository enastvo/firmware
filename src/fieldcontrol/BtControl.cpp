#include "fieldcontrol/BtControl.h"

#if HAS_BLUETOOTH

#include <NimBLEDevice.h>
#include <cstring>

namespace fieldcontrol
{

static NimBLEClient *sClient = nullptr;

int BtControl::scan(BtScanResult *strongest)
{
    NimBLEScan *pScan = NimBLEDevice::getScan();
    pScan->setActiveScan(true);
    NimBLEScanResults results = pScan->start(3, false); // 3 second blocking scan
    int n = results.getCount();

    if (n > 0 && strongest) {
        int bestIdx = 0;
        int bestRssi = -128;
        for (int i = 0; i < n; i++) {
            NimBLEAdvertisedDevice d = results.getDevice(i);
            if (d.haveRSSI() && d.getRSSI() > bestRssi) {
                bestRssi = d.getRSSI();
                bestIdx = i;
            }
        }
        NimBLEAdvertisedDevice best = results.getDevice(bestIdx);
        memcpy(strongest->addr, best.getAddress().getNative(), 6);
        strongest->rssi = (int8_t)bestRssi;
        strongest->name[0] = '\0';
        if (best.haveName()) {
            strncpy(strongest->name, best.getName().c_str(), sizeof(strongest->name) - 1);
        }
    }

    pScan->clearResults();
    return n;
}

bool BtControl::connect(const uint8_t addr[6])
{
    if (sClient) {
        sClient->disconnect();
        NimBLEDevice::deleteClient(sClient);
        sClient = nullptr;
    }

    uint8_t addrCopy[6];
    memcpy(addrCopy, addr, 6);
    NimBLEAddress a(addrCopy, BLE_ADDR_PUBLIC);

    sClient = NimBLEDevice::createClient(a);
    bool ok = sClient->connect();
    if (!ok) {
        NimBLEDevice::deleteClient(sClient);
        sClient = nullptr;
    }
    return ok;
}

void BtControl::disconnect()
{
    if (sClient) {
        sClient->disconnect();
        NimBLEDevice::deleteClient(sClient);
        sClient = nullptr;
    }
}

bool BtControl::isConnected()
{
    return sClient && sClient->isConnected();
}

int BtControl::gattRead(const char *serviceUuid, const char *charUuid, uint8_t *out, size_t outLen)
{
    if (!sClient || !sClient->isConnected()) {
        return -1;
    }
    NimBLERemoteService *svc = sClient->getService(serviceUuid);
    if (!svc) {
        return -1;
    }
    NimBLERemoteCharacteristic *ch = svc->getCharacteristic(charUuid);
    if (!ch) {
        return -1;
    }
    NimBLEAttValue v = ch->readValue();
    size_t n = v.length() < outLen ? v.length() : outLen;
    memcpy(out, v.data(), n);
    return (int)n;
}

bool BtControl::gattWrite(const char *serviceUuid, const char *charUuid, const uint8_t *data, size_t len)
{
    if (!sClient || !sClient->isConnected()) {
        return false;
    }
    NimBLERemoteService *svc = sClient->getService(serviceUuid);
    if (!svc) {
        return false;
    }
    NimBLERemoteCharacteristic *ch = svc->getCharacteristic(charUuid);
    if (!ch) {
        return false;
    }
    return ch->writeValue(data, len, true);
}

} // namespace fieldcontrol

#endif // HAS_BLUETOOTH
