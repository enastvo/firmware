#include "FieldControlModule.h"
#include "MeshService.h"
#include "Router.h"
#include "configuration.h"
#include "fieldcontrol/BtControl.h"
#include "fieldcontrol/WifiControl.h"
#include "mesh/Channels.h"
#include <cstring>

FieldControlModule *fieldControlModule;

FieldControlModule::FieldControlModule()
    : ProtobufModule("fieldcontrol", meshtastic_PortNum_PRIVATE_APP, &meshtastic_FieldMessage_msg)
{
    // Deliberately NOT setting boundChannel here - see the class comment in
    // FieldControlModule.h for why PKI-encrypted unicast traffic needs its own check
    // instead of the framework's channel-name binding.
}

bool FieldControlModule::isAuthorized(const meshtastic_MeshPacket &mp)
{
    if (mp.pki_encrypted) {
        return true;
    }
    meshtastic_Channel &ch = channels.getByIndex(mp.channel);
    return strcasecmp(ch.settings.name, "fieldctrl") == 0;
}

void FieldControlModule::replyWith(const meshtastic_MeshPacket &req, uint32_t requestId, bool success, const char *error,
                                    const uint8_t *result, size_t resultLen)
{
    meshtastic_FieldMessage r = meshtastic_FieldMessage_init_default;
    r.request_id = requestId;
    r.which_payload_variant = meshtastic_FieldMessage_response_tag;
    r.response.success = success;
    if (error) {
        strncpy(r.response.error, error, sizeof(r.response.error) - 1);
    }
    if (result && resultLen) {
        size_t n = resultLen < sizeof(r.response.result.bytes) ? resultLen : sizeof(r.response.result.bytes);
        memcpy(r.response.result.bytes, result, n);
        r.response.result.size = n;
    }

    meshtastic_MeshPacket *p = allocDataProtobuf(r);
    setReplyTo(p, req);
    myReply = p;
}

// Result encoding for WifiOp.STATUS: [connected(1) | rssiDbm(1) | ip(4) | ssid(<=32, no NUL)]
// Result encoding for WifiOp.SCAN:   [count(1) | strongestRssi(1) | strongestSsid(<=32, no NUL)]
// Deliberately not protobuf - these are small enough that a fixed byte layout is cheaper to
// encode/decode than nesting another message, and the field meanings are documented here and
// in docs/architecture.md rather than in the wire schema.
void FieldControlModule::handleWifiOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_WifiOp &op)
{
#if HAS_WIFI
    using namespace fieldcontrol;

    switch (op.kind) {
    case meshtastic_WifiOp_Kind_ASSOCIATE: {
        bool started = WifiControl::associate(op.ssid, op.psk);
        LOG_INFO("FieldControl: WifiOp ASSOCIATE ssid='%s' started=%d", op.ssid, started);
        replyWith(mp, requestId, started, started ? NULL : "ssid required");
        break;
    }
    case meshtastic_WifiOp_Kind_DISASSOCIATE: {
        WifiControl::disassociate();
        LOG_INFO("FieldControl: WifiOp DISASSOCIATE");
        replyWith(mp, requestId, true, NULL);
        break;
    }
    case meshtastic_WifiOp_Kind_STATUS: {
        WifiStatus s = WifiControl::status();
        uint8_t buf[1 + 1 + 4 + sizeof(s.ssid)];
        size_t len = 0;
        buf[len++] = s.connected ? 1 : 0;
        buf[len++] = (uint8_t)s.rssiDbm;
        memcpy(&buf[len], s.ip, 4);
        len += 4;
        size_t ssidLen = strnlen(s.ssid, sizeof(s.ssid));
        memcpy(&buf[len], s.ssid, ssidLen);
        len += ssidLen;
        LOG_INFO("FieldControl: WifiOp STATUS connected=%d rssi=%d", s.connected, s.rssiDbm);
        replyWith(mp, requestId, true, NULL, buf, len);
        break;
    }
    case meshtastic_WifiOp_Kind_SCAN: {
        char strongestSsid[33] = {0};
        int8_t strongestRssi = 0;
        int n = WifiControl::scan(strongestSsid, sizeof(strongestSsid), &strongestRssi);
        uint8_t buf[1 + 1 + sizeof(strongestSsid) - 1];
        size_t len = 0;
        buf[len++] = (uint8_t)(n < 0 ? 0 : (n > 255 ? 255 : n));
        buf[len++] = (uint8_t)strongestRssi;
        size_t ssidLen = strnlen(strongestSsid, sizeof(strongestSsid));
        memcpy(&buf[len], strongestSsid, ssidLen);
        len += ssidLen;
        LOG_INFO("FieldControl: WifiOp SCAN found=%d", n);
        replyWith(mp, requestId, n >= 0, n >= 0 ? NULL : "scan failed", buf, len);
        break;
    }
    default:
        replyWith(mp, requestId, false, "unknown wifi op kind");
        break;
    }
#else
    (void)op;
    LOG_WARN("FieldControl: WifiOp received but HAS_WIFI is 0 on this build");
    replyWith(mp, requestId, false, "wifi not supported on this hardware");
#endif
}

// Result encoding for BtOp.SCAN: [count(1) | strongestRssi(1) | addr(6) | name(<=31, no NUL)]
// GATT_READ's result is just the raw characteristic value, capped to FieldResult.result's
// 140-byte capacity. See the WifiOp comment above for why this isn't nested protobuf instead.
void FieldControlModule::handleBtOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_BtOp &op)
{
#if HAS_BLUETOOTH
    using namespace fieldcontrol;

    switch (op.kind) {
    case meshtastic_BtOp_Kind_SCAN: {
        BtScanResult best{};
        int n = BtControl::scan(&best);
        uint8_t buf[1 + 1 + 6 + sizeof(best.name)];
        size_t len = 0;
        buf[len++] = (uint8_t)(n < 0 ? 0 : (n > 255 ? 255 : n));
        buf[len++] = (uint8_t)best.rssi;
        memcpy(&buf[len], best.addr, 6);
        len += 6;
        size_t nameLen = strnlen(best.name, sizeof(best.name));
        memcpy(&buf[len], best.name, nameLen);
        len += nameLen;
        LOG_INFO("FieldControl: BtOp SCAN found=%d", n);
        replyWith(mp, requestId, n >= 0, n >= 0 ? NULL : "scan failed", buf, len);
        break;
    }
    case meshtastic_BtOp_Kind_CONNECT: {
        bool ok = BtControl::connect(op.addr);
        LOG_INFO("FieldControl: BtOp CONNECT ok=%d", ok);
        replyWith(mp, requestId, ok, ok ? NULL : "connect failed");
        break;
    }
    case meshtastic_BtOp_Kind_DISCONNECT: {
        BtControl::disconnect();
        LOG_INFO("FieldControl: BtOp DISCONNECT");
        replyWith(mp, requestId, true, NULL);
        break;
    }
    case meshtastic_BtOp_Kind_GATT_READ: {
        uint8_t buf[140];
        int n = BtControl::gattRead(op.service_uuid, op.char_uuid, buf, sizeof(buf));
        LOG_INFO("FieldControl: BtOp GATT_READ n=%d", n);
        replyWith(mp, requestId, n >= 0, n >= 0 ? NULL : "gatt read failed", n > 0 ? buf : NULL, n > 0 ? (size_t)n : 0);
        break;
    }
    case meshtastic_BtOp_Kind_GATT_WRITE: {
        bool ok = BtControl::gattWrite(op.service_uuid, op.char_uuid, op.data.bytes, op.data.size);
        LOG_INFO("FieldControl: BtOp GATT_WRITE ok=%d", ok);
        replyWith(mp, requestId, ok, ok ? NULL : "gatt write failed");
        break;
    }
    default:
        replyWith(mp, requestId, false, "unknown bt op kind");
        break;
    }
#else
    (void)op;
    LOG_WARN("FieldControl: BtOp received but HAS_BLUETOOTH is 0 on this build");
    replyWith(mp, requestId, false, "bluetooth not supported on this hardware");
#endif
}

bool FieldControlModule::handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_FieldMessage *decoded)
{
    if (!isAuthorized(mp)) {
        // Not PKI-encrypted and not on our private channel - silently drop rather than
        // acknowledging a private app exists at this portnum to an unverified sender.
        LOG_WARN("FieldControl: unauthorized packet (pki=%d, channel=%d), ignoring", mp.pki_encrypted, mp.channel);
        return true;
    }

    uint32_t requestId = decoded->request_id;

    switch (decoded->which_payload_variant) {
    case meshtastic_FieldMessage_wifi_tag:
        handleWifiOp(mp, requestId, decoded->wifi);
        break;
    case meshtastic_FieldMessage_bt_tag:
        handleBtOp(mp, requestId, decoded->bt);
        break;
    case meshtastic_FieldMessage_net_tag:
        LOG_WARN("FieldControl: NetOp not implemented until Phase 4");
        replyWith(mp, requestId, false, "net op not implemented yet");
        break;
    case meshtastic_FieldMessage_script_tag:
        LOG_WARN("FieldControl: ScriptOp not implemented until Phase 5");
        replyWith(mp, requestId, false, "script op not implemented yet");
        break;
    case meshtastic_FieldMessage_response_tag:
        // A response arrived at a node that isn't the interactive client (e.g. a relay) - nothing to do.
        break;
    default:
        LOG_WARN("FieldControl: unknown payload_variant %d", decoded->which_payload_variant);
        break;
    }

    return true;
}
