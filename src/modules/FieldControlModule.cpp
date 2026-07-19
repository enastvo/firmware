#include "FieldControlModule.h"
#include "MeshService.h"
#include "Router.h"
#include "configuration.h"
#include "fieldcontrol/BtControl.h"
#include "fieldcontrol/NetControl.h"
#include "fieldcontrol/ScriptEngine.h"
#include "fieldcontrol/ScriptStore.h"
#include "fieldcontrol/WifiControl.h"
#include "mesh/Channels.h"
#include <cstring>

FieldControlModule *fieldControlModule;
uint8_t FieldControlModule::scriptBytecode[fieldcontrol::ScriptStore::MAX_SCRIPT_SIZE];

FieldControlModule::FieldControlModule()
    : ProtobufModule("fieldcontrol", meshtastic_PortNum_PRIVATE_APP, &meshtastic_FieldMessage_msg),
      concurrency::OSThread("FieldControl", 500)
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

bool FieldControlModule::isReplay(uint32_t fromNode, uint32_t requestId)
{
    for (auto &r : seenRequests) {
        if (r.valid && r.fromNode == fromNode && r.requestId == requestId) {
            return true;
        }
    }
    return false;
}

void FieldControlModule::rememberRequest(uint32_t fromNode, uint32_t requestId)
{
    seenRequests[seenRequestsNext] = {fromNode, requestId, true};
    seenRequestsNext = (seenRequestsNext + 1) % SEEN_WINDOW;
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

// Result encoding for NetOp.PING: [sent(1) | received(1) | minMs(2,LE) | avgMs(2,LE) | maxMs(2,LE)]
// Result encoding for NetOp.SEND: [bytesSent(2,LE)]
// NetOp.RECV's result is the raw bytes read (up to FieldResult.result's 140-byte capacity),
// waited for with a fixed 3s timeout - see the WifiOp comment above for why this isn't nested
// protobuf, and docs/architecture.md for why RECV doesn't take an explicit length/timeout (kept
// out of scope for this phase; revisit if a real target needs one).
void FieldControlModule::handleNetOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_NetOp &op)
{
#if HAS_WIFI
    using namespace fieldcontrol;

    switch (op.kind) {
    case meshtastic_NetOp_Kind_PING: {
        PingResult r;
        bool ok = NetControl::ping(op.host, 4, &r);
        uint8_t buf[8];
        buf[0] = r.sent;
        buf[1] = r.received;
        buf[2] = (uint8_t)(r.minMs & 0xFF);
        buf[3] = (uint8_t)(r.minMs >> 8);
        buf[4] = (uint8_t)(r.avgMs & 0xFF);
        buf[5] = (uint8_t)(r.avgMs >> 8);
        buf[6] = (uint8_t)(r.maxMs & 0xFF);
        buf[7] = (uint8_t)(r.maxMs >> 8);
        LOG_INFO("FieldControl: NetOp PING host='%s' sent=%d recv=%d", op.host, r.sent, r.received);
        replyWith(mp, requestId, ok, ok ? NULL : "host resolution failed", buf, sizeof(buf));
        break;
    }
    case meshtastic_NetOp_Kind_TCP_CONNECT: {
        bool ok = NetControl::tcpConnect(op.host, (uint16_t)op.port);
        LOG_INFO("FieldControl: NetOp TCP_CONNECT host='%s' port=%u ok=%d", op.host, op.port, ok);
        replyWith(mp, requestId, ok, ok ? NULL : "tcp connect failed");
        break;
    }
    case meshtastic_NetOp_Kind_SEND: {
        int n = NetControl::tcpSend(op.data.bytes, op.data.size);
        LOG_INFO("FieldControl: NetOp SEND n=%d", n);
        uint8_t buf[2] = {(uint8_t)(n & 0xFF), (uint8_t)((n >> 8) & 0xFF)};
        replyWith(mp, requestId, n >= 0, n >= 0 ? NULL : "not connected", buf, sizeof(buf));
        break;
    }
    case meshtastic_NetOp_Kind_RECV: {
        uint8_t buf[140];
        // 0 means "use the default" for backwards compatibility with clients that don't
        // set these fields; caps protect the module from a client asking to block for an
        // unreasonably long time (RECV still runs on the main packet-handling path, unlike
        // ScriptOp.EXECUTE which got a background task in Phase 6).
        size_t len = op.recv_len == 0 ? sizeof(buf) : op.recv_len;
        len = len > sizeof(buf) ? sizeof(buf) : len;
        uint32_t timeoutMs = op.recv_timeout_ms == 0 ? 3000 : op.recv_timeout_ms;
        timeoutMs = timeoutMs > 15000 ? 15000 : timeoutMs;

        int n = NetControl::tcpRecv(buf, len, timeoutMs);
        LOG_INFO("FieldControl: NetOp RECV len=%u timeout=%ums n=%d", (unsigned)len, timeoutMs, n);
        replyWith(mp, requestId, n >= 0, n >= 0 ? NULL : "not connected", n > 0 ? buf : NULL, n > 0 ? (size_t)n : 0);
        break;
    }
    default:
        replyWith(mp, requestId, false, "unknown net op kind");
        break;
    }
#else
    (void)op;
    LOG_WARN("FieldControl: NetOp received but HAS_WIFI is 0 on this build");
    replyWith(mp, requestId, false, "network ops not supported on this hardware");
#endif
}

// Result encoding for ScriptOp.LIST: repeated [nameLen(1) | name(nameLen) | sizeBytes(4,LE)]
// entries, count-prefixed by a single leading byte. EXECUTE's result is whatever
// ScriptEngine collected (see ScriptEngine.h's opcode/output format).
void FieldControlModule::handleScriptOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_ScriptOp &op)
{
    using namespace fieldcontrol;

    switch (op.kind) {
    case meshtastic_ScriptOp_Kind_UPLOAD_CHUNK: {
        ChunkResult r =
            ScriptStore::putChunk(op.script_id, op.chunk_index, op.total_chunks, op.chunk_data.bytes, op.chunk_data.size, op.crc32);
        LOG_INFO("FieldControl: ScriptOp UPLOAD_CHUNK id='%s' %u/%u result=%d", op.script_id, op.chunk_index, op.total_chunks,
                 (int)r);
        replyWith(mp, requestId, r != ChunkResult::ERROR, r != ChunkResult::ERROR ? NULL : "chunk upload failed");
        break;
    }
    case meshtastic_ScriptOp_Kind_EXECUTE: {
        if (scriptTaskHandle != nullptr) {
            replyWith(mp, requestId, false, "a script is already running");
            break;
        }
        int n = ScriptStore::load(op.script_id, scriptBytecode, sizeof(scriptBytecode));
        if (n <= 0) {
            replyWith(mp, requestId, false, "script not found");
            break;
        }
        scriptBytecodeLen = (size_t)n;
        scriptRequesterNode = getFrom(&mp);
        scriptRequestChannel = mp.channel;
        scriptRequestId = requestId;
        scriptAbortRequested = false;

        BaseType_t created = xTaskCreate(&FieldControlModule::scriptTaskEntry, "fieldscript", 8192, this, 1, &scriptTaskHandle);
        if (created != pdPASS) {
            scriptTaskHandle = nullptr;
            replyWith(mp, requestId, false, "failed to start script task");
            break;
        }
        LOG_INFO("FieldControl: ScriptOp EXECUTE id='%s' started in background task", op.script_id);
        replyWith(mp, requestId, true, NULL); // ack: started. A separate FieldMessage(response) with the
                                                // real result follows asynchronously when the task finishes.
        break;
    }
    case meshtastic_ScriptOp_Kind_LIST: {
        auto scripts = ScriptStore::list();
        uint8_t buf[140];
        size_t len = 0;
        buf[len++] = (uint8_t)(scripts.size() > 255 ? 255 : scripts.size());
        for (auto &s : scripts) {
            size_t nameLen = strnlen(s.name, sizeof(s.name));
            if (len + 1 + nameLen + 4 > sizeof(buf)) {
                break;
            }
            buf[len++] = (uint8_t)nameLen;
            memcpy(&buf[len], s.name, nameLen);
            len += nameLen;
            memcpy(&buf[len], &s.sizeBytes, 4);
            len += 4;
        }
        replyWith(mp, requestId, true, NULL, buf, len);
        break;
    }
    case meshtastic_ScriptOp_Kind_DELETE: {
        bool ok = ScriptStore::remove(op.script_id);
        LOG_INFO("FieldControl: ScriptOp DELETE id='%s' ok=%d", op.script_id, ok);
        replyWith(mp, requestId, ok, ok ? NULL : "delete failed");
        break;
    }
    case meshtastic_ScriptOp_Kind_ABORT: {
        if (scriptTaskHandle == nullptr) {
            replyWith(mp, requestId, false, "no script running");
        } else {
            scriptAbortRequested = true;
            replyWith(mp, requestId, true, NULL); // ack: abort requested, not necessarily instant
        }
        break;
    }
    default:
        replyWith(mp, requestId, false, "unknown script op kind");
        break;
    }
}

// Entry point handed to xTaskCreate; just forwards to the instance method and cleans
// itself up. Follows the same pattern as AudioModule's run_codec2/codec2HandlerTask.
void FieldControlModule::scriptTaskEntry(void *param)
{
    static_cast<FieldControlModule *>(param)->runScriptTask();
    vTaskDelete(nullptr);
}

void FieldControlModule::runScriptTask()
{
    // Only compute here - do not call into the mesh send path from this background
    // task (see the class comment in FieldControlModule.h for why). sendScriptCompletion()
    // does the actual send, from runOnce() on the main thread.
    fieldcontrol::ScriptEngine::run(scriptBytecode, scriptBytecodeLen, &scriptResult, &scriptAbortRequested);
    LOG_INFO("FieldControl: script task finished, completed=%d aborted=%d", scriptResult.completed, scriptResult.aborted);
    scriptResultReady = true;
    scriptTaskHandle = nullptr; // allow a new EXECUTE
}

void FieldControlModule::sendScriptCompletion()
{
    meshtastic_FieldMessage r = meshtastic_FieldMessage_init_default;
    r.request_id = scriptRequestId;
    r.which_payload_variant = meshtastic_FieldMessage_response_tag;
    r.response.success = scriptResult.completed;
    if (!scriptResult.completed) {
        const char *why = scriptResult.aborted ? "script aborted" : "script hit its step/time budget or was malformed";
        strncpy(r.response.error, why, sizeof(r.response.error) - 1);
    }
    if (scriptResult.outputLen) {
        size_t n = scriptResult.outputLen < sizeof(r.response.result.bytes) ? scriptResult.outputLen
                                                                             : sizeof(r.response.result.bytes);
        memcpy(r.response.result.bytes, scriptResult.output, n);
        r.response.result.size = n;
    }

    // This is an unsolicited follow-up, not a reply to a packet still in scope, so we
    // can't use setReplyTo() here - address it manually instead. Meshtastic's own
    // decoded.request_id (ack-linking) is deliberately left unset: it was already
    // consumed by the immediate "started" reply - our own r.request_id above is what
    // callers should match on for this async completion message.
    meshtastic_MeshPacket *p = allocDataProtobuf(r);
    p->to = scriptRequesterNode;
    p->channel = scriptRequestChannel;
    p->want_ack = true;
    p->priority = meshtastic_MeshPacket_Priority_RELIABLE;
    service->sendToMesh(p);
    LOG_INFO("FieldControl: sent script completion, completed=%d", scriptResult.completed);
}

int32_t FieldControlModule::runOnce()
{
    if (scriptResultReady) {
        scriptResultReady = false;
        sendScriptCompletion();
    }
    return 500;
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

    // Supplementary replay guard (see the class comment in FieldControlModule.h) - skip it
    // for the response variant, which we never act on anyway.
    if (decoded->which_payload_variant != meshtastic_FieldMessage_response_tag) {
        NodeNum fromNode = getFrom(&mp);
        if (isReplay(fromNode, requestId)) {
            LOG_WARN("FieldControl: duplicate request_id %u from 0x%x, ignoring (possible replay)", requestId, fromNode);
            return true;
        }
        rememberRequest(fromNode, requestId);
    }

    switch (decoded->which_payload_variant) {
    case meshtastic_FieldMessage_wifi_tag:
        handleWifiOp(mp, requestId, decoded->wifi);
        break;
    case meshtastic_FieldMessage_bt_tag:
        handleBtOp(mp, requestId, decoded->bt);
        break;
    case meshtastic_FieldMessage_net_tag:
        handleNetOp(mp, requestId, decoded->net);
        break;
    case meshtastic_FieldMessage_script_tag:
        handleScriptOp(mp, requestId, decoded->script);
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
