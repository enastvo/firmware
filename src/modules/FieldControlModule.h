#pragma once
#include "ProtobufModule.h"
#include "concurrency/OSThread.h"
#include "fieldcontrol/FileStore.h"
#include "fieldcontrol/ScriptEngine.h"
#include "fieldcontrol/ScriptStore.h"
#include "freertosinc.h"
#include "mesh/Channels.h"
#include "mesh/generated/meshtastic/field_control.pb.h"

/**
 * Barn remote-control module (see docs/architecture.md in the project repo).
 *
 * Runs on meshtastic_PortNum_PRIVATE_APP. A Controller node sends a FieldMessage
 * with one of the command variants (wifi/bt/net/script) set; this module (running
 * on the Agent) executes it and replies with a FieldMessage carrying the same
 * request_id and the `response` variant set.
 *
 * Authorization: Meshtastic auto-upgrades direct unicast messages to PKI
 * (public-key) encryption whenever the sender already knows the destination's
 * public key, which bypasses channel-PSK encryption entirely and reports
 * mp.channel as 0 regardless of the channel the client asked for. Framework-level
 * boundChannel binding can't distinguish "arrived unencrypted on the wrong
 * channel" from "arrived PKI-encrypted, channel field just isn't meaningful" - so
 * this module does its own check in handleReceivedProtobuf instead of setting
 * boundChannel: accept if mp.pki_encrypted, OR if it arrived on the dedicated
 * "fieldctrl" private channel (kept for a future broadcast-to-many-Agents path
 * where PKI, which is inherently point-to-point, doesn't apply).
 *
 * Phase 2 adds real WiFi control (WifiControl, see src/fieldcontrol/) for
 * WifiOp SCAN/ASSOCIATE/DISASSOCIATE/STATUS. Phase 3 adds real Bluetooth control
 * (BtControl) for BtOp SCAN/CONNECT/DISCONNECT/GATT_READ/GATT_WRITE. Phase 4 adds
 * real network-layer control (NetControl) for NetOp PING/TCP_CONNECT/SEND/RECV,
 * usable once WifiOp.ASSOCIATE has joined a network. Phase 5 adds script storage
 * (ScriptStore) and a bytecode interpreter (ScriptEngine) for ScriptOp
 * UPLOAD_CHUNK/EXECUTE/LIST/DELETE. Added alongside the unified CLI: FileOp
 * UPLOAD_CHUNK/LIST/DELETE for generic file uploads (FileStore, no EXECUTE - files
 * are opaque bytes, not bytecode), sharing ChunkedStore's implementation with
 * ScriptStore but a separate "/files" root and independent upload-progress state.
 *
 * Phase 6 hardening:
 *  - EXECUTE now runs in its own FreeRTOS task instead of blocking this module's
 *    packet handling for the script's duration. ABORT sets a flag the task checks
 *    between instructions and inside DELAY's wait loop. Only one script can run at
 *    a time. The task itself does NOT call into the mesh send path directly -
 *    testing showed a packet sent that way was missing the PKI auto-encryption
 *    every other reply gets (see Router.cpp's "Use PKI!" condition, which doesn't
 *    obviously depend on calling context, but the observed behavior differed
 *    regardless), which isn't worth the risk to chase further. Instead the task
 *    just stashes the result and sets scriptResultReady; runOnce() (below),
 *    called from the main thread like every other module's packet handling,
 *    notices the flag and sends the actual FieldMessage from there - the same
 *    context/call path that already reliably gets PKI treatment. The completion
 *    message is matched by our own FieldMessage.request_id, not Meshtastic's own
 *    ack-linking (that was already consumed by the immediate "started" reply).
 *  - A small replay window (isReplay/rememberRequest) rejects a duplicate
 *    (fromNode, request_id) pair. This is a supplementary defense on top of PKI's
 *    AEAD (which already rejects tampered ciphertext) and Meshtastic's own
 *    packet-ID dedup (PacketHistory, which is capacity-bounded, not a strict time
 *    window) - it specifically guards against a captured ciphertext being blindly
 *    replayed later after it's aged out of that generic dedup. It resets on
 *    reboot, which is an accepted tradeoff, not a bug.
 */
class FieldControlModule : public ProtobufModule<meshtastic_FieldMessage>, private concurrency::OSThread
{
  public:
    FieldControlModule();

  protected:
    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_FieldMessage *decoded) override;
    virtual int32_t runOnce() override;

  private:
    void replyWith(const meshtastic_MeshPacket &req, uint32_t requestId, bool success, const char *error,
                    const uint8_t *result = nullptr, size_t resultLen = 0);
    bool isAuthorized(const meshtastic_MeshPacket &mp);
    bool isReplay(uint32_t fromNode, uint32_t requestId);
    void rememberRequest(uint32_t fromNode, uint32_t requestId);
    void handleWifiOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_WifiOp &op);
    void handleBtOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_BtOp &op);
    void handleNetOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_NetOp &op);
    void handleScriptOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_ScriptOp &op);
    void handleFileOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_FileOp &op);

    static void scriptTaskEntry(void *param);
    void runScriptTask();
    void sendScriptCompletion();

    static constexpr size_t SEEN_WINDOW = 32;
    struct SeenRequest {
        uint32_t fromNode = 0;
        uint32_t requestId = 0;
        bool valid = false;
    };
    SeenRequest seenRequests[SEEN_WINDOW];
    size_t seenRequestsNext = 0;

    TaskHandle_t scriptTaskHandle = nullptr;
    volatile bool scriptAbortRequested = false;
    volatile bool scriptResultReady = false;
    fieldcontrol::ScriptRunResult scriptResult;
    NodeNum scriptRequesterNode = 0;
    ChannelIndex scriptRequestChannel = 0;
    uint32_t scriptRequestId = 0;
    static uint8_t scriptBytecode[fieldcontrol::ScriptStore::MAX_SCRIPT_SIZE];
    size_t scriptBytecodeLen = 0;
};

extern FieldControlModule *fieldControlModule;
