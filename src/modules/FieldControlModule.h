#pragma once
#include "ProtobufModule.h"
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
 * UPLOAD_CHUNK/EXECUTE/LIST/DELETE - EXECUTE runs synchronously for now (see
 * ScriptEngine.h for why), so ABORT isn't meaningful until Phase 6 hardening adds
 * a background execution task.
 */
class FieldControlModule : public ProtobufModule<meshtastic_FieldMessage>
{
  public:
    FieldControlModule();

  protected:
    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_FieldMessage *decoded) override;

  private:
    void replyWith(const meshtastic_MeshPacket &req, uint32_t requestId, bool success, const char *error,
                    const uint8_t *result = nullptr, size_t resultLen = 0);
    bool isAuthorized(const meshtastic_MeshPacket &mp);
    void handleWifiOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_WifiOp &op);
    void handleBtOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_BtOp &op);
    void handleNetOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_NetOp &op);
    void handleScriptOp(const meshtastic_MeshPacket &mp, uint32_t requestId, const meshtastic_ScriptOp &op);
};

extern FieldControlModule *fieldControlModule;
