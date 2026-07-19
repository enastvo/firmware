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
 * Phase 1 only implements WifiOp.STATUS, returning a stub result, to prove the
 * protobuf schema / unicast-with-ack / authorization plumbing works end to end
 * before any real WiFi/BT/script logic is added in later phases.
 */
class FieldControlModule : public ProtobufModule<meshtastic_FieldMessage>
{
  public:
    FieldControlModule();

  protected:
    virtual bool handleReceivedProtobuf(const meshtastic_MeshPacket &mp, meshtastic_FieldMessage *decoded) override;

  private:
    void replyWith(const meshtastic_MeshPacket &req, uint32_t requestId, bool success, const char *error);
    bool isAuthorized(const meshtastic_MeshPacket &mp);
};

extern FieldControlModule *fieldControlModule;
