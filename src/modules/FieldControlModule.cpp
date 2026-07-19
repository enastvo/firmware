#include "FieldControlModule.h"
#include "MeshService.h"
#include "Router.h"
#include "configuration.h"
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

void FieldControlModule::replyWith(const meshtastic_MeshPacket &req, uint32_t requestId, bool success, const char *error)
{
    meshtastic_FieldMessage r = meshtastic_FieldMessage_init_default;
    r.request_id = requestId;
    r.which_payload_variant = meshtastic_FieldMessage_response_tag;
    r.response.success = success;
    if (error) {
        strncpy(r.response.error, error, sizeof(r.response.error) - 1);
    }

    meshtastic_MeshPacket *p = allocDataProtobuf(r);
    setReplyTo(p, req);
    myReply = p;
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
    case meshtastic_FieldMessage_wifi_tag: {
        if (decoded->wifi.kind == meshtastic_WifiOp_Kind_STATUS) {
            // Phase 1: prove the round trip works. Real status reporting arrives in Phase 2
            // (WifiControl), see docs/architecture.md.
            LOG_INFO("FieldControl: WifiOp STATUS (Phase 1 stub reply)");
            replyWith(mp, requestId, true, NULL);
        } else {
            LOG_WARN("FieldControl: WifiOp kind %d not implemented until Phase 2", decoded->wifi.kind);
            replyWith(mp, requestId, false, "wifi op not implemented yet");
        }
        break;
    }
    case meshtastic_FieldMessage_bt_tag:
        LOG_WARN("FieldControl: BtOp not implemented until Phase 3");
        replyWith(mp, requestId, false, "bt op not implemented yet");
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
