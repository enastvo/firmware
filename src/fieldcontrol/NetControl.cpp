#include "fieldcontrol/NetControl.h"

#if HAS_WIFI

#include <WiFi.h>
#include <cstring>
#include <ping/ping_sock.h>

namespace fieldcontrol
{

static WiFiClient sClient;

namespace
{
struct PingCtx {
    uint8_t sent = 0;
    uint8_t received = 0;
    uint32_t totalMs = 0;
    uint16_t minMs = 0xFFFF;
    uint16_t maxMs = 0;
    volatile bool done = false;
};

void onPingSuccess(esp_ping_handle_t hdl, void *args)
{
    PingCtx *ctx = (PingCtx *)args;
    uint32_t elapsedMs = 0;
    esp_ping_get_profile(hdl, ESP_PING_PROF_TIMEGAP, &elapsedMs, sizeof(elapsedMs));
    ctx->sent++;
    ctx->received++;
    ctx->totalMs += elapsedMs;
    if (elapsedMs < ctx->minMs) {
        ctx->minMs = (uint16_t)elapsedMs;
    }
    if (elapsedMs > ctx->maxMs) {
        ctx->maxMs = (uint16_t)elapsedMs;
    }
}

void onPingTimeout(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    ((PingCtx *)args)->sent++;
}

void onPingEnd(esp_ping_handle_t hdl, void *args)
{
    (void)hdl;
    ((PingCtx *)args)->done = true;
}
} // namespace

bool NetControl::ping(const char *host, uint8_t count, PingResult *result)
{
    memset(result, 0, sizeof(*result));
    if (!host || !host[0] || count == 0) {
        return false;
    }

    IPAddress ip;
    if (!WiFi.hostByName(host, ip)) {
        return false;
    }

    ip_addr_t target;
    IP_ADDR4(&target, ip[0], ip[1], ip[2], ip[3]);

    esp_ping_config_t config = ESP_PING_DEFAULT_CONFIG();
    config.target_addr = target;
    config.count = count;
    config.interval_ms = 500;
    config.timeout_ms = 1000;

    PingCtx ctx;
    esp_ping_callbacks_t cbs = {};
    cbs.cb_args = &ctx;
    cbs.on_ping_success = onPingSuccess;
    cbs.on_ping_timeout = onPingTimeout;
    cbs.on_ping_end = onPingEnd;

    esp_ping_handle_t hdl;
    if (esp_ping_new_session(&config, &cbs, &hdl) != ESP_OK) {
        return false;
    }
    esp_ping_start(hdl);

    uint32_t deadline = millis() + (uint32_t)count * 1600 + 2000;
    while (!ctx.done && millis() < deadline) {
        delay(50);
    }

    esp_ping_stop(hdl);
    esp_ping_delete_session(hdl);

    result->sent = ctx.sent;
    result->received = ctx.received;
    if (ctx.received > 0) {
        result->avgMs = (uint16_t)(ctx.totalMs / ctx.received);
        result->minMs = ctx.minMs;
        result->maxMs = ctx.maxMs;
    }
    return true;
}

bool NetControl::tcpConnect(const char *host, uint16_t port)
{
    if (sClient.connected()) {
        sClient.stop();
    }
    return sClient.connect(host, port, 5000) != 0;
}

void NetControl::tcpClose()
{
    sClient.stop();
}

bool NetControl::tcpConnected()
{
    return sClient.connected();
}

int NetControl::tcpSend(const uint8_t *data, size_t len)
{
    if (!sClient.connected()) {
        return -1;
    }
    return (int)sClient.write(data, len);
}

int NetControl::tcpRecv(uint8_t *out, size_t outLen, uint32_t timeoutMs)
{
    if (!sClient.connected()) {
        return -1;
    }
    uint32_t deadline = millis() + timeoutMs;
    while (sClient.available() == 0 && millis() < deadline) {
        delay(20);
    }
    int avail = sClient.available();
    if (avail <= 0) {
        return 0;
    }
    size_t n = (size_t)avail < outLen ? (size_t)avail : outLen;
    return sClient.read(out, n);
}

} // namespace fieldcontrol

#endif // HAS_WIFI
