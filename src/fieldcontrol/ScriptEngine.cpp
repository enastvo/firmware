#include "fieldcontrol/ScriptEngine.h"
#include "configuration.h"
#include "fieldcontrol/BtControl.h"
#include "fieldcontrol/NetControl.h"
#include "fieldcontrol/WifiControl.h"
#include <cstring>

namespace fieldcontrol
{

namespace
{
constexpr uint8_t OP_HALT = 0x00;
constexpr uint8_t OP_DELAY = 0x01;
constexpr uint8_t OP_JMP = 0x02;
constexpr uint8_t OP_JZ = 0x03;
constexpr uint8_t OP_JNZ = 0x04;
constexpr uint8_t OP_SET = 0x05;
constexpr uint8_t OP_ADD = 0x06;
constexpr uint8_t OP_WIFI_STATUS = 0x10;
constexpr uint8_t OP_WIFI_ASSOC = 0x11;
constexpr uint8_t OP_WIFI_DISASSOC = 0x12;
constexpr uint8_t OP_WIFI_SCAN = 0x13;
constexpr uint8_t OP_BT_SCAN = 0x20;
constexpr uint8_t OP_NET_PING = 0x30;
constexpr uint8_t OP_NET_TCP_CONNECT = 0x31;
constexpr uint8_t OP_NET_TCP_CLOSE = 0x32;
constexpr uint8_t OP_NET_TCP_CONNECT_INDEXED = 0x33;
constexpr uint8_t OP_PORT_TABLE = 0x40;

// Both raised to fit a full common-ports scan (~1000 ports): each loop iteration is
// ~5 instructions (NET_TCP_CONNECT_INDEXED, NET_TCP_CLOSE, 2x ADD, JNZ), so 1000
// ports needs ~5000 instructions; wall-clock is bounded by real TCP connect timeouts
// (1000 ports at up to a few hundred ms each for filtered/dropped ports can run several
// minutes). Safe now that EXECUTE runs in its own background task (Phase 6) - a
// longer-running script no longer blocks the module's own packet handling.
constexpr uint32_t MAX_INSTRUCTIONS = 10000;
constexpr uint32_t MAX_WALLCLOCK_MS = 300000;
constexpr size_t MAX_CONSTS = 16;
constexpr size_t NUM_REGS = 4;

struct Const {
    const uint8_t *data = nullptr;
    uint8_t len = 0;
};

class Interpreter
{
  public:
    Interpreter(const uint8_t *bytecode, size_t len, volatile bool *abortFlag) : buf(bytecode), bufLen(len), abort(abortFlag) {}

    void run(ScriptRunResult *result)
    {
        result->completed = false;
        result->aborted = false;
        result->outputLen = 0;

        if (!parseHeader()) {
            return;
        }

        size_t pc = codeStart;
        uint32_t startMs = millis();
        uint32_t steps = 0;
        bool ok = true;

        while (pc < bufLen) {
            if (abort && *abort) {
                ok = false;
                result->aborted = true;
                break;
            }
            if (++steps > MAX_INSTRUCTIONS || millis() - startMs > MAX_WALLCLOCK_MS) {
                ok = false;
                break;
            }

            uint8_t op = buf[pc++];

            if (op == OP_HALT) {
                result->completed = true;
                break;
            } else if (op == OP_DELAY) {
                if (pc + 2 > bufLen) {
                    ok = false;
                    break;
                }
                if (!delayCheckingAbort(readU16(pc))) {
                    ok = false;
                    result->aborted = true;
                    break;
                }
                pc += 2;
            } else if (op == OP_JMP) {
                if (pc + 2 > bufLen) {
                    ok = false;
                    break;
                }
                pc = codeStart + readU16(pc);
            } else if (op == OP_JZ || op == OP_JNZ) {
                if (pc + 3 > bufLen || buf[pc] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                bool zero = (regs[buf[pc]] == 0);
                uint16_t addr = readU16(pc + 1);
                pc += 3;
                if ((op == OP_JZ && zero) || (op == OP_JNZ && !zero)) {
                    pc = codeStart + addr;
                }
            } else if (op == OP_SET || op == OP_ADD) {
                if (pc + 5 > bufLen || buf[pc] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                uint8_t reg = buf[pc];
                int32_t val = readI32(pc + 1);
                pc += 5;
                if (op == OP_SET) {
                    regs[reg] = val;
                } else {
                    regs[reg] += val;
                }
            }
#if HAS_WIFI
            else if (op == OP_WIFI_STATUS) {
                if (pc + 1 > bufLen || buf[pc] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                uint8_t reg = buf[pc++];
                regs[reg] = WifiControl::status().connected ? 1 : 0;
                appendOutput(op, regs[reg]);
            } else if (op == OP_WIFI_ASSOC) {
                if (pc + 2 > bufLen) {
                    ok = false;
                    break;
                }
                char ssidBuf[33], pskBuf[64];
                WifiControl::associate(constCStr(buf[pc], ssidBuf, sizeof(ssidBuf)), constCStr(buf[pc + 1], pskBuf, sizeof(pskBuf)));
                pc += 2;
            } else if (op == OP_WIFI_DISASSOC) {
                WifiControl::disassociate();
            } else if (op == OP_WIFI_SCAN) {
                if (pc + 1 > bufLen || buf[pc] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                uint8_t reg = buf[pc++];
                char ssid[33];
                int8_t rssi;
                int n = WifiControl::scan(ssid, sizeof(ssid), &rssi);
                regs[reg] = n;
                appendOutput(op, n);
            } else if (op == OP_NET_PING) {
                if (pc + 2 > bufLen || buf[pc + 1] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                char hostBuf[64];
                PingResult pr;
                NetControl::ping(constCStr(buf[pc], hostBuf, sizeof(hostBuf)), 4, &pr);
                regs[buf[pc + 1]] = pr.received;
                appendOutput(op, pr.received);
                pc += 2;
            } else if (op == OP_NET_TCP_CONNECT) {
                // hostConst:u8 portReg:u8 timeoutMs:u16 resultReg:u8 - port comes from a
                // register (not an immediate) so a scan loop can vary it each iteration.
                // Unlike NET_PING/WIFI_SCAN this only reports (appends output) on success,
                // so a scan of many ports stays compact - see ScriptEngine.h.
                if (pc + 5 > bufLen || buf[pc + 1] >= NUM_REGS || buf[pc + 4] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                char hostBuf[64];
                uint8_t hostC = buf[pc];
                uint16_t port = (uint16_t)regs[buf[pc + 1]];
                uint16_t timeoutMs = readU16(pc + 2);
                uint8_t resultReg = buf[pc + 4];
                pc += 5;
                bool connected = NetControl::tcpConnect(constCStr(hostC, hostBuf, sizeof(hostBuf)), port, timeoutMs);
                regs[resultReg] = connected ? 1 : 0;
                if (connected) {
                    appendOutput(op, port);
                }
            } else if (op == OP_NET_TCP_CLOSE) {
                NetControl::tcpClose();
            } else if (op == OP_PORT_TABLE) {
                // count:u16 followed by count * u16(LE) port values, embedded directly in
                // the instruction stream (not the 255-byte-limited string constant pool,
                // which can't hold e.g. a 1000-port table). Not "executed" beyond recording
                // where the table is and skipping past it - see NET_TCP_CONNECT_INDEXED.
                if (pc + 2 > bufLen) {
                    ok = false;
                    break;
                }
                uint16_t count = readU16(pc);
                size_t tableBytes = (size_t)count * 2;
                if (pc + 2 + tableBytes > bufLen) {
                    ok = false;
                    break;
                }
                portTable = &buf[pc + 2];
                portTableCount = count;
                pc += 2 + tableBytes;
            } else if (op == OP_NET_TCP_CONNECT_INDEXED) {
                // hostConst:u8 indexReg:u8 timeoutMs:u16 resultReg:u8 - port is read from
                // the most recently declared OP_PORT_TABLE at position regs[indexReg],
                // for scanning a specific list of ports (not a contiguous range, which
                // NET_TCP_CONNECT's direct register value already covers). Reports the
                // real port number (not the index) on success, same convention as
                // NET_TCP_CONNECT.
                if (pc + 5 > bufLen || buf[pc + 1] >= NUM_REGS || buf[pc + 4] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                char hostBuf[64];
                uint8_t hostC = buf[pc];
                int32_t index = regs[buf[pc + 1]];
                uint16_t timeoutMs = readU16(pc + 2);
                uint8_t resultReg = buf[pc + 4];
                pc += 5;
                if (!portTable || index < 0 || (uint32_t)index >= portTableCount) {
                    regs[resultReg] = 0;
                } else {
                    uint16_t port;
                    memcpy(&port, &portTable[(size_t)index * 2], 2);
                    bool connected = NetControl::tcpConnect(constCStr(hostC, hostBuf, sizeof(hostBuf)), port, timeoutMs);
                    regs[resultReg] = connected ? 1 : 0;
                    if (connected) {
                        appendOutput(op, port);
                    }
                }
            }
#endif
#if HAS_BLUETOOTH
            else if (op == OP_BT_SCAN) {
                if (pc + 1 > bufLen || buf[pc] >= NUM_REGS) {
                    ok = false;
                    break;
                }
                uint8_t reg = buf[pc++];
                BtScanResult best{};
                int n = BtControl::scan(&best);
                regs[reg] = n;
                appendOutput(op, n);
            }
#endif
            else {
                ok = false;
                break;
            }
        }

        if (!ok) {
            result->completed = false;
        }
        memcpy(result->output, outBuf, outLen);
        result->outputLen = outLen;
    }

  private:
    bool parseHeader()
    {
        if (bufLen < 2 || buf[0] != 1 /* version */) {
            return false;
        }
        uint8_t constCount = buf[1];
        size_t pos = 2;
        for (uint8_t i = 0; i < constCount; i++) {
            if (pos >= bufLen) {
                return false;
            }
            uint8_t clen = buf[pos++];
            if (pos + clen > bufLen) {
                return false;
            }
            if (i < MAX_CONSTS) {
                consts[i].data = &buf[pos];
                consts[i].len = clen;
                numConsts = i + 1;
            }
            pos += clen;
        }
        codeStart = pos;
        return true;
    }

    const char *constCStr(uint8_t idx, char *scratch, size_t scratchLen)
    {
        if (idx >= numConsts) {
            scratch[0] = '\0';
            return scratch;
        }
        size_t n = consts[idx].len < scratchLen - 1 ? consts[idx].len : scratchLen - 1;
        memcpy(scratch, consts[idx].data, n);
        scratch[n] = '\0';
        return scratch;
    }

    void appendOutput(uint8_t opcode, int32_t value)
    {
        if (outLen + 5 > sizeof(outBuf)) {
            return; // silently drop once full - script keeps running
        }
        outBuf[outLen++] = opcode;
        memcpy(&outBuf[outLen], &value, 4);
        outLen += 4;
    }

    uint16_t readU16(size_t pos)
    {
        uint16_t v;
        memcpy(&v, &buf[pos], 2);
        return v;
    }

    int32_t readI32(size_t pos)
    {
        int32_t v;
        memcpy(&v, &buf[pos], 4);
        return v;
    }

    // Waits ms in short slices so an abort request lands promptly instead of only
    // being noticed between whole instructions. Returns false if aborted partway.
    bool delayCheckingAbort(uint16_t ms)
    {
        uint32_t remaining = ms;
        while (remaining > 0) {
            if (abort && *abort) {
                return false;
            }
            uint32_t step = remaining < 50 ? remaining : 50;
            delay(step);
            remaining -= step;
        }
        return true;
    }

    const uint8_t *buf;
    size_t bufLen;
    volatile bool *abort;
    size_t codeStart = 0;
    Const consts[MAX_CONSTS];
    uint8_t numConsts = 0;
    int32_t regs[NUM_REGS] = {0, 0, 0, 0};
    uint8_t outBuf[100];
    size_t outLen = 0;
    const uint8_t *portTable = nullptr;
    uint16_t portTableCount = 0;
};

} // namespace

void ScriptEngine::run(const uint8_t *bytecode, size_t len, ScriptRunResult *result, volatile bool *abortFlag)
{
    Interpreter interp(bytecode, len, abortFlag);
    interp.run(result);
}

} // namespace fieldcontrol
