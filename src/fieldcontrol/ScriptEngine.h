#pragma once
#include "configuration.h"

#include <cstddef>
#include <cstdint>

namespace fieldcontrol
{

struct ScriptRunResult {
    bool completed; // true if HALT was reached; false if the step/wall-clock budget was hit,
                     // a malformed instruction was found, or the script was aborted
    bool aborted;    // true specifically if *abortFlag was set mid-run (see run())
    uint8_t output[140];
    size_t outputLen;
};

/**
 * Compact register-based bytecode interpreter for uploaded scripts (see
 * docs/architecture.md, Phase 5). Bytecode format:
 *
 *   [u8 version=1]
 *   [u8 constCount]
 *     constCount times: [u8 len][len bytes]   - raw string constants (SSIDs, hosts, ...)
 *   [instructions until end of buffer]
 *     each instruction: [u8 opcode][operands, see ScriptEngine.cpp's opcode table]
 *
 * 4 general i32 registers. "Reporting" opcodes (WIFI_STATUS/WIFI_SCAN/BT_SCAN/NET_PING)
 * each append a compact [opcode(1) | value(4,i32)] record to the output buffer, which
 * becomes the ScriptOp.EXECUTE response's result bytes. NET_TCP_CONNECT only reports
 * when the connection succeeds (the port number as the value) - unlike the others it
 * doesn't report every call, so a port-scan loop's output stays proportional to how
 * many ports were actually open, not how many were probed.
 *
 * Phase 6 moves execution into its own FreeRTOS task (see FieldControlModule) so a
 * long-running script can't block the module's packet handling; abortFlag lets that
 * caller request early termination (checked between every instruction, and inside
 * DELAY's wait loop so a long delay doesn't make abort unresponsive). Still has a
 * hard instruction-count + wall-clock budget as a backstop even without an abort
 * request.
 */
class ScriptEngine
{
  public:
    static void run(const uint8_t *bytecode, size_t len, ScriptRunResult *result, volatile bool *abortFlag = nullptr);
};

} // namespace fieldcontrol
