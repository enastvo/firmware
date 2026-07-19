#pragma once
#include "configuration.h"

#include <cstddef>
#include <cstdint>

namespace fieldcontrol
{

struct ScriptRunResult {
    bool completed; // true if HALT was reached; false if the step/wall-clock budget was hit
                     // or a malformed instruction was found
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
 * becomes the ScriptOp.EXECUTE response's result bytes.
 *
 * Runs synchronously within the calling context (FieldControlModule, on the main
 * packet-handling path) with a hard instruction-count + wall-clock budget as a basic
 * safety net. A real background FreeRTOS task with mid-execution ScriptOp.ABORT
 * support is deferred to Phase 6 hardening rather than built here, since Phase 5's
 * goal is a working interpreter, not the full async/watchdog design.
 */
class ScriptEngine
{
  public:
    static void run(const uint8_t *bytecode, size_t len, ScriptRunResult *result);
};

} // namespace fieldcontrol
