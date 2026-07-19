#pragma once
#include "configuration.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fieldcontrol
{

enum class ChunkResult { OK, COMPLETE, ERROR };

struct ScriptInfo {
    char name[32];
    uint32_t sizeBytes;
};

/**
 * LittleFS-backed storage for uploaded scripts (see docs/architecture.md, Phase 5).
 * Only one upload can be in progress at a time - starting a new one (chunkIndex==0
 * for a different scriptId) abandons any prior incomplete upload.
 */
class ScriptStore
{
  public:
    static constexpr size_t MAX_SCRIPT_SIZE = 4096;

    /**
     * Handles one ScriptOp.UPLOAD_CHUNK. Returns OK if more chunks are expected,
     * COMPLETE if this was the final chunk and crc32OnFinal matched the
     * reassembled blob (the script is now stored under scriptId and executable),
     * ERROR on an out-of-order chunk, CRC mismatch, oversized script, or IO error.
     */
    static ChunkResult putChunk(const char *scriptId, uint32_t chunkIndex, uint32_t totalChunks, const uint8_t *data,
                                size_t len, uint32_t crc32OnFinal);

    /// Loads a fully-uploaded script into buf. Returns bytes loaded, or negative on failure.
    static int load(const char *scriptId, uint8_t *buf, size_t bufLen);

    static bool remove(const char *scriptId);

    /// Lists stored scripts (name + size), up to maxCount.
    static std::vector<ScriptInfo> list(size_t maxCount = 16);
};

} // namespace fieldcontrol
