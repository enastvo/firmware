#pragma once
#include "configuration.h"
#include "fieldcontrol/ChunkedStore.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fieldcontrol
{

using ScriptInfo = BlobInfo;

/**
 * Thin static facade over ChunkedStore("/scripts") - see ChunkedStore.h for the
 * actual implementation (shared with FileStore). Kept as its own class so call
 * sites in FieldControlModule read as ScriptStore::putChunk(...) etc.
 */
class ScriptStore
{
  public:
    static constexpr size_t MAX_SCRIPT_SIZE = ChunkedStore::MAX_BLOB_SIZE;

    static ChunkResult putChunk(const char *scriptId, uint32_t chunkIndex, uint32_t totalChunks, const uint8_t *data,
                                size_t len, uint32_t crc32OnFinal)
    {
        return store().putChunk(scriptId, chunkIndex, totalChunks, data, len, crc32OnFinal);
    }

    static int load(const char *scriptId, uint8_t *buf, size_t bufLen) { return store().load(scriptId, buf, bufLen); }

    static bool remove(const char *scriptId) { return store().remove(scriptId); }

    static std::vector<ScriptInfo> list(size_t maxCount = 16) { return store().list(maxCount); }

  private:
    static ChunkedStore &store()
    {
        static ChunkedStore s("/scripts");
        return s;
    }
};

} // namespace fieldcontrol
