#pragma once
#include "configuration.h"
#include "fieldcontrol/ChunkedStore.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fieldcontrol
{

using FileInfo = BlobInfo;

/**
 * Thin static facade over ChunkedStore("/files") - generic file uploads (any
 * bytes, not interpreted as bytecode), independent of ScriptStore's "/scripts".
 * See ChunkedStore.h for the shared implementation.
 */
class FileStore
{
  public:
    static constexpr size_t MAX_FILE_SIZE = ChunkedStore::MAX_BLOB_SIZE;

    static ChunkResult putChunk(const char *fileId, uint32_t chunkIndex, uint32_t totalChunks, const uint8_t *data, size_t len,
                                uint32_t crc32OnFinal)
    {
        return store().putChunk(fileId, chunkIndex, totalChunks, data, len, crc32OnFinal);
    }

    static int load(const char *fileId, uint8_t *buf, size_t bufLen) { return store().load(fileId, buf, bufLen); }

    static bool remove(const char *fileId) { return store().remove(fileId); }

    static std::vector<FileInfo> list(size_t maxCount = 16) { return store().list(maxCount); }

  private:
    static ChunkedStore &store()
    {
        static ChunkedStore s("/files");
        return s;
    }
};

} // namespace fieldcontrol
