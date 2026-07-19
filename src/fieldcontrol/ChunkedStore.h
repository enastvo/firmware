#pragma once
#include "configuration.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace fieldcontrol
{

enum class ChunkResult { OK, COMPLETE, ERROR };

struct BlobInfo {
    char name[32];
    uint32_t sizeBytes;
};

/**
 * LittleFS-backed chunked-upload/CRC32/list/delete storage, shared by ScriptStore
 * (see docs/architecture.md, Phase 5) and FileStore (generic file uploads, added
 * alongside the unified CLI). Each instance owns one root directory and its own
 * upload-progress state, so two independent stores (scripts vs. files) can each
 * have an upload in flight without interfering with each other.
 *
 * Only one upload can be in progress at a time *per instance* - starting a new one
 * (chunkIndex==0 for a different id) abandons any prior incomplete upload on that
 * same store.
 */
class ChunkedStore
{
  public:
    static constexpr size_t MAX_BLOB_SIZE = 4096;

    explicit ChunkedStore(const char *rootDir) : root(rootDir) {}

    /**
     * Handles one UPLOAD_CHUNK. Returns OK if more chunks are expected, COMPLETE
     * if this was the final chunk and crc32OnFinal matched the reassembled blob
     * (now stored under id), ERROR on an out-of-order chunk, CRC mismatch,
     * oversized blob, or IO error.
     */
    ChunkResult putChunk(const char *id, uint32_t chunkIndex, uint32_t totalChunks, const uint8_t *data, size_t len,
                         uint32_t crc32OnFinal);

    /// Loads a fully-uploaded blob into buf. Returns bytes loaded, or negative on failure.
    int load(const char *id, uint8_t *buf, size_t bufLen);

    bool remove(const char *id);

    /// Lists stored blobs (name + size), up to maxCount.
    std::vector<BlobInfo> list(size_t maxCount = 16);

  private:
    void blobPath(const char *id, char *out, size_t outLen);
    void blobTmpPath(const char *id, char *out, size_t outLen);

    const char *root;
    char uploadId[17] = {0};
    uint32_t expectedChunk = 0;
    uint32_t totalChunksExpected = 0;
    size_t uploadedBytes = 0;
};

} // namespace fieldcontrol
