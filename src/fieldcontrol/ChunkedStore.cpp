#include "fieldcontrol/ChunkedStore.h"
#include "FSCommon.h"
#include "SPILock.h"
#include <ErriezCRC32.h>
#include <cstdio>
#include <cstring>

namespace fieldcontrol
{

void ChunkedStore::blobPath(const char *id, char *out, size_t outLen)
{
    snprintf(out, outLen, "%s/%s", root, id);
}

void ChunkedStore::blobTmpPath(const char *id, char *out, size_t outLen)
{
    snprintf(out, outLen, "%s/.%s.tmp", root, id);
}

ChunkResult ChunkedStore::putChunk(const char *id, uint32_t chunkIndex, uint32_t totalChunks, const uint8_t *data, size_t len,
                                   uint32_t crc32OnFinal)
{
    if (!id || !id[0] || totalChunks == 0 || chunkIndex >= totalChunks) {
        return ChunkResult::ERROR;
    }

    char tmpPath[48];
    blobTmpPath(id, tmpPath, sizeof(tmpPath));

    spiLock->lock();
    FSCom.mkdir(root);

    if (chunkIndex == 0) {
        // (Re)start a fresh upload, abandoning any previous incomplete one.
        strncpy(uploadId, id, sizeof(uploadId) - 1);
        uploadId[sizeof(uploadId) - 1] = '\0';
        expectedChunk = 0;
        totalChunksExpected = totalChunks;
        uploadedBytes = 0;
        FSCom.remove(tmpPath);
    }

    if (strncmp(uploadId, id, sizeof(uploadId)) != 0 || chunkIndex != expectedChunk || totalChunksExpected != totalChunks ||
        uploadedBytes + len > MAX_BLOB_SIZE) {
        spiLock->unlock();
        return ChunkResult::ERROR;
    }

    File f = FSCom.open(tmpPath, chunkIndex == 0 ? FILE_O_WRITE : FILE_APPEND);
    if (!f) {
        spiLock->unlock();
        return ChunkResult::ERROR;
    }
    size_t written = f.write(data, len);
    f.close();

    if (written != len) {
        spiLock->unlock();
        return ChunkResult::ERROR;
    }
    uploadedBytes += len;
    expectedChunk++;

    bool isFinal = (chunkIndex + 1 == totalChunks);
    if (!isFinal) {
        spiLock->unlock();
        return ChunkResult::OK;
    }

    // Final chunk: verify CRC32 of the whole reassembled blob before making it visible.
    File rf = FSCom.open(tmpPath, FILE_O_READ);
    if (!rf) {
        spiLock->unlock();
        return ChunkResult::ERROR;
    }
    size_t fileSize = rf.size();
    std::vector<uint8_t> blob(fileSize);
    size_t readBytes = rf.read(blob.data(), fileSize);
    rf.close();

    bool crcOk = (readBytes == fileSize) && (crc32Buffer(blob.data(), fileSize) == crc32OnFinal);
    if (!crcOk) {
        FSCom.remove(tmpPath);
        spiLock->unlock();
        return ChunkResult::ERROR;
    }

    char finalPath[48];
    blobPath(id, finalPath, sizeof(finalPath));
    FSCom.remove(finalPath); // clear any previous version
    spiLock->unlock();

    // renameFile takes the SPI lock itself - must not be called while we hold it.
    renameFile(tmpPath, finalPath);
    return ChunkResult::COMPLETE;
}

int ChunkedStore::load(const char *id, uint8_t *buf, size_t bufLen)
{
    char path[48];
    blobPath(id, path, sizeof(path));

    spiLock->lock();
    File f = FSCom.open(path, FILE_O_READ);
    if (!f) {
        spiLock->unlock();
        return -1;
    }
    size_t n = f.read(buf, bufLen);
    f.close();
    spiLock->unlock();
    return (int)n;
}

bool ChunkedStore::remove(const char *id)
{
    char path[48];
    blobPath(id, path, sizeof(path));

    spiLock->lock();
    bool ok = FSCom.remove(path);
    spiLock->unlock();
    return ok;
}

std::vector<BlobInfo> ChunkedStore::list(size_t maxCount)
{
    std::vector<BlobInfo> out;

    spiLock->lock();
    FSCom.mkdir(root);
    auto files = getFiles(root, 1, maxCount); // getFiles requires the caller to hold spiLock
    spiLock->unlock();

    for (auto &f : files) {
        const char *base = strrchr(f.file_name, '/');
        base = base ? base + 1 : f.file_name;
        if (base[0] == '.') {
            continue; // skip in-progress .tmp uploads
        }
        BlobInfo info{};
        strncpy(info.name, base, sizeof(info.name) - 1);
        info.sizeBytes = f.size_bytes;
        out.push_back(info);
    }
    return out;
}

} // namespace fieldcontrol
