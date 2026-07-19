#include "fieldcontrol/ScriptStore.h"
#include "FSCommon.h"
#include "SPILock.h"
#include <ErriezCRC32.h>
#include <cstdio>
#include <cstring>

namespace fieldcontrol
{

namespace
{
char sUploadId[17] = {0};
uint32_t sExpectedChunk = 0;
uint32_t sTotalChunks = 0;
size_t sUploadedBytes = 0;

void scriptPath(const char *id, char *out, size_t outLen)
{
    snprintf(out, outLen, "/scripts/%s", id);
}

void scriptTmpPath(const char *id, char *out, size_t outLen)
{
    snprintf(out, outLen, "/scripts/.%s.tmp", id);
}
} // namespace

ChunkResult ScriptStore::putChunk(const char *scriptId, uint32_t chunkIndex, uint32_t totalChunks, const uint8_t *data,
                                   size_t len, uint32_t crc32OnFinal)
{
    if (!scriptId || !scriptId[0] || totalChunks == 0 || chunkIndex >= totalChunks) {
        return ChunkResult::ERROR;
    }

    char tmpPath[48];
    scriptTmpPath(scriptId, tmpPath, sizeof(tmpPath));

    spiLock->lock();
    FSCom.mkdir("/scripts");

    if (chunkIndex == 0) {
        // (Re)start a fresh upload, abandoning any previous incomplete one.
        strncpy(sUploadId, scriptId, sizeof(sUploadId) - 1);
        sUploadId[sizeof(sUploadId) - 1] = '\0';
        sExpectedChunk = 0;
        sTotalChunks = totalChunks;
        sUploadedBytes = 0;
        FSCom.remove(tmpPath);
    }

    if (strncmp(sUploadId, scriptId, sizeof(sUploadId)) != 0 || chunkIndex != sExpectedChunk || sTotalChunks != totalChunks ||
        sUploadedBytes + len > ScriptStore::MAX_SCRIPT_SIZE) {
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
    sUploadedBytes += len;
    sExpectedChunk++;

    bool isFinal = (chunkIndex + 1 == totalChunks);
    if (!isFinal) {
        spiLock->unlock();
        return ChunkResult::OK;
    }

    // Final chunk: verify CRC32 of the whole reassembled blob before making it executable.
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
    scriptPath(scriptId, finalPath, sizeof(finalPath));
    FSCom.remove(finalPath); // clear any previous version of this script
    spiLock->unlock();

    // renameFile takes the SPI lock itself - must not be called while we hold it.
    renameFile(tmpPath, finalPath);
    return ChunkResult::COMPLETE;
}

int ScriptStore::load(const char *scriptId, uint8_t *buf, size_t bufLen)
{
    char path[48];
    scriptPath(scriptId, path, sizeof(path));

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

bool ScriptStore::remove(const char *scriptId)
{
    char path[48];
    scriptPath(scriptId, path, sizeof(path));

    spiLock->lock();
    bool ok = FSCom.remove(path);
    spiLock->unlock();
    return ok;
}

std::vector<ScriptInfo> ScriptStore::list(size_t maxCount)
{
    std::vector<ScriptInfo> out;

    spiLock->lock();
    FSCom.mkdir("/scripts");
    auto files = getFiles("/scripts", 1, maxCount); // getFiles requires the caller to hold spiLock
    spiLock->unlock();

    for (auto &f : files) {
        const char *base = strrchr(f.file_name, '/');
        base = base ? base + 1 : f.file_name;
        if (base[0] == '.') {
            continue; // skip in-progress .tmp uploads
        }
        ScriptInfo info{};
        strncpy(info.name, base, sizeof(info.name) - 1);
        info.sizeBytes = f.size_bytes;
        out.push_back(info);
    }
    return out;
}

} // namespace fieldcontrol
