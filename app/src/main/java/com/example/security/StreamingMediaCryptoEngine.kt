package com.example.security

import android.media.MediaDataSource
import java.io.ByteArrayOutputStream
import java.io.EOFException
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Arrays
import javax.crypto.AEADBadTagException

/**
 * Streaming chunked authenticated encryption engine (`PVM1`) and zero-disk-plaintext
 * `MediaDataSource` for the PRIVATE VAULT Photo & Video Vault (Task 1).
 *
 * Binary Format (`PVM1`):
 * - Header (32 bytes):
 *   - `[0..3]`   4B Magic `"PVM1"`
 *   - `[4..5]`   2B Format Version (`1`)
 *   - `[6..7]`   2B Flags (`0`)
 *   - `[8..11]`  4B Nominal Plaintext Chunk Size (`262144` = 256 KiB)
 *   - `[12..15]` 4B Total Chunk Count `N` (`>= 1`)
 *   - `[16..23]` 8B Total Original Plaintext Bytes (`>= 1`)
 *   - `[24..31]` 8B Reserved (`0L`)
 * - Chunk Frame `i` (`0 <= i < N`):
 *   - `4B` Plaintext Chunk Length `L` (`1 <= L <= 262144`; for `0 <= i < N - 1`, `L == 262144`)
 *   - `12B` Chunk Nonce (CSPRNG 96-bit IV)
 *   - `L + 16B` AES-256-GCM Ciphertext + 128-bit Authentication Tag bound to:
 *     `AAD = "PVM1-CHK|mediaId=$mediaId|slot=$vaultSlot|ver=1|idx=$i|total=$N|last=${i == N - 1}|len=$L|totalPlain=$totalPlaintextBytes"`
 *
 * Security Guarantees:
 * - Constant-memory streaming: Large videos never load into RAM at once.
 * - Full-stream every-chunk verification (Correction 1): `verifyEncryptedMediaFileEveryChunk`
 *   decrypts and verifies the AES-256-GCM authentication tag of EVERY chunk `0 .. N-1` before
 *   any imported file can be marked `COMMITTED`.
 * - Anti-reordering, anti-omission, anti-truncation: Every chunk's index `i`, total chunk count `N`,
 *   `isLast` flag, chunk length `L`, and total file size are cryptographically bound in its AAD.
 * - Zero temporary plaintext files on disk: Video playback uses `EncryptedChunkMediaDataSource`
 *   with an in-memory 2-chunk (`512 KiB`) ring buffer that is zeroed on `close()`.
 */
object StreamingMediaCryptoEngine {

    private val PVM1_MAGIC = "PVM1".toByteArray(StandardCharsets.US_ASCII)
    const val FORMAT_VERSION_V1: Int = 1
    const val HEADER_BYTES: Int = 32
    const val CHUNK_PLAIN_BYTES: Int = 256 * 1024 // 256 KiB per chunk
    const val CHUNK_FRAME_OVERHEAD_BYTES: Int = 4 + CryptoEngine.NONCE_BYTES + CryptoEngine.GCM_TAG_BYTES // 32 bytes
    const val FULL_CHUNK_FRAME_BYTES: Int = CHUNK_PLAIN_BYTES + CHUNK_FRAME_OVERHEAD_BYTES // 262,176 bytes

    data class ParsedMediaHeader(
        val formatVersion: Int,
        val flags: Int,
        val nominalChunkPlainBytes: Int,
        val totalChunks: Int,
        val totalPlaintextBytes: Long
    )

    data class EncryptedMediaVerifyReport(
        val header: ParsedMediaHeader,
        val encryptedFileBytes: Long,
        val ciphertextSha256Hex: String
    )

    fun buildChunkAad(
        mediaId: String,
        vaultSlot: Int,
        formatVersion: Int,
        chunkIndex: Int,
        totalChunks: Int,
        isLastChunk: Boolean,
        chunkPlainLength: Int,
        totalPlaintextBytes: Long
    ): ByteArray {
        val aad = "PVM1-CHK|mediaId=$mediaId|slot=$vaultSlot|ver=$formatVersion|idx=$chunkIndex|total=$totalChunks|last=$isLastChunk|len=$chunkPlainLength|totalPlain=$totalPlaintextBytes"
        return aad.toByteArray(StandardCharsets.UTF_8)
    }

    fun buildThumbnailAad(
        mediaId: String,
        vaultSlot: Int,
        formatVersion: Int = FORMAT_VERSION_V1
    ): ByteArray {
        val aad = "PVT1|mediaId=$mediaId|slot=$vaultSlot|ver=$formatVersion"
        return aad.toByteArray(StandardCharsets.UTF_8)
    }

    /**
     * Streams plaintext from `inputStream` in 256 KiB chunks, encrypts each chunk with a fresh
     * 12-byte CSPRNG nonce under `fileMediaKey`, writes `<targetFile>`, and then updates the
     * 32-byte header with the exact `totalChunks` and `totalPlaintextBytes`.
     *
     * Wait: Because `totalChunks` and `totalPlaintextBytes` are bound in each chunk's AAD to
     * prevent truncation even if the header is tampered with, if `knownPlaintextSize` is not
     * known upfront or could differ from the stream, we first determine the exact stream length
     * or write using the exact `expectedPlaintextSize` verified at EOF.
     */
    @Throws(IOException::class, IllegalArgumentException::class)
    fun encryptStreamToMediaFile(
        inputStream: InputStream,
        expectedPlaintextSize: Long,
        targetFile: File,
        mediaId: String,
        vaultSlot: Int,
        fileMediaKey: ByteArray,
        onProgress: (bytesProcessed: Long, totalBytes: Long) -> Unit = { _, _ -> }
    ): ParsedMediaHeader {
        require(fileMediaKey.size == CryptoEngine.DEK_BYTES) { "Media key must be 32 bytes." }
        require(expectedPlaintextSize > 0L) { "Cannot import an empty (0-byte) media file." }

        val totalChunksLong = (expectedPlaintextSize + CHUNK_PLAIN_BYTES - 1L) / CHUNK_PLAIN_BYTES.toLong()
        require(totalChunksLong in 1L..Int.MAX_VALUE.toLong()) { "Invalid chunk count." }
        val totalChunks = totalChunksLong.toInt()

        val headerBytes = ByteArray(HEADER_BYTES)
        ByteBuffer.wrap(headerBytes).apply {
            put(PVM1_MAGIC)
            putShort(FORMAT_VERSION_V1.toShort())
            putShort(0.toShort())
            putInt(CHUNK_PLAIN_BYTES)
            putInt(totalChunks)
            putLong(expectedPlaintextSize)
            putLong(0L)
        }

        val readBuffer = ByteArray(CHUNK_PLAIN_BYTES)
        var totalPlainRead = 0L
        var chunkIndex = 0

        try {
            FileOutputStream(targetFile).use { fos ->
                fos.write(headerBytes)

                while (true) {
                    val bytesRead = readChunkFullyOrUntilEof(inputStream, readBuffer)
                    if (bytesRead <= 0) break

                    if (chunkIndex >= totalChunks) {
                        throw IllegalArgumentException("Source stream exceeded expected media byte length.")
                    }
                    totalPlainRead += bytesRead.toLong()
                    val isLast = (chunkIndex == totalChunks - 1)
                    if (!isLast && bytesRead != CHUNK_PLAIN_BYTES) {
                        throw IllegalArgumentException("Non-final media chunk had unexpected length ($bytesRead).")
                    }

                    val plainChunkSlice = if (bytesRead == readBuffer.size) {
                        readBuffer
                    } else {
                        readBuffer.copyOf(bytesRead)
                    }

                    val nonce = CryptoEngine.generateNonce()
                    val aad = buildChunkAad(
                        mediaId = mediaId,
                        vaultSlot = vaultSlot,
                        formatVersion = FORMAT_VERSION_V1,
                        chunkIndex = chunkIndex,
                        totalChunks = totalChunks,
                        isLastChunk = isLast,
                        chunkPlainLength = bytesRead,
                        totalPlaintextBytes = expectedPlaintextSize
                    )

                    val ciphertext = try {
                        CryptoEngine.encryptAesGcm(
                            keyBytes = fileMediaKey,
                            nonce = nonce,
                            plaintext = plainChunkSlice,
                            aad = aad
                        )
                    } finally {
                        if (plainChunkSlice !== readBuffer) {
                            Arrays.fill(plainChunkSlice, 0.toByte())
                        }
                    }

                    val frameHeader = ByteBuffer.allocate(4 + CryptoEngine.NONCE_BYTES)
                        .putInt(bytesRead)
                        .put(nonce)
                        .array()
                    fos.write(frameHeader)
                    fos.write(ciphertext)

                    chunkIndex++
                    onProgress(totalPlainRead, expectedPlaintextSize)
                }
                fos.flush()
                try {
                    fos.fd.sync()
                } catch (_: Throwable) {
                }
            }

            if (chunkIndex != totalChunks || totalPlainRead != expectedPlaintextSize) {
                throw IllegalArgumentException(
                    "Media stream length mismatch (expected $expectedPlaintextSize bytes across $totalChunks chunks, read $totalPlainRead bytes)."
                )
            }

            return ParsedMediaHeader(
                formatVersion = FORMAT_VERSION_V1,
                flags = 0,
                nominalChunkPlainBytes = CHUNK_PLAIN_BYTES,
                totalChunks = totalChunks,
                totalPlaintextBytes = expectedPlaintextSize
            )
        } finally {
            Arrays.fill(readBuffer, 0.toByte())
        }
    }

    /**
     * Correction 1: Mandatory full-stream verification pass.
     * Reads `encryptedFile` from offset 0 to EOF, validates the 32-byte `PVM1` header,
     * decrypts and verifies the AES-256-GCM tag and index-bound `AAD` of EVERY chunk `0 .. N-1`,
     * confirms exact chunk count and total plaintext byte count, confirms zero trailing bytes,
     * and returns the full-file SHA-256 hex digest of the encrypted file.
     */
    @Throws(IOException::class, AEADBadTagException::class, IllegalArgumentException::class)
    fun verifyEncryptedMediaFileEveryChunk(
        encryptedFile: File,
        mediaId: String,
        vaultSlot: Int,
        fileMediaKey: ByteArray,
        onVerifyProgress: (chunkIndex: Int, totalChunks: Int) -> Unit = { _, _ -> }
    ): EncryptedMediaVerifyReport {
        require(fileMediaKey.size == CryptoEngine.DEK_BYTES) { "Media key must be 32 bytes." }
        if (!encryptedFile.exists() || !encryptedFile.isFile) {
            throw IllegalArgumentException("Encrypted media file is missing.")
        }

        val sha256 = MessageDigest.getInstance("SHA-256")
        FileInputStream(encryptedFile).use { fis ->
            val headerBytes = ByteArray(HEADER_BYTES)
            readExactBytes(fis, headerBytes, 0, HEADER_BYTES)
            sha256.update(headerBytes)

            val header = parseAndValidateHeader(headerBytes)
            var verifiedPlainBytes = 0L
            val frameHeaderBuf = ByteArray(4 + CryptoEngine.NONCE_BYTES)

            for (chunkIndex in 0 until header.totalChunks) {
                readExactBytes(fis, frameHeaderBuf, 0, frameHeaderBuf.size)
                sha256.update(frameHeaderBuf)

                val fb = ByteBuffer.wrap(frameHeaderBuf)
                val plainLen = fb.int
                val isLast = (chunkIndex == header.totalChunks - 1)
                if (plainLen <= 0 || plainLen > header.nominalChunkPlainBytes) {
                    throw IllegalArgumentException("Invalid chunk length $plainLen at chunk $chunkIndex.")
                }
                if (!isLast && plainLen != header.nominalChunkPlainBytes) {
                    throw IllegalArgumentException("Non-final chunk $chunkIndex is shorter than nominal chunk size.")
                }

                val nonce = ByteArray(CryptoEngine.NONCE_BYTES)
                fb.get(nonce)

                val cipherLen = plainLen + CryptoEngine.GCM_TAG_BYTES
                val cipherBytes = ByteArray(cipherLen)
                readExactBytes(fis, cipherBytes, 0, cipherLen)
                sha256.update(cipherBytes)

                val aad = buildChunkAad(
                    mediaId = mediaId,
                    vaultSlot = vaultSlot,
                    formatVersion = header.formatVersion,
                    chunkIndex = chunkIndex,
                    totalChunks = header.totalChunks,
                    isLastChunk = isLast,
                    chunkPlainLength = plainLen,
                    totalPlaintextBytes = header.totalPlaintextBytes
                )

                val decryptedChunk = CryptoEngine.decryptAesGcm(
                    keyBytes = fileMediaKey,
                    nonce = nonce,
                    ciphertext = cipherBytes,
                    aad = aad
                )
                try {
                    if (decryptedChunk.size != plainLen) {
                        throw IllegalArgumentException("Authenticated chunk length mismatch at chunk $chunkIndex.")
                    }
                    verifiedPlainBytes += decryptedChunk.size.toLong()
                } finally {
                    Arrays.fill(decryptedChunk, 0.toByte())
                }

                onVerifyProgress(chunkIndex + 1, header.totalChunks)
            }

            // Ensure no trailing unauthenticated bytes exist after chunk N-1
            val extraByte = fis.read()
            if (extraByte != -1) {
                throw IllegalArgumentException("Encrypted media file contains unexpected trailing bytes after final chunk.")
            }

            if (verifiedPlainBytes != header.totalPlaintextBytes) {
                throw IllegalArgumentException(
                    "Verified plaintext byte total ($verifiedPlainBytes) does not match header (${header.totalPlaintextBytes})."
                )
            }

            val digestHex = sha256.digest().joinToString("") { "%02x".format(it) }
            return EncryptedMediaVerifyReport(
                header = header,
                encryptedFileBytes = encryptedFile.length(),
                ciphertextSha256Hex = digestHex
            )
        }
    }

    /**
     * Decrypts all chunks of a verified photo (or small media item) into a plaintext byte array in RAM.
     * Enforces a maximum in-memory allocation bound (`maxInMemoryBytes`, default 32 MiB) so large
     * videos are never loaded into a single byte array.
     */
    @Throws(IOException::class, AEADBadTagException::class, IllegalArgumentException::class)
    fun decryptMediaFileToMemoryBytes(
        encryptedFile: File,
        mediaId: String,
        vaultSlot: Int,
        fileMediaKey: ByteArray,
        maxInMemoryBytes: Long = 32L * 1024L * 1024L
    ): ByteArray {
        require(fileMediaKey.size == CryptoEngine.DEK_BYTES) { "Media key must be 32 bytes." }
        FileInputStream(encryptedFile).use { fis ->
            val headerBytes = ByteArray(HEADER_BYTES)
            readExactBytes(fis, headerBytes, 0, HEADER_BYTES)
            val header = parseAndValidateHeader(headerBytes)
            require(header.totalPlaintextBytes <= maxInMemoryBytes) {
                "Media file exceeds maximum in-memory decode size ($maxInMemoryBytes bytes)."
            }

            val out = ByteArrayOutputStream(header.totalPlaintextBytes.toInt())
            val frameHeaderBuf = ByteArray(4 + CryptoEngine.NONCE_BYTES)

            for (chunkIndex in 0 until header.totalChunks) {
                readExactBytes(fis, frameHeaderBuf, 0, frameHeaderBuf.size)
                val fb = ByteBuffer.wrap(frameHeaderBuf)
                val plainLen = fb.int
                val isLast = (chunkIndex == header.totalChunks - 1)
                if (plainLen <= 0 || plainLen > header.nominalChunkPlainBytes) {
                    throw IllegalArgumentException("Invalid chunk length at chunk $chunkIndex.")
                }
                if (!isLast && plainLen != header.nominalChunkPlainBytes) {
                    throw IllegalArgumentException("Non-final chunk $chunkIndex length mismatch.")
                }

                val nonce = ByteArray(CryptoEngine.NONCE_BYTES)
                fb.get(nonce)
                val cipherBytes = ByteArray(plainLen + CryptoEngine.GCM_TAG_BYTES)
                readExactBytes(fis, cipherBytes, 0, cipherBytes.size)

                val aad = buildChunkAad(
                    mediaId = mediaId,
                    vaultSlot = vaultSlot,
                    formatVersion = header.formatVersion,
                    chunkIndex = chunkIndex,
                    totalChunks = header.totalChunks,
                    isLastChunk = isLast,
                    chunkPlainLength = plainLen,
                    totalPlaintextBytes = header.totalPlaintextBytes
                )

                val plainChunk = CryptoEngine.decryptAesGcm(
                    keyBytes = fileMediaKey,
                    nonce = nonce,
                    ciphertext = cipherBytes,
                    aad = aad
                )
                try {
                    out.write(plainChunk)
                } finally {
                    Arrays.fill(plainChunk, 0.toByte())
                }
            }

            if (fis.read() != -1) {
                throw IllegalArgumentException("Unexpected trailing bytes after final chunk.")
            }

            val result = out.toByteArray()
            if (result.size.toLong() != header.totalPlaintextBytes) {
                Arrays.fill(result, 0.toByte())
                throw IllegalArgumentException("Decrypted byte count mismatch.")
            }
            return result
        }
    }

    /**
     * Encrypts a thumbnail byte array (`PVT1`) with a 12-byte CSPRNG nonce and writes to `targetFile`.
     */
    @Throws(IOException::class)
    fun encryptThumbnailToFile(
        plaintextThumbBytes: ByteArray,
        targetFile: File,
        mediaId: String,
        vaultSlot: Int,
        thumbnailKey: ByteArray
    ) {
        require(thumbnailKey.size == CryptoEngine.DEK_BYTES) { "Thumbnail key must be 32 bytes." }
        val nonce = CryptoEngine.generateNonce()
        val aad = buildThumbnailAad(mediaId, vaultSlot, FORMAT_VERSION_V1)
        val ciphertext = CryptoEngine.encryptAesGcm(
            keyBytes = thumbnailKey,
            nonce = nonce,
            plaintext = plaintextThumbBytes,
            aad = aad
        )
        FileOutputStream(targetFile).use { fos ->
            fos.write(nonce)
            fos.write(ciphertext)
            fos.flush()
        }
    }

    /**
     * Decrypts and authenticates an encrypted thumbnail file (`PVT1`) into RAM.
     */
    @Throws(IOException::class, AEADBadTagException::class, IllegalArgumentException::class)
    fun decryptThumbnailFromFile(
        encryptedThumbFile: File,
        mediaId: String,
        vaultSlot: Int,
        thumbnailKey: ByteArray
    ): ByteArray {
        require(thumbnailKey.size == CryptoEngine.DEK_BYTES) { "Thumbnail key must be 32 bytes." }
        val raw = encryptedThumbFile.readBytes()
        require(raw.size > CryptoEngine.NONCE_BYTES + CryptoEngine.GCM_TAG_BYTES) {
            "Truncated encrypted thumbnail file."
        }
        val nonce = raw.copyOfRange(0, CryptoEngine.NONCE_BYTES)
        val ciphertext = raw.copyOfRange(CryptoEngine.NONCE_BYTES, raw.size)
        val aad = buildThumbnailAad(mediaId, vaultSlot, FORMAT_VERSION_V1)
        return CryptoEngine.decryptAesGcm(
            keyBytes = thumbnailKey,
            nonce = nonce,
            ciphertext = ciphertext,
            aad = aad
        )
    }

    fun sha256Hex(bytes: ByteArray): String =
        MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }

    fun parseAndValidateHeader(headerBytes: ByteArray): ParsedMediaHeader {
        require(headerBytes.size == HEADER_BYTES) { "Invalid PVM1 header length." }
        val buf = ByteBuffer.wrap(headerBytes)
        val magic = ByteArray(4)
        buf.get(magic)
        require(magic.contentEquals(PVM1_MAGIC)) { "Invalid PVM1 file magic." }

        val version = buf.short.toInt()
        require(version == FORMAT_VERSION_V1) { "Unsupported PVM1 format version: $version" }

        val flags = buf.short.toInt()
        require(flags == 0) { "Unsupported PVM1 header flags: $flags" }

        val nominalChunkSize = buf.int
        require(nominalChunkSize == CHUNK_PLAIN_BYTES) {
            "Unexpected PVM1 chunk size: $nominalChunkSize"
        }

        val totalChunks = buf.int
        require(totalChunks >= 1) { "Invalid PVM1 totalChunks: $totalChunks" }

        val totalPlaintextBytes = buf.long
        require(totalPlaintextBytes >= 1L) { "Invalid PVM1 totalPlaintextBytes: $totalPlaintextBytes" }

        val reserved = buf.long
        require(reserved == 0L) { "Non-zero PVM1 reserved header field." }

        val expectedClubs = ((totalPlaintextBytes + nominalChunkSize - 1L) / nominalChunkSize.toLong()).toInt()
        require(totalChunks == expectedClubs) {
            "Header chunk count ($totalChunks) inconsistent with totalPlaintextBytes ($totalPlaintextBytes)."
        }

        return ParsedMediaHeader(
            formatVersion = version,
            flags = flags,
            nominalChunkPlainBytes = nominalChunkSize,
            totalChunks = totalChunks,
            totalPlaintextBytes = totalPlaintextBytes
        )
    }

    private fun readChunkFullyOrUntilEof(input: InputStream, buffer: ByteArray): Int {
        var total = 0
        while (total < buffer.size) {
            val read = input.read(buffer, total, buffer.size - total)
            if (read == -1) break
            total += read
        }
        return total
    }

    private fun readExactBytes(input: InputStream, buffer: ByteArray, offset: Int, length: Int) {
        var total = 0
        while (total < length) {
            val read = input.read(buffer, offset + total, length - total)
            if (read == -1) {
                throw EOFException("Unexpected EOF while reading PVM1 encrypted media stream.")
            }
            total += read
        }
    }

    /**
     * Zero-disk-plaintext `MediaDataSource` for Android `MediaPlayer` video playback (Task 1.C).
     *
     * - Seeks to any chunk in `O(1)` time (`32L + chunkIndex * 262_176L`).
     * - Authenticates the AES-256-GCM tag and index-bound `AAD` of each accessed chunk before
     *   copying bytes to `MediaPlayer`.
     * - Keeps at most 2 decrypted chunks (`512 KiB`) in RAM and zeroes all key and plaintext
     *   buffers immediately on `close()`.
     */
    class EncryptedChunkMediaDataSource(
        encryptedFile: File,
        private val mediaId: String,
        private val vaultSlot: Int,
        fileMediaKey: ByteArray
    ) : MediaDataSource() {

        private val lock = Any()
        private val keyCopy: ByteArray = fileMediaKey.copyOf()
        private val raf: RandomAccessFile = RandomAccessFile(encryptedFile, "r")
        private val header: ParsedMediaHeader

        @Volatile
        private var isClosed: Boolean = false

        private data class CachedChunk(
            val chunkIndex: Int,
            val plainBytes: ByteArray
        ) {
            fun wipe() {
                Arrays.fill(plainBytes, 0.toByte())
            }
        }

        // Bounded 2-chunk LRU in RAM (max 512 KiB)
        private val chunkCache = ArrayDeque<CachedChunk>(2)

        init {
            try {
                require(keyCopy.size == CryptoEngine.DEK_BYTES) { "Media key must be 32 bytes." }
                val headerBytes = ByteArray(HEADER_BYTES)
                raf.seek(0L)
                raf.readFully(headerBytes)
                header = parseAndValidateHeader(headerBytes)

                // Verify the physical file size matches the exact expected frame total before playback
                val lastChunkPlainLen = (header.totalPlaintextBytes - (header.totalChunks - 1).toLong() * CHUNK_PLAIN_BYTES.toLong()).toInt()
                val expectedFileSize = HEADER_BYTES.toLong() +
                    (header.totalChunks - 1).toLong() * FULL_CHUNK_FRAME_BYTES.toLong() +
                    (CHUNK_FRAME_OVERHEAD_BYTES + lastChunkPlainLen).toLong()
                if (raf.length() != expectedFileSize) {
                    throw IOException("Encrypted media file size mismatch (truncated or corrupted).")
                }
            } catch (t: Throwable) {
                Arrays.fill(keyCopy, 0.toByte())
                try {
                    raf.close()
                } catch (_: Throwable) {
                }
                throw t
            }
        }

        override fun getSize(): Long = synchronized(lock) {
            if (isClosed) return -1L
            header.totalPlaintextBytes
        }

        override fun readAt(position: Long, buffer: ByteArray, offset: Int, size: Int): Int = synchronized(lock) {
            if (isClosed) throw IOException("EncryptedChunkMediaDataSource is closed.")
            if (position < 0L) throw IllegalArgumentException("Negative read position.")
            if (size == 0) return 0
            if (position >= header.totalPlaintextBytes) return -1

            val maxReadable = (header.totalPlaintextBytes - position).coerceAtMost(size.toLong()).toInt()
            var totalCopied = 0
            var currentPos = position

            while (totalCopied < maxReadable) {
                val chunkIndex = (currentPos / CHUNK_PLAIN_BYTES.toLong()).toInt()
                val offsetInChunk = (currentPos % CHUNK_PLAIN_BYTES.toLong()).toInt()
                val plainChunk = getOrDecryptChunkLocked(chunkIndex)
                val availableInChunk = plainChunk.size - offsetInChunk
                if (availableInChunk <= 0) break

                val toCopy = minOf(availableInChunk, maxReadable - totalCopied)
                System.arraycopy(plainChunk, offsetInChunk, buffer, offset + totalCopied, toCopy)
                totalCopied += toCopy
                currentPos += toCopy.toLong()
            }

            return if (totalCopied == 0) -1 else totalCopied
        }

        private fun getOrDecryptChunkLocked(chunkIndex: Int): ByteArray {
            if (chunkIndex !in 0 until header.totalChunks) {
                throw IOException("Chunk index $chunkIndex out of bounds.")
            }
            val existingIdx = chunkCache.indexOfFirst { it.chunkIndex == chunkIndex }
            if (existingIdx >= 0) {
                val hit = chunkCache.removeAt(existingIdx)
                chunkCache.addLast(hit)
                return hit.plainBytes
            }

            val fileOffset = HEADER_BYTES.toLong() + chunkIndex.toLong() * FULL_CHUNK_FRAME_BYTES.toLong()
            raf.seek(fileOffset)
            val plainLen = raf.readInt()
            val isLast = (chunkIndex == header.totalChunks - 1)
            val expectedPlainLen = if (isLast) {
                (header.totalPlaintextBytes - (header.totalChunks - 1).toLong() * CHUNK_PLAIN_BYTES.toLong()).toInt()
            } else {
                CHUNK_PLAIN_BYTES
            }
            if (plainLen != expectedPlainLen) {
                throw IOException("Chunk $chunkIndex length header ($plainLen) does not match expected length ($expectedPlainLen).")
            }

            val nonce = ByteArray(CryptoEngine.NONCE_BYTES)
            raf.readFully(nonce)
            val cipherBytes = ByteArray(plainLen + CryptoEngine.GCM_TAG_BYTES)
            raf.readFully(cipherBytes)

            val aad = buildChunkAad(
                mediaId = mediaId,
                vaultSlot = vaultSlot,
                formatVersion = header.formatVersion,
                chunkIndex = chunkIndex,
                totalChunks = header.totalChunks,
                isLastChunk = isLast,
                chunkPlainLength = plainLen,
                totalPlaintextBytes = header.totalPlaintextBytes
            )

            val decrypted = try {
                CryptoEngine.decryptAesGcm(
                    keyBytes = keyCopy,
                    nonce = nonce,
                    ciphertext = cipherBytes,
                    aad = aad
                )
            } catch (e: AEADBadTagException) {
                throw IOException("AES-256-GCM authentication failed on video chunk $chunkIndex.", e)
            }

            if (chunkCache.size >= 2) {
                val evicted = chunkCache.removeFirst()
                evicted.wipe()
            }
            chunkCache.addLast(CachedChunk(chunkIndex, decrypted))
            return decrypted
        }

        override fun close() = synchronized(lock) {
            if (isClosed) return
            isClosed = true
            chunkCache.forEach { it.wipe() }
            chunkCache.clear()
            Arrays.fill(keyCopy, 0.toByte())
            try {
                raf.close()
            } catch (_: Throwable) {
            }
        }
    }
}
