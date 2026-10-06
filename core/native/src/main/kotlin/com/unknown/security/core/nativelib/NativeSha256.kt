package com.unknown.security.core.nativelib

/**
 * Streaming SHA-256 over native code, useful for hashing large APK files
 * chunk by chunk without keeping the digest state in the Kotlin heap.
 *
 * One-shot hashing of small buffers is available through [of].
 *
 * Instances are single-use: [finish] returns the lowercase hex digest and
 * releases the native state.
 */
class NativeSha256 private constructor(
    private var handle: Long,
) : AutoCloseable {
    /** Feeds one chunk into the digest. */
    fun update(data: ByteArray) {
        check(handle != CLOSED_HANDLE) { "NativeSha256 is finished or closed" }
        NativeEngine.nativeHashUpdate(handle, data)
    }

    /** Returns the lowercase hex digest and releases native state. */
    fun finish(): String {
        check(handle != CLOSED_HANDLE) { "NativeSha256 is finished or closed" }
        val toFinish = handle
        handle = CLOSED_HANDLE
        return NativeEngine.nativeHashFinish(toFinish)
    }

    override fun close() {
        if (handle != CLOSED_HANDLE) {
            val toRelease = handle
            handle = CLOSED_HANDLE
            // There is no separate destroy entry point for hash handles;
            // finishing consumes the native state.
            NativeEngine.nativeHashFinish(toRelease)
        }
    }

    companion object {
        private const val CLOSED_HANDLE = 0L

        /** Starts a new streaming digest; `null` when native code is unavailable. */
        fun create(): NativeSha256? {
            if (!NativeEngine.available) {
                return null
            }
            val handle = NativeEngine.nativeHashCreate()
            return if (handle != CLOSED_HANDLE) NativeSha256(handle) else null
        }

        /** One-shot digest; `null` when native code is unavailable. */
        fun of(data: ByteArray): String? {
            if (!NativeEngine.available) {
                return null
            }
            return NativeEngine.nativeSha256Hex(data)
        }
    }
}
