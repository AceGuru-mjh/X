package com.unknown.security.core.nativelib

/**
 * Direct JNI surface of libunknown_native.so.
 *
 * Everything below is an implementation detail of this module — higher-level
 * code should use [NativeRuleSet] instead. The library loads lazily so that
 * devices without a matching ABI degrade gracefully instead of crashing at
 * class-load time.
 */
internal object NativeEngine {
    /** True when libunknown_native.so loaded successfully. */
    val available: Boolean by lazy {
        try {
            System.loadLibrary("unknown_native")
            true
        } catch (error: LinkageError) {
            false
        }
    }

    external fun nativeVersion(): String

    external fun nativeCreate(): Long

    external fun nativeDestroy(handle: Long)

    external fun nativeCompile(
        handle: Long,
        rulesBlob: String,
    ): Boolean

    external fun nativeRuleCount(handle: Long): Int

    external fun nativeEvaluate(
        handle: Long,
        snapshotBlob: String,
    ): Array<String>

    external fun nativeSha256Hex(data: ByteArray): String

    external fun nativeHashCreate(): Long

    external fun nativeHashUpdate(
        handle: Long,
        data: ByteArray,
    )

    external fun nativeHashFinish(handle: Long): String
}
