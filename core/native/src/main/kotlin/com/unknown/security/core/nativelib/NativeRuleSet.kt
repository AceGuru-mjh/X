package com.unknown.security.core.nativelib

import com.unknown.security.core.model.DetectionRule
import com.unknown.security.core.model.PackageSnapshot

/**
 * A [DetectionRule] collection compiled into the native detection core.
 *
 * Compilation happens once — the C++ side builds an Aho-Corasick automaton
 * over every keyword, dense permission bitmaps, SHA-256 and exact package
 * tables and validates every regex. Each [evaluate] call afterwards walks
 * those indexes without touching managed memory on the hot path.
 *
 * Instances are safe for concurrent [evaluate] calls (each thread owns its
 * native scratch). Native memory is released by [close]; a closed set must
 * not be used again, and closing is expected to happen from one thread —
 * the usual [AutoCloseable] ownership discipline.
 *
 * @see NativeRuleCodec for the wire protocol between Kotlin and C++.
 */
class NativeRuleSet private constructor(
    @Volatile private var handle: Long,
) : AutoCloseable {
    /** Number of rules held by the compiled set, every severity included. */
    val ruleCount: Int
        get() {
            check(handle != CLOSED_HANDLE) { "NativeRuleSet is closed" }
            return NativeEngine.nativeRuleCount(handle)
        }

    /**
     * Evaluates [snapshot] against every rule and returns the verdict.
     *
     * @throws IllegalArgumentException when the snapshot cannot be encoded.
     * @throws IllegalStateException when this set is already closed.
     */
    fun evaluate(snapshot: PackageSnapshot): NativeVerdict {
        check(handle != CLOSED_HANDLE) { "NativeRuleSet is closed" }
        val blob = NativeRuleCodec.encodeSnapshot(snapshot)
        return NativeRuleCodec.decodeVerdict(NativeEngine.nativeEvaluate(handle, blob))
    }

    override fun close() {
        if (handle != CLOSED_HANDLE) {
            val toRelease = handle
            handle = CLOSED_HANDLE
            NativeEngine.nativeDestroy(toRelease)
        }
    }

    companion object {
        private const val CLOSED_HANDLE = 0L

        /**
         * Compiles [rules] into a native rule set.
         *
         * Pass the ENABLED rules only — disabled rules would be matched by
         * the native core all the same, so filter with `enabledRules` first.
         *
         * @return the compiled set, or `null` when the native core is not
         *   available on this device — callers should fall back to the pure
         *   Kotlin engine in that case.
         * @throws IllegalArgumentException when a rule cannot be compiled;
         *   the message identifies the offending rule.
         */
        fun compile(rules: List<DetectionRule>): NativeRuleSet? {
            if (!NativeEngine.available) {
                return null
            }
            val handle = NativeEngine.nativeCreate()
            try {
                NativeEngine.nativeCompile(handle, NativeRuleCodec.encodeRules(rules))
                return NativeRuleSet(handle)
            } catch (error: Throwable) {
                NativeEngine.nativeDestroy(handle)
                throw error
            }
        }
    }
}
