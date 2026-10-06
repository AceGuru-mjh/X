package com.unknown.security.core.nativelib

import com.unknown.security.core.model.DetectionRule
import com.unknown.security.core.model.PackageSnapshot
import com.unknown.security.core.model.ThreatSeverity
import com.unknown.security.core.model.VerdictLevel

/**
 * Encodes rules and snapshots into the compact line protocol consumed by the
 * native core (full specification in docs/NATIVE_ENGINE.md):
 *
 *  - fields of one record are separated by `\u001F`
 *  - lists inside a field are separated by `\u001E`
 *  - rules are separated by `\n`
 *
 * Encoding is pure string assembly with no reflection; decoding validates
 * every native answer before it re-enters the type system.
 */
internal object NativeRuleCodec {
    private const val FIELD_SEPARATOR = "\u001F"
    private const val LIST_SEPARATOR = "\u001E"

    /** Free-text fields must never smuggle protocol control characters. */
    private val forbiddenChars = charArrayOf(FIELD_SEPARATOR[0], LIST_SEPARATOR[0], '\n', '\r')

    fun encodeRules(rules: List<DetectionRule>): String = rules.joinToString(separator = "\n") { it.toProtocolLine() }

    fun encodeSnapshot(snapshot: PackageSnapshot): String =
        buildString {
            append(snapshot.packageName)
            append(FIELD_SEPARATOR)
            append(sanitize(snapshot.label))
            append(FIELD_SEPARATOR)
            append(snapshot.targetSdk.toString())
            append(FIELD_SEPARATOR)
            append(
                snapshot.permissions.joinToString(LIST_SEPARATOR) { sanitize(it) },
            )
            append(FIELD_SEPARATOR)
            append(snapshot.sha256.orEmpty().lowercase())
        }

    fun decodeVerdict(result: Array<String>): NativeVerdict {
        require(result.isNotEmpty()) { "native verdict is empty" }
        val header = result[0].split(FIELD_SEPARATOR)
        require(header.size == 3) { "malformed verdict header: ${result[0]}" }
        val level =
            when (header[0]) {
                "0" -> VerdictLevel.CLEAN
                "1" -> VerdictLevel.SUSPICIOUS
                "2" -> VerdictLevel.DANGEROUS
                else -> throw IllegalArgumentException("unknown verdict level code: ${header[0]}")
            }
        val score = header[1].toIntOrNull() ?: throw IllegalArgumentException("verdict score is not a number: ${header[1]}")
        val count = header[2].toIntOrNull() ?: throw IllegalArgumentException("verdict count is not a number: ${header[2]}")
        require(result.size == count + 1) { "verdict declares $count matches but carries ${result.size - 1}" }
        val matched =
            result.drop(1).map { raw ->
                val parts = raw.split(FIELD_SEPARATOR)
                require(parts.size == 4) { "malformed match entry: $raw" }
                NativeMatchedRule(
                    ruleId = parts[0],
                    ruleName = parts[1],
                    severity =
                        when (parts[2]) {
                            "0" -> ThreatSeverity.LOW
                            "1" -> ThreatSeverity.MEDIUM
                            "2" -> ThreatSeverity.HIGH
                            "3" -> ThreatSeverity.CRITICAL
                            else -> throw IllegalArgumentException("unknown severity code: ${parts[2]}")
                        },
                    detail = parts[3],
                )
            }
        return NativeVerdict(
            level = level,
            score = score,
            matchedRules = matched,
        )
    }

    private fun DetectionRule.toProtocolLine(): String {
        val head =
            listOf(
                typeCode(),
                sanitize(id),
                sanitize(name),
                severity.code(),
            )
        val fields =
            when (this) {
                is DetectionRule.PackageNameRule -> {
                    listOf(pattern, if (isRegex) "1" else "0")
                }

                is DetectionRule.LabelKeywordRule -> {
                    listOf(keywords.filter { it.isNotEmpty() }.joinToString(LIST_SEPARATOR))
                }

                is DetectionRule.PermissionComboRule -> {
                    listOf(
                        required.filter { it.isNotEmpty() }.joinToString(LIST_SEPARATOR),
                        anyOf.filter { it.isNotEmpty() }.joinToString(LIST_SEPARATOR),
                        anyOfCount.toString(),
                    )
                }

                is DetectionRule.ApkHashRule -> {
                    listOf(sha256.lowercase())
                }

                is DetectionRule.TargetSdkRule -> {
                    listOf(
                        maxTargetSdk.toString(),
                        if (requireDangerousPermissions) "1" else "0",
                    )
                }
            }
        return (head + fields).joinToString(FIELD_SEPARATOR)
    }

    private fun DetectionRule.typeCode(): String =
        when (this) {
            is DetectionRule.PackageNameRule -> "P"
            is DetectionRule.LabelKeywordRule -> "K"
            is DetectionRule.PermissionComboRule -> "C"
            is DetectionRule.ApkHashRule -> "H"
            is DetectionRule.TargetSdkRule -> "T"
        }

    private fun ThreatSeverity.code(): String =
        when (this) {
            ThreatSeverity.LOW -> "0"
            ThreatSeverity.MEDIUM -> "1"
            ThreatSeverity.HIGH -> "2"
            ThreatSeverity.CRITICAL -> "3"
        }

    private fun sanitize(text: String): String {
        var needsSanitizing = false
        for (char in text) {
            if (char in forbiddenChars) {
                needsSanitizing = true
                break
            }
        }
        if (!needsSanitizing) {
            return text
        }
        return text.map { if (it in forbiddenChars) ' ' else it }.joinToString("")
    }
}
