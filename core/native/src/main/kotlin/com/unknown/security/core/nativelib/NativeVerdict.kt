package com.unknown.security.core.nativelib

import com.unknown.security.core.model.MatchedRule
import com.unknown.security.core.model.ScanVerdict
import com.unknown.security.core.model.ThreatSeverity
import com.unknown.security.core.model.VerdictLevel

/** One native rule hit — mirrors [MatchedRule] from core/model. */
data class NativeMatchedRule(
    val ruleId: String,
    val ruleName: String,
    val severity: ThreatSeverity,
    val detail: String,
)

/** Result of a native evaluation — mirrors [ScanVerdict] from core/model. */
data class NativeVerdict(
    val level: VerdictLevel,
    val score: Int,
    val matchedRules: List<NativeMatchedRule> = emptyList(),
) {
    /** Bridges this verdict into the domain model used by the scan UI. */
    fun toScanVerdict(packageName: String): ScanVerdict =
        ScanVerdict(
            packageName = packageName,
            level = level,
            score = score,
            matchedRules =
                matchedRules.map { matched ->
                    MatchedRule(
                        ruleId = matched.ruleId,
                        ruleName = matched.ruleName,
                        severity = matched.severity,
                        detail = matched.detail,
                    )
                },
        )
}
