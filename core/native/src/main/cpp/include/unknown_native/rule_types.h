#pragma once

#include <cstdint>

namespace unknown::native {

/** Detection rule kinds — one per DetectionRule subclass in core/model. */
enum class RuleType : std::uint8_t {
    PackageName = 0,
    LabelKeyword = 1,
    PermissionCombo = 2,
    ApkHash = 3,
    TargetSdk = 4,
};

/** Threat severity — mirrors ThreatSeverity in core/model. */
enum class Severity : std::uint8_t {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
};

/** Scoring weights, identical to ThreatSeverity.score in core/model. */
inline constexpr int kSeverityScores[4] = {10, 25, 50, 100};

/** Verdict levels — mirrors VerdictLevel in core/model. */
enum class VerdictLevel : std::uint8_t {
    Clean = 0,
    Suspicious = 1,
    Dangerous = 2,
};

}  // namespace unknown::native
