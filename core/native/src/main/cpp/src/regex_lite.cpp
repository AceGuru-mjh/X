#include "unknown_native/regex_lite.h"

#include <array>
#include <utility>

namespace unknown::native {

namespace {

constexpr std::size_t kMaxPatternLength = 512;
constexpr std::size_t kMaxInstructions = 2048;
constexpr std::size_t kMaxClasses = 128;
constexpr int kMaxRepeatCount = 100;
constexpr std::uint32_t kMaxSteps = 100000;
constexpr std::uint32_t kMaxMatchDepth = 1024;

using ClassBitmap = std::vector<std::uint8_t>;

void addCharToBitmap(ClassBitmap& bitmap, char c) {
    const auto byte = static_cast<std::uint8_t>(c);
    bitmap[static_cast<std::size_t>(byte >> 3)] |= static_cast<std::uint8_t>(1u << (byte & 7));
}

void addRangeToBitmap(ClassBitmap& bitmap, char lo, char hi) {
    for (int v = static_cast<int>(static_cast<std::uint8_t>(lo)); v <= static_cast<int>(static_cast<std::uint8_t>(hi)); ++v) {
        const auto byte = static_cast<std::uint8_t>(v);
        bitmap[static_cast<std::size_t>(byte >> 3)] |= static_cast<std::uint8_t>(1u << (byte & 7));
    }
}

void invertBitmap(ClassBitmap& bitmap) {
    for (auto& byte : bitmap) {
        byte = static_cast<std::uint8_t>(~byte);
    }
}

ClassBitmap digitsBitmap() {
    ClassBitmap bitmap(32, 0);
    addRangeToBitmap(bitmap, '0', '9');
    return bitmap;
}

ClassBitmap wordBitmap() {
    ClassBitmap bitmap(32, 0);
    addRangeToBitmap(bitmap, '0', '9');
    addRangeToBitmap(bitmap, 'A', 'Z');
    addRangeToBitmap(bitmap, 'a', 'z');
    addCharToBitmap(bitmap, '_');
    return bitmap;
}

ClassBitmap spaceBitmap() {
    ClassBitmap bitmap(32, 0);
    addCharToBitmap(bitmap, ' ');
    addCharToBitmap(bitmap, '\t');
    addCharToBitmap(bitmap, '\n');
    addCharToBitmap(bitmap, '\r');
    addCharToBitmap(bitmap, '\f');
    addCharToBitmap(bitmap, '\v');
    return bitmap;
}

void mergeBitmap(ClassBitmap& into, const ClassBitmap& from) {
    for (std::size_t i = 0; i < into.size() && i < from.size(); ++i) {
        into[i] |= from[i];
    }
}

bool isDigitChar(char c) noexcept { return c >= '0' && c <= '9'; }

}  // namespace

bool RegexLite::compile(std::string_view pattern, RegexLite* out, std::string* error) {
    if (out == nullptr) {
        if (error != nullptr) {
            *error = "null output regex";
        }
        return false;
    }
    if (pattern.empty()) {
        if (error != nullptr) {
            *error = "empty pattern";
        }
        return false;
    }
    if (pattern.size() > kMaxPatternLength) {
        if (error != nullptr) {
            *error = "pattern longer than 512 bytes";
        }
        return false;
    }

    RegexLite scratch;

    // A local compiler with the same access rights as this member function.
    struct Compiler {
        RegexLite& re;
        std::string_view pat;
        std::size_t pos = 0;
        std::string error;

        bool bad() const { return !error.empty(); }

        bool fail(std::string message) {
            if (error.empty()) {
                error = std::move(message);
            }
            return false;
        }

        bool atEnd() const { return pos >= pat.size(); }

        char peek() const { return pat[pos]; }

        bool eat(char c) {
            if (!atEnd() && pat[pos] == c) {
                ++pos;
                return true;
            }
            return false;
        }

        std::int32_t emit(Op op, std::uint8_t ch = 0, std::uint32_t cls = 0, std::int32_t x = 0, std::int32_t y = 0) {
            if (re.prog_.size() >= kMaxInstructions) {
                fail("pattern too complex");
                return -1;
            }
            re.prog_.push_back(Inst{op, ch, cls, x, y});
            return static_cast<std::int32_t>(re.prog_.size()) - 1;
        }

        std::int32_t addClass(const ClassBitmap& bitmap) {
            if (re.classes_.size() >= kMaxClasses) {
                fail("too many character classes");
                return 0;
            }
            re.classes_.push_back(bitmap);
            return static_cast<std::int32_t>(re.classes_.size()) - 1;
        }

        bool parse() {
            if (!parseAlt()) {
                return false;
            }
            if (!atEnd()) {
                return fail("unmatched ')'");
            }
            emit(Op::Match);
            return !bad();
        }

        bool parseAlt() {
            const std::int32_t splitPos = emit(Op::Split);
            if (splitPos < 0) {
                return false;
            }
            if (!parseConcat()) {
                return false;
            }
            if (eat('|')) {
                const std::int32_t jmpPos = emit(Op::Jmp);
                if (jmpPos < 0) {
                    return false;
                }
                re.prog_[static_cast<std::size_t>(splitPos)].x = splitPos + 1;
                re.prog_[static_cast<std::size_t>(splitPos)].y = static_cast<std::int32_t>(re.prog_.size());
                if (!parseAlt()) {
                    return false;
                }
                const std::int32_t end = static_cast<std::int32_t>(re.prog_.size());
                re.prog_[static_cast<std::size_t>(jmpPos)].x = end;
            } else {
                // No alternation: the split becomes a no-op.
                re.prog_[static_cast<std::size_t>(splitPos)].x = splitPos + 1;
                re.prog_[static_cast<std::size_t>(splitPos)].y = splitPos + 1;
            }
            return true;
        }

        bool parseConcat() {
            while (!atEnd() && peek() != '|' && peek() != ')') {
                if (!parseRepeat()) {
                    return false;
                }
            }
            return true;
        }

        bool parseRepeat() {
            const std::int32_t splitPos = emit(Op::Split);
            if (splitPos < 0) {
                return false;
            }
            const std::size_t atomStart = re.prog_.size();
            if (!parseAtom()) {
                return false;
            }
            if (re.prog_.size() == atomStart) {
                // Nothing was emitted: reject a dangling quantifier.
                if (!atEnd()) {
                    const char c = peek();
                    if (c == '*' || c == '+' || c == '?' || c == '{') {
                        return fail("quantifier without preceding atom");
                    }
                }
                re.prog_[static_cast<std::size_t>(splitPos)].x = splitPos + 1;
                re.prog_[static_cast<std::size_t>(splitPos)].y = splitPos + 1;
                return true;
            }

            const auto makeTrivial = [&] {
                re.prog_[static_cast<std::size_t>(splitPos)].x = splitPos + 1;
                re.prog_[static_cast<std::size_t>(splitPos)].y = splitPos + 1;
            };

            if (atEnd()) {
                makeTrivial();
                return true;
            }
            const char c = peek();
            if (c == '*') {
                ++pos;
                re.prog_[static_cast<std::size_t>(splitPos)].x = static_cast<std::int32_t>(atomStart);
                emit(Op::Jmp, 0, 0, splitPos);
                re.prog_[static_cast<std::size_t>(splitPos)].y = static_cast<std::int32_t>(re.prog_.size());
                return !bad();
            }
            if (c == '+') {
                ++pos;
                makeTrivial();
                const std::int32_t loopSplit = emit(Op::Split, 0, 0, static_cast<std::int32_t>(atomStart));
                if (loopSplit < 0) {
                    return false;
                }
                re.prog_[static_cast<std::size_t>(loopSplit)].y = static_cast<std::int32_t>(re.prog_.size());
                return !bad();
            }
            if (c == '?') {
                ++pos;
                re.prog_[static_cast<std::size_t>(splitPos)].x = static_cast<std::int32_t>(atomStart);
                re.prog_[static_cast<std::size_t>(splitPos)].y = static_cast<std::int32_t>(re.prog_.size());
                return !bad();
            }
            if (c == '{') {
                int minCount = 0;
                int maxCount = 0;  // -1 = open ended
                if (!parseBounds(&minCount, &maxCount)) {
                    return false;
                }

                // Snapshot the atom so it can be duplicated or dropped.
                std::vector<Inst> atomCode(re.prog_.begin() + static_cast<std::ptrdiff_t>(atomStart), re.prog_.end());
                const auto emitCopies = [&](int times) {
                    for (int t = 0; t < times; ++t) {
                        const std::int32_t base = static_cast<std::int32_t>(re.prog_.size());
                        const std::int32_t delta = base - static_cast<std::int32_t>(atomStart);
                        for (Inst inst : atomCode) {
                            if (inst.op == Op::Split || inst.op == Op::Jmp) {
                                inst.x += delta;
                                if (inst.op == Op::Split) {
                                    inst.y += delta;
                                }
                            }
                            if (re.prog_.size() >= kMaxInstructions) {
                                fail("pattern too complex");
                                return;
                            }
                            re.prog_.push_back(inst);
                        }
                    }
                };

                if (minCount == 0) {
                    re.prog_.resize(atomStart);
                } else if (minCount > 1) {
                    emitCopies(minCount - 1);
                    if (bad()) {
                        return false;
                    }
                }

                if (maxCount < 0) {
                    // Open ended: star over one extra copy.
                    const std::int32_t loopSplit = emit(Op::Split);
                    if (loopSplit < 0) {
                        return false;
                    }
                    re.prog_[static_cast<std::size_t>(loopSplit)].x = loopSplit + 1;
                    emitCopies(1);
                    emit(Op::Jmp, 0, 0, loopSplit);
                    re.prog_[static_cast<std::size_t>(loopSplit)].y = static_cast<std::int32_t>(re.prog_.size());
                } else if (maxCount > minCount) {
                    std::vector<std::int32_t> optionalSplits;
                    for (int k = minCount; k < maxCount; ++k) {
                        const std::int32_t split = emit(Op::Split);
                        if (split < 0) {
                            return false;
                        }
                        re.prog_[static_cast<std::size_t>(split)].x = split + 1;
                        optionalSplits.push_back(split);
                        emitCopies(1);
                        if (bad()) {
                            return false;
                        }
                    }
                    const std::int32_t end = static_cast<std::int32_t>(re.prog_.size());
                    for (const std::int32_t split : optionalSplits) {
                        re.prog_[static_cast<std::size_t>(split)].y = end;
                    }
                }
                makeTrivial();
                return !bad();
            }

            makeTrivial();
            return true;
        }

        bool parseBounds(int* minCount, int* maxCount) {
            ++pos;  // '{'
            int lower = 0;
            if (!parseBoundNumber(&lower)) {
                return false;
            }
            if (eat('}')) {
                *minCount = lower;
                *maxCount = lower;
                return true;
            }
            if (!eat(',')) {
                return fail("expected ',' or '}' in repetition");
            }
            if (eat('}')) {
                *minCount = lower;
                *maxCount = -1;
                return true;
            }
            int upper = 0;
            if (!parseBoundNumber(&upper)) {
                return false;
            }
            if (!eat('}')) {
                return fail("expected '}' to close repetition");
            }
            if (upper < lower) {
                return fail("repetition upper bound below lower bound");
            }
            *minCount = lower;
            *maxCount = upper;
            return true;
        }

        bool parseBoundNumber(int* value) {
            if (atEnd() || !isDigitChar(peek())) {
                return fail("invalid repetition bound");
            }
            int v = 0;
            while (!atEnd() && isDigitChar(peek())) {
                v = v * 10 + (peek() - '0');
                ++pos;
                if (v > kMaxRepeatCount) {
                    return fail("repetition bound too large");
                }
            }
            *value = v;
            return true;
        }

        bool parseAtom() {
            if (atEnd()) {
                return true;  // empty atom
            }
            const char c = peek();
            switch (c) {
                case '(': {
                    ++pos;
                    if (!parseAlt()) {
                        return false;
                    }
                    if (!eat(')')) {
                        return fail("unclosed group");
                    }
                    return true;
                }
                case '[':
                    return parseClass();
                case '.':
                    ++pos;
                    emit(Op::Any);
                    return !bad();
                case '^':
                    ++pos;
                    emit(Op::AssertStart);
                    return !bad();
                case '$':
                    ++pos;
                    emit(Op::AssertEnd);
                    return !bad();
                case '\\':
                    return parseEscape();
                case '*':
                case '+':
                case '?':
                    return fail("nothing to repeat");
                case ']':
                    return fail("unexpected ']'");
                default:
                    // '{' at atom position is a literal brace; everything
                    // else is an ordinary literal character.
                    ++pos;
                    emit(Op::Char, static_cast<std::uint8_t>(c));
                    return !bad();
            }
        }

        bool parseEscape() {
            ++pos;  // backslash
            if (atEnd()) {
                return fail("trailing backslash");
            }
            const char c = peek();
            ++pos;
            switch (c) {
                case 'd':
                    emit(Op::Class, 0, static_cast<std::uint32_t>(addClass(digitsBitmap())));
                    return !bad();
                case 'D':
                    return emitNegatedClass(digitsBitmap());
                case 'w':
                    emit(Op::Class, 0, static_cast<std::uint32_t>(addClass(wordBitmap())));
                    return !bad();
                case 'W':
                    return emitNegatedClass(wordBitmap());
                case 's':
                    emit(Op::Class, 0, static_cast<std::uint32_t>(addClass(spaceBitmap())));
                    return !bad();
                case 'S':
                    return emitNegatedClass(spaceBitmap());
                case 't':
                    emit(Op::Char, static_cast<std::uint8_t>('\t'));
                    return !bad();
                case 'n':
                    emit(Op::Char, static_cast<std::uint8_t>('\n'));
                    return !bad();
                case 'r':
                    emit(Op::Char, static_cast<std::uint8_t>('\r'));
                    return !bad();
                case 'f':
                    emit(Op::Char, static_cast<std::uint8_t>('\f'));
                    return !bad();
                case 'v':
                    emit(Op::Char, static_cast<std::uint8_t>('\v'));
                    return !bad();
                default:
                    emit(Op::Char, static_cast<std::uint8_t>(c));
                    return !bad();
            }
        }

        bool emitNegatedClass(ClassBitmap bitmap) {
            invertBitmap(bitmap);
            emit(Op::Class, 0, static_cast<std::uint32_t>(addClass(bitmap)));
            return !bad();
        }

        bool parseClass() {
            ++pos;  // '['
            bool negate = false;
            if (eat('^')) {
                negate = true;
            }
            ClassBitmap bitmap(32, 0);
            bool any = false;

            while (true) {
                if (atEnd()) {
                    return fail("unclosed character class");
                }
                char c = peek();
                if (c == ']' && any) {
                    ++pos;
                    break;
                }

                // Parse one item: an escape class, a literal, or a range.
                if (c == '\\') {
                    ++pos;
                    if (atEnd()) {
                        return fail("trailing backslash in character class");
                    }
                    const char esc = peek();
                    ++pos;
                    if (esc == 'd' || esc == 'w' || esc == 's') {
                        mergeBitmap(bitmap, esc == 'd' ? digitsBitmap() : (esc == 'w' ? wordBitmap() : spaceBitmap()));
                        any = true;
                        continue;  // escape classes cannot start a range
                    }
                    if (esc == 'D' || esc == 'W' || esc == 'S') {
                        ClassBitmap predefined = esc == 'D' ? digitsBitmap() : (esc == 'W' ? wordBitmap() : spaceBitmap());
                        invertBitmap(predefined);
                        mergeBitmap(bitmap, predefined);
                        any = true;
                        continue;
                    }
                    c = unescape(esc);
                } else {
                    ++pos;
                }

                // Optional range: [a-z]. A '-' right before ']' is a literal.
                if (!atEnd() && peek() == '-' && pos + 1 < pat.size() && pat[pos + 1] != ']') {
                    ++pos;  // '-'
                    char hi = 0;
                    if (!atEnd() && peek() == '\\') {
                        ++pos;
                        if (atEnd()) {
                            return fail("trailing backslash in character class");
                        }
                        hi = unescape(peek());
                        ++pos;
                    } else if (!atEnd()) {
                        hi = peek();
                        ++pos;
                    } else {
                        return fail("unclosed character class");
                    }
                    if (static_cast<std::uint8_t>(hi) < static_cast<std::uint8_t>(c)) {
                        return fail("invalid character range");
                    }
                    addRangeToBitmap(bitmap, c, hi);
                    any = true;
                } else {
                    addCharToBitmap(bitmap, c);
                    any = true;
                }
            }

            if (negate) {
                invertBitmap(bitmap);
            }
            emit(Op::Class, 0, static_cast<std::uint32_t>(addClass(bitmap)));
            return !bad();
        }

        static char unescape(char esc) {
            switch (esc) {
                case 't':
                    return '\t';
                case 'n':
                    return '\n';
                case 'r':
                    return '\r';
                case 'f':
                    return '\f';
                case 'v':
                    return '\v';
                default:
                    return esc;
            }
        }
    };

    Compiler compiler{scratch, pattern, 0, {}};
    if (!compiler.parse()) {
        if (error != nullptr) {
            *error = compiler.error;
        }
        return false;
    }
    *out = std::move(scratch);
    return true;
}

bool RegexLite::search(std::string_view text) const noexcept {
    if (prog_.empty()) {
        return false;  // never compiled
    }
    for (std::size_t start = 0; start <= text.size(); ++start) {
        std::uint32_t steps = kMaxSteps;
        if (matchRec(0, start, text, &steps, kMaxMatchDepth)) {
            return true;
        }
    }
    return false;
}

bool RegexLite::matchRec(std::int32_t pc,
                         std::size_t pos,
                         std::string_view text,
                         std::uint32_t* stepsLeft,
                         std::uint32_t depthLeft) const noexcept {
    while (true) {
        if (*stepsLeft == 0) {
            return false;  // step budget exhausted — treat as non-match
        }
        if (depthLeft == 0) {
            return false;  // recursion depth cap — protects small thread stacks
        }
        --(*stepsLeft);
        const Inst& inst = prog_[static_cast<std::size_t>(pc)];
        switch (inst.op) {
            case Op::Char:
                if (pos >= text.size() || static_cast<std::uint8_t>(text[pos]) != inst.ch) {
                    return false;
                }
                ++pos;
                ++pc;
                break;
            case Op::Any:
                if (pos >= text.size()) {
                    return false;
                }
                ++pos;
                ++pc;
                break;
            case Op::Class: {
                if (pos >= text.size()) {
                    return false;
                }
                const auto& bitmap = classes_[static_cast<std::size_t>(inst.cls)];
                const std::uint8_t byte = static_cast<std::uint8_t>(text[pos]);
                if ((bitmap[static_cast<std::size_t>(byte >> 3)] & (1u << (byte & 7))) == 0) {
                    return false;
                }
                ++pos;
                ++pc;
                break;
            }
            case Op::AssertStart:
                if (pos != 0) {
                    return false;
                }
                ++pc;
                break;
            case Op::AssertEnd:
                if (pos != text.size()) {
                    return false;
                }
                ++pc;
                break;
            case Op::Jmp:
                pc = inst.x;
                break;
            case Op::Split:
                if (matchRec(inst.x, pos, text, stepsLeft, depthLeft - 1)) {
                    return true;
                }
                pc = inst.y;
                break;
            case Op::Match:
                return true;
        }
    }
}

}  // namespace unknown::native
