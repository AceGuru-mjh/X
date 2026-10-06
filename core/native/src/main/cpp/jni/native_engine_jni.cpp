#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <exception>
#include <new>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <vector>

#include "unknown_native/engine.h"
#include "unknown_native/protocol.h"
#include "unknown_native/sha256.h"

namespace {

constexpr std::uint64_t kHandleMagic = 0x554e4b4e5f4e4154ULL;  // "UNKN_NAT"

struct EngineHandle {
    std::uint64_t magic;
    std::unique_ptr<unknown::native::CompiledRuleSet> set;
};

struct HashHandle {
    std::uint64_t magic;
    unknown::native::Sha256 hash;
};

void throwIllegalArgument(JNIEnv* env, const char* message) {
    if (env == nullptr) {
        return;
    }
    const jclass clazz = env->FindClass("java/lang/IllegalArgumentException");
    if (clazz != nullptr) {
        env->ThrowNew(clazz, message);
    }
}

EngineHandle* asEngineHandle(JNIEnv* env, jlong handle) {
    if (handle == 0) {
        throwIllegalArgument(env, "native engine handle is null");
        return nullptr;
    }
    auto* engine = reinterpret_cast<EngineHandle*>(static_cast<std::uintptr_t>(handle));
    if (engine->magic != kHandleMagic) {
        throwIllegalArgument(env, "invalid native engine handle (already closed?)");
        return nullptr;
    }
    return engine;
}

HashHandle* asHashHandle(JNIEnv* env, jlong handle) {
    if (handle == 0) {
        throwIllegalArgument(env, "native hash handle is null");
        return nullptr;
    }
    auto* hasher = reinterpret_cast<HashHandle*>(static_cast<std::uintptr_t>(handle));
    if (hasher->magic != kHandleMagic) {
        throwIllegalArgument(env, "invalid native hash handle (already finished?)");
        return nullptr;
    }
    return hasher;
}

/** RAII wrapper around GetStringUTFChars; view length uses GetStringUTFLength. */
class UtfString final {
public:
    UtfString(JNIEnv* env, jstring reference) : env_(env), reference_(reference) {
        if (reference_ != nullptr) {
            chars_ = env_->GetStringUTFChars(reference_, nullptr);
            bytes_ = env_->GetStringUTFLength(reference_);
        }
    }

    ~UtfString() {
        if (chars_ != nullptr) {
            env_->ReleaseStringUTFChars(reference_, chars_);
        }
    }

    UtfString(const UtfString&) = delete;
    UtfString& operator=(const UtfString&) = delete;

    [[nodiscard]] std::string_view view() const { return {chars_, static_cast<std::size_t>(bytes_)}; }

    [[nodiscard]] bool valid() const { return chars_ != nullptr; }

private:
    JNIEnv* env_;
    jstring reference_;
    const char* chars_ = nullptr;
    jsize bytes_ = 0;
};

jlong toJLong(const void* pointer) {
    return static_cast<jlong>(reinterpret_cast<std::uintptr_t>(pointer));
}

/**
 * Guards a JNI entry body against C++ exceptions escaping into the VM,
 * which would be undefined behaviour. [body] returns the JNI result.
 */
template <typename Body>
auto guarded(JNIEnv* env, const char* entry, Body&& body) -> decltype(body()) {
    using Result = decltype(body());
    try {
        return body();
    } catch (const std::bad_alloc&) {
        env->ExceptionClear();
        throwIllegalArgument(env, "native code out of memory");
    } catch (const std::exception& error) {
        env->ExceptionClear();
        throwIllegalArgument(env, (std::string(entry) + ": " + error.what()).c_str());
    } catch (...) {
        env->ExceptionClear();
        throwIllegalArgument(env, (std::string(entry) + ": unknown native failure").c_str());
    }
    if constexpr (std::is_void_v<Result>) {
        return;  // a Java exception is pending; the JVM unwinds on return
    } else {
        return Result{};  // safe default while a Java exception is pending
    }
}

}  // namespace

extern "C" {

JNIEXPORT jstring JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeVersion(JNIEnv* env, jobject /*thiz*/) {
    return guarded(env, "nativeVersion", [&]() -> jstring {
        const std::string version = "unknown-native 1.0.0 (c++17, aho-corasick+bitmap+sha256+regex)";
        return env->NewStringUTF(version.c_str());
    });
}

JNIEXPORT jlong JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeCreate(JNIEnv* env, jobject /*thiz*/) {
    return guarded(env, "nativeCreate", [&]() -> jlong {
        auto* handle = new (std::nothrow) EngineHandle{kHandleMagic, nullptr};
        return handle != nullptr ? toJLong(handle) : 0;
    });
}

JNIEXPORT void JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeDestroy(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    guarded(env, "nativeDestroy", [&]() {
        EngineHandle* engine = asEngineHandle(env, handle);
        if (engine == nullptr) {
            return;
        }
        engine->magic = 0;
        delete engine;
    });
}

JNIEXPORT jboolean JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeCompile(JNIEnv* env,
                                                                    jobject /*thiz*/,
                                                                    jlong handle,
                                                                    jstring rulesBlob) {
    return guarded(env, "nativeCompile", [&]() -> jboolean {
        EngineHandle* engine = asEngineHandle(env, handle);
        if (engine == nullptr) {
            return JNI_FALSE;
        }
        if (rulesBlob == nullptr) {
            throwIllegalArgument(env, "rules blob is null");
            return JNI_FALSE;
        }
        const UtfString blob(env, rulesBlob);
        if (!blob.valid()) {
            return JNI_FALSE;  // OOM already pending in the JVM
        }
        std::string error;
        auto compiled = unknown::native::CompiledRuleSet::compile(blob.view(), &error);
        if (compiled == nullptr) {
            throwIllegalArgument(env, error.c_str());
            return JNI_FALSE;
        }
        engine->set = std::move(compiled);
        return JNI_TRUE;
    });
}

JNIEXPORT jint JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeRuleCount(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    return guarded(env, "nativeRuleCount", [&]() -> jint {
        EngineHandle* engine = asEngineHandle(env, handle);
        if (engine == nullptr) {
            return 0;
        }
        return engine->set != nullptr ? static_cast<jint>(engine->set->ruleCount()) : 0;
    });
}

JNIEXPORT jobjectArray JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeEvaluate(JNIEnv* env,
                                                                     jobject /*thiz*/,
                                                                     jlong handle,
                                                                     jstring snapshotBlob) {
    return guarded(env, "nativeEvaluate", [&]() -> jobjectArray {
        EngineHandle* engine = asEngineHandle(env, handle);
        if (engine == nullptr) {
            return nullptr;
        }
        if (engine->set == nullptr) {
            throwIllegalArgument(env, "engine handle was never compiled");
            return nullptr;
        }
        if (snapshotBlob == nullptr) {
            throwIllegalArgument(env, "snapshot blob is null");
            return nullptr;
        }
        const UtfString blob(env, snapshotBlob);
        if (!blob.valid()) {
            return nullptr;
        }
        unknown::native::Snapshot snapshot;
        std::string error;
        if (!unknown::native::protocol::parseSnapshot(blob.view(), &snapshot, &error)) {
            throwIllegalArgument(env, error.c_str());
            return nullptr;
        }

        // One scratch per Java thread: allocation-free in the steady state.
        static thread_local unknown::native::EvalScratch scratch;
        unknown::native::Verdict verdict;
        engine->set->evaluate(snapshot, scratch, verdict);

        const std::size_t matchCount = verdict.matchCount;
        const jclass stringClass = env->FindClass("java/lang/String");
        if (stringClass == nullptr) {
            return nullptr;
        }
        const auto arrayLength = static_cast<jsize>(matchCount + 1);
        jobjectArray result = env->NewObjectArray(arrayLength, stringClass, nullptr);
        if (result == nullptr) {
            return nullptr;
        }

        const auto setAndRelease = [&](jsize index, const std::string& text) {
            jstring element = env->NewStringUTF(text.c_str());
            if (element == nullptr) {
                return;  // OOM pending
            }
            env->SetObjectArrayElement(result, index, element);
            env->DeleteLocalRef(element);
        };

        char header[48];
        std::snprintf(header,
                      sizeof(header),
                      "%d\x1f%d\x1f%u",
                      static_cast<int>(verdict.level),
                      static_cast<int>(verdict.score),
                      static_cast<unsigned>(verdict.matchCount));
        setAndRelease(0, header);

        std::string line;
        for (std::size_t i = 0; i < matchCount; ++i) {
            const unknown::native::MatchedRuleView& match = verdict.matches[i];
            line.clear();
            line.reserve(match.ruleId.size() + match.ruleName.size() + match.detailLength + 8);
            line.append(match.ruleId);
            line.push_back('\x1f');
            line.append(match.ruleName);
            line.push_back('\x1f');
            line.push_back(static_cast<char>('0' + static_cast<int>(match.severity)));
            line.push_back('\x1f');
            line.append(match.detail, match.detailLength);
            setAndRelease(static_cast<jsize>(i + 1), line);
        }
        return result;
    });
}

JNIEXPORT jstring JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeSha256Hex(JNIEnv* env,
                                                                      jobject /*thiz*/,
                                                                      jbyteArray data) {
    return guarded(env, "nativeSha256Hex", [&]() -> jstring {
        if (data == nullptr) {
            throwIllegalArgument(env, "data is null");
            return nullptr;
        }
        const jsize length = env->GetArrayLength(data);
        if (length < 0) {
            throwIllegalArgument(env, "negative array length");
            return nullptr;
        }
        auto* bytes = env->GetByteArrayElements(data, nullptr);
        if (bytes == nullptr) {
            return nullptr;
        }
        unknown::native::Sha256 hasher;
        hasher.update(bytes, static_cast<std::size_t>(length));
        env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
        std::uint8_t digest[32];
        hasher.finish(digest);
        const std::string hex = unknown::native::toHexLower(digest, sizeof(digest));
        return env->NewStringUTF(hex.c_str());
    });
}

JNIEXPORT jlong JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeHashCreate(JNIEnv* env, jobject /*thiz*/) {
    return guarded(env, "nativeHashCreate", [&]() -> jlong {
        auto* handle = new (std::nothrow) HashHandle{kHandleMagic, unknown::native::Sha256{}};
        return handle != nullptr ? toJLong(handle) : 0;
    });
}

JNIEXPORT void JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeHashUpdate(JNIEnv* env,
                                                                       jobject /*thiz*/,
                                                                       jlong handle,
                                                                       jbyteArray data) {
    guarded(env, "nativeHashUpdate", [&]() {
        HashHandle* hasher = asHashHandle(env, handle);
        if (hasher == nullptr) {
            return;
        }
        if (data == nullptr) {
            throwIllegalArgument(env, "data is null");
            return;
        }
        const jsize length = env->GetArrayLength(data);
        if (length < 0) {
            throwIllegalArgument(env, "negative array length");
            return;
        }
        auto* bytes = env->GetByteArrayElements(data, nullptr);
        if (bytes == nullptr) {
            return;
        }
        hasher->hash.update(bytes, static_cast<std::size_t>(length));
        env->ReleaseByteArrayElements(data, bytes, JNI_ABORT);
    });
}

JNIEXPORT jstring JNICALL
Java_com_unknown_security_core_nativelib_NativeEngine_nativeHashFinish(JNIEnv* env, jobject /*thiz*/, jlong handle) {
    return guarded(env, "nativeHashFinish", [&]() -> jstring {
        HashHandle* hasher = asHashHandle(env, handle);
        if (hasher == nullptr) {
            return nullptr;
        }
        std::uint8_t digest[32];
        hasher->hash.finish(digest);
        hasher->magic = 0;
        delete hasher;
        const std::string hex = unknown::native::toHexLower(digest, sizeof(digest));
        return env->NewStringUTF(hex.c_str());
    });
}

}  // extern "C"
