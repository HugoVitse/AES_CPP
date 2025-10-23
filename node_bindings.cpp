// binding.cpp
#include <napi.h>
#include "AES_CPP/block.hpp"
#include "AES_CPP/enums.hpp"
#include "AES_CPP/file.hpp"
#include "AES_CPP/key.hpp"

using namespace AES_CPP;

// --------------------
// Wrappers C++ -> JS
// --------------------

// Wrapper pour File
class FileWrapper : public Napi::ObjectWrap<FileWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "File", {
            InstanceMethod("encode", &FileWrapper::Encode),
            InstanceMethod("decode", &FileWrapper::Decode)
        });

        constructor = Napi::Persistent(func);
        constructor.SuppressDestruct();
        exports.Set("File", func);
        return exports;
    }

    FileWrapper(const Napi::CallbackInfo& info) 
        : Napi::ObjectWrap<FileWrapper>(info) {
        std::string inPath = info[0].As<Napi::String>();
        std::string outPath = info[1].As<Napi::String>();
        file_ = std::make_unique<File>(inPath, outPath);
    }

private:
    static Napi::FunctionReference constructor;
    std::unique_ptr<File> file_;

    Napi::Value Encode(const Napi::CallbackInfo& info) {
        std::string keyStr = info[0].As<Napi::String>();
        std::string methodStr = info[1].As<Napi::String>();

        // Crée un Key sur le tas
        auto keyPtr = std::make_unique<Key>(keyStr);

        ChainingMethod method = ChainingMethod::CBC; // default
        if (methodStr == "CBC") method = ChainingMethod::CBC;
        else if (methodStr == "ECB") method = ChainingMethod::ECB;
        else if (methodStr == "CTR") method = ChainingMethod::CTR;
        else if (methodStr == "GCM") method = ChainingMethod::GCM;

        file_->encode(keyPtr.get(), method);

        return info.Env().Undefined();
    }

    Napi::Value Decode(const Napi::CallbackInfo& info) {
        std::string keyStr = info[0].As<Napi::String>();

        auto keyPtr = std::make_unique<Key>(keyStr);
        file_->decode(keyPtr.get());

        return info.Env().Undefined();
    }
};

Napi::FunctionReference FileWrapper::constructor;

// Wrapper pour Key
class KeyWrapper : public Napi::ObjectWrap<KeyWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "Key", {
            // ajoute éventuellement des méthodes ici
        });

        constructor = Napi::Persistent(func);
        constructor.SuppressDestruct();
        exports.Set("Key", func);
        return exports;
    }

    KeyWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<KeyWrapper>(info) {
        std::string keyStr = info[0].As<Napi::String>();
        key_ = std::make_unique<Key>(keyStr);
    }

private:
    static Napi::FunctionReference constructor;
    std::unique_ptr<Key> key_;
};

Napi::FunctionReference KeyWrapper::constructor;

// Wrapper pour IV
class IVWrapper : public Napi::ObjectWrap<IVWrapper> {
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports) {
        Napi::Function func = DefineClass(env, "IV", {});
        constructor = Napi::Persistent(func);
        constructor.SuppressDestruct();
        exports.Set("IV", func);
        return exports;
    }

    IVWrapper(const Napi::CallbackInfo& info) : Napi::ObjectWrap<IVWrapper>(info) {
        std::string ivStr = info[0].As<Napi::String>();
        iv_ = std::make_unique<IV>(ivStr);
    }

private:
    static Napi::FunctionReference constructor;
    std::unique_ptr<IV> iv_;
};

Napi::FunctionReference IVWrapper::constructor;

// --------------------
// Enum wrappers
// --------------------
Napi::Object InitEnums(Napi::Env env, Napi::Object exports) {
    Napi::Object chaining = Napi::Object::New(env);
    chaining.Set("CBC", Napi::Number::New(env, static_cast<int>(ChainingMethod::CBC)));
    chaining.Set("ECB", Napi::Number::New(env, static_cast<int>(ChainingMethod::ECB)));
    chaining.Set("CTR", Napi::Number::New(env, static_cast<int>(ChainingMethod::CTR)));
    chaining.Set("GCM", Napi::Number::New(env, static_cast<int>(ChainingMethod::GCM)));
    exports.Set("ChainingMethod", chaining);

    Napi::Object padding = Napi::Object::New(env);
    padding.Set("ZeroPadding", Napi::Number::New(env, static_cast<int>(Padding::ZeroPadding)));
    padding.Set("PKcs7", Napi::Number::New(env, static_cast<int>(Padding::PKcs7)));
    padding.Set("None_", Napi::Number::New(env, static_cast<int>(Padding::None)));
    exports.Set("Padding", padding);

    return exports;
}

// --------------------
// Init module
// --------------------
Napi::Object InitAll(Napi::Env env, Napi::Object exports) {
    FileWrapper::Init(env, exports);
    KeyWrapper::Init(env, exports);
    IVWrapper::Init(env, exports);
    InitEnums(env, exports);
    return exports;
}

NODE_API_MODULE(aescpp, InitAll)
