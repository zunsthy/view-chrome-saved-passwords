#include <node.h>
#include <windows.h>
#include <Wincrypt.h>

namespace crypt {
  using v8::FunctionCallbackInfo;
  using v8::Isolate;
  using v8::Local;
  using v8::String;
  using v8::Object;
  using v8::Value;
  using v8::ArrayBuffer;
  using v8::Uint8Array;
  using v8::Exception;

  void LocalDeleter(void* data, size_t _length, void* _dData) {
    LocalFree(data);
  }

  void CryptProtectOrUnprotectData(const FunctionCallbackInfo<Value>& args, boolean crypt) {
    Isolate* isolate = args.GetIsolate();
    if (!args[0]->IsUint8Array()) {
      isolate->ThrowException(
        Exception::TypeError(
          String::NewFromUtf8(isolate,
            "input must be \"Uint8Array\"").ToLocalChecked()));
      return;
    }
    Local<Uint8Array> input = Local<Uint8Array>::Cast(args[0]);
    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    DWORD cbDataIn = input->Length();
    BYTE *pbDataIn = new BYTE[cbDataIn];
    input->CopyContents(pbDataIn, cbDataIn);
    dataIn.pbData = pbDataIn;
    dataIn.cbData = cbDataIn;
    if (crypt) {
      if (!CryptProtectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        isolate->ThrowError("CryptProtectData() encrypt error");
        return;
      }
    } else {
      if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
        isolate->ThrowError("CryptUnprotectData() decrypt error");
        return;
      }
    }
    Local<ArrayBuffer> ab = ArrayBuffer::New(isolate,
      ArrayBuffer::NewBackingStore(dataOut.pbData, dataOut.cbData, LocalDeleter, NULL));
    Local<Uint8Array> out = Uint8Array::New(ab, 0, ab->ByteLength());
    delete pbDataIn;
    args.GetReturnValue().Set(out);
  }

  void SimpleCryptProtectData(const FunctionCallbackInfo<Value>& args) {
    CryptProtectOrUnprotectData(args, true);
  }

  void SimpleCryptUnprotectData(const FunctionCallbackInfo<Value>& args) {
    CryptProtectOrUnprotectData(args, false);
  }

  void Initialize(Local<Object> exports) {
    NODE_SET_METHOD(exports, "CryptProtectData", SimpleCryptProtectData);
    NODE_SET_METHOD(exports, "CryptUnprotectData", SimpleCryptUnprotectData);
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
}
