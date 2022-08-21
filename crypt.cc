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

  void SimpleCryptProtectData(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    if (!args[0]->IsUint8Array()) {
      isolate->ThrowException(
        Exception::TypeError(
          String::NewFromUtf8(isolate,
            "CryptProtectData() need IsUint8Array as input").ToLocalChecked()));
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
    if (!CryptProtectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
      isolate->ThrowError("CryptProtectData() encrypt error");
      return;
    }

    Local<ArrayBuffer> ab = ArrayBuffer::New(isolate, dataOut.cbData);
    memcpy(ab->GetBackingStore()->Data(), dataOut.pbData, dataOut.cbData);
    Local<Uint8Array> out = Uint8Array::New(ab, 0, ab->ByteLength());
    LocalFree(dataOut.pbData);
    delete pbDataIn;
    args.GetReturnValue().Set(out);
  }

  void SimpleCryptUnprotectData(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    if (!args[0]->IsUint8Array()) {
      isolate->ThrowException(
        Exception::TypeError(
          String::NewFromUtf8(isolate,
            "CryptUnprotectData() need IsUint8Array as input").ToLocalChecked()));
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
    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
      isolate->ThrowError("CryptUnprotectData() encrypt error");
      return;
    }

    Local<ArrayBuffer> ab = ArrayBuffer::New(isolate, dataOut.cbData);
    memcpy(ab->GetBackingStore()->Data(), dataOut.pbData, dataOut.cbData);
    Local<Uint8Array> out = Uint8Array::New(ab, 0, ab->ByteLength());
    LocalFree(dataOut.pbData);
    delete pbDataIn;
    args.GetReturnValue().Set(out);
  }

  void Initialize(Local<Object> exports) {
    NODE_SET_METHOD(exports, "CryptProtectData", SimpleCryptProtectData);
    NODE_SET_METHOD(exports, "CryptUnprotectData", SimpleCryptUnprotectData);
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
}
