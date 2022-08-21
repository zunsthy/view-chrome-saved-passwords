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
  using v8::Exception;

  void SimpleCryptProtectData(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    if (!args[0]->IsArrayBuffer()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "CryptProtectData() need ArrayBuffer as input").ToLocalChecked()));
      return;
    }
    Local<ArrayBuffer> input = Local<ArrayBuffer>::Cast(args[0]);

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    BYTE *pbDataIn = (BYTE *)input->GetBackingStore()->Data();
    DWORD cbDataIn = input->GetBackingStore()->ByteLength();
    dataIn.pbData = pbDataIn;
    dataIn.cbData = cbDataIn;
    if (!CryptProtectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
      isolate->ThrowError("CryptProtectData() encrypt error");
      return;
    }
  
    Local<ArrayBuffer> ab = ArrayBuffer::New(isolate, dataOut.cbData);
    memcpy(ab->GetBackingStore()->Data(), dataOut.pbData, dataOut.cbData);
    LocalFree(dataOut.pbData);
    args.GetReturnValue().Set(ab);
  }

  void SimpleCryptUnprotectData(const FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = args.GetIsolate();
    if (!args[0]->IsArrayBuffer()) {
      isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "CryptUnprotectData() need ArrayBuffer as input").ToLocalChecked()));
      return;
    }
    Local<ArrayBuffer> input = Local<ArrayBuffer>::Cast(args[0]);

    DATA_BLOB dataIn;
    DATA_BLOB dataOut;
    BYTE *pbDataIn = (BYTE *)input->GetBackingStore()->Data();
    DWORD cbDataIn = input->GetBackingStore()->ByteLength();
    dataIn.pbData = pbDataIn;
    dataIn.cbData = cbDataIn;
    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, 0, &dataOut)) {
      isolate->ThrowError("CryptUnprotectData() decrypt error");
      return;
    }
  
    Local<ArrayBuffer> ab = ArrayBuffer::New(isolate, dataOut.cbData);
    memcpy(ab->GetBackingStore()->Data(), dataOut.pbData, dataOut.cbData);
    LocalFree(dataOut.pbData);
    args.GetReturnValue().Set(ab);
  }

  void Initialize(Local<Object> exports) {
    NODE_SET_METHOD(exports, "CryptProtectData", SimpleCryptProtectData);
    NODE_SET_METHOD(exports, "CryptUnprotectData", SimpleCryptUnprotectData);
  }

  NODE_MODULE(NODE_GYP_MODULE_NAME, Initialize)
}
