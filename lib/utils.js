const base64ToUint8Array = (b64str) => {
  const str = atob(b64str);
  const arr = new Uint8Array(str.length);
  for (let i = 0; i < str.length; i++) {
    arr[i] = str.charCodeAt(i);
  }
  return arr;
};

exports.base64ToUint8Array = base64ToUint8Array;
