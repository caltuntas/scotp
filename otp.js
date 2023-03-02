const jsSHA = require("jssha");

function decode (n) {
  var t = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
  var c, h, i, o, A = '', f = '', u = '', l = 0;
  if (/[^A-Za-z0-9\+\/\=]/g.exec(n)) {
    throw new Error('There were invalid base64 characters in the input text.\nValid base64 characters are A-Z, a-z, 0-9, \'+\', \'/\',and \'=\'\nExpect errors in decoding.');
  }
  n = n.replace(/[^A-Za-z0-9\+\/\=]/g, '');
  do {
    c = t.indexOf(n.charAt(l++)) << 2 | (i = t.indexOf(n.charAt(l++))) >> 4;
    h = (15 & i) << 4 | (o = t.indexOf(n.charAt(l++))) >> 2;
    f = (3 & o) << 6 | (u = t.indexOf(n.charAt(l++)));
    A += String.fromCharCode(c);
    64 != o && (A += String.fromCharCode(h));
    64 != u && (A += String.fromCharCode(f));
    c = h = f = '';
    i = o = u = '';
  } while (l < n.length);
  return A;
}

function dec2hex(s) {
  return (s < 15.5 ? "0" : "") + Math.round(s).toString(16);
};

function hex2dec(s) {
  return parseInt(s, 16);
};

function leftpad(str, len, pad) {
  return (
    len + 1 >= str.length &&
    (str =
      Array(1 + len - str.length).join(pad) + str),
    str
  );
};
function _base32tohexUpdated (_0x1d94a4) {
  for (
    var _0x77b264 = _base32_decode(_0x1d94a4.toUpperCase()),
    _0x170fb2 = "",
    _0x1bacec = 0;
    _0x1bacec < _0x77b264.output.length;
    _0x1bacec++
  ) {
    _0x170fb2 =
      _0x170fb2 +
      (_0x77b264.output[_0x1bacec] < 16 ? "0" : "") +
      _dec2hex(_0x77b264.output[_0x1bacec]);
  }
  return _0x170fb2;
}

function _base32_decode (_0x44cc71) {
  for (
    var _0x51bb1a = 0,
    _0x39a8b7 = 0,
    _0x552bd6 = [],
    _0x66e8bf = 0,
    _0x1b7b36 = 0;
    _0x66e8bf < _0x44cc71.length;

  ) {
    var _0x4e17cf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=".indexOf(
      _0x44cc71.charAt(_0x66e8bf++)
    );
    _0x4e17cf >= 0 &&
      _0x4e17cf < 32 &&
      ((_0x51bb1a <<= 5),
        (_0x51bb1a |= _0x4e17cf),
        (_0x39a8b7 += 5) >= 8 &&
        ((_0x552bd6[_0x1b7b36++] = (_0x51bb1a >> (_0x39a8b7 - 8)) & 255),
          (_0x39a8b7 -= 8)));
  }
  var _0x4b3127 = { output: _0x552bd6 };
  return (_0x4b3127.bitsLeft = _0x39a8b7), _0x4b3127;
}

function _dec2hex (dec) {
  for (
    var key = "0123456789ABCDEF", maskedKey = key.substr(15 & dec, 1);
    dec > 15;

  ) {
    maskedKey = key.substr(15 & (dec >>= 4), 1) + maskedKey;
  }
  return maskedKey;
}


const totpPeriod = 30;
const totpDigits = 6;
const timestamp = Math.round(new Date().getTime() / 1000);
const paddedTimestamp = leftpad( dec2hex(Math.floor(timestamp / totpPeriod)), 16, "0");
const hexVal = _base32tohexUpdated(secret);

var shaObj = new jsSHA('SHA-1', 'HEX');
shaObj.setHMACKey(hexVal, 'HEX');
shaObj.update(paddedTimestamp);
const hmac = shaObj.getHMAC('HEX');
const hmacdec = hex2dec(hmac.substring(hmac.length - 1));
let hexdec = (hex2dec(hmac.substr(2 * hmacdec, 8)) & hex2dec("7fffffff")) + "";
hexdec = hexdec.substr(hexdec.length - totpDigits, totpDigits);

console.log(hexdec);
