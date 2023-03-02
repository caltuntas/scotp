function _0x9367a6(_0x2887fe) {
	var _0xa2623d = {
		outputUpper: false,
		b64Pad: '=',
		shakeLen: -1
	};
	var _0x1fc076 = _0xa2623d;
	if (_0x2887fe = _0x2887fe || {}, _0x1fc076.outputUpper = _0x2887fe.outputUpper || false, true === _0x2887fe.hasOwnProperty('b64Pad') && (_0x1fc076.b64Pad = _0x2887fe.b64Pad), true === _0x2887fe.hasOwnProperty('shakeLen')) {
		if (0 != _0x2887fe.shakeLen % 8) {
			throw Error('shakeLen must be a multiple of 8');
		}
		_0x1fc076.shakeLen = _0x2887fe.shakeLen;
	}
	if ('boolean' != typeof _0x1fc076.outputUpper) {
		throw Error('Invalid outputUpper formatting option');
	}
	if ('string' != typeof _0x1fc076.b64Pad) {
		throw Error('Invalid b64Pad formatting option');
	}
	return _0x1fc076;
}

const  getHMAC = function (fmt, _0x24b7fb) {
	var _0x366c62, _0x32d4b2, _0x3120c5, _0x715138;
	if (false === _0x3cf787) {
		throw Error('Cannot call getHMAC without first setting HMAC key');
	}
	switch (_0x3120c5 = _0x9367a6(_0x24b7fb), fmt) {
		case 'HEX':
			_0x366c62 = function (_0xda8713) {
				;
				return _0x52e4c3(_0xda8713, _0x308866, _0x172179, _0x3120c5);
			};
			break;
		case 'B64':
			_0x366c62 = function (_0x419d7f) {
				;
				return _0x3d70ed(_0x419d7f, _0x308866, _0x172179, _0x3120c5);
			};
			break;
		case 'BYTES':
			_0x366c62 = function (_0x1406bc) {
				;
				return _0x57e885(_0x1406bc, _0x308866, _0x172179);
			};
			break;
		case 'ARRAYBUFFER':
			try {
				_0x366c62 = new ArrayBuffer(0);
			} catch (_0x5a8b51) {
				throw Error('ARRAYBUFFER not supported by this environment');
			}
			_0x366c62 = function (_0x1cf332) {
				;
				return _0x2563a8(_0x1cf332, _0x308866, _0x172179);
			};
			break;
		default:
			throw Error('outputFormat must be HEX, B64, BYTES, or ARRAYBUFFER');
	}
	return _0x32d4b2 = _0x245a9c(_0x33f6ea.slice(), _0x14da37, _0x1652a7, _0x1df2a5(_0x4b4866), _0x308866), _0x715138 = _0x31a7b7(_0x48974f, _0x324b89(_0x4900d9)), _0x366c62(_0x715138 = _0x245a9c(_0x32d4b2, _0x308866, _0x44dda5, _0x715138, _0x308866));
};

const update = function (_0x3ab1b9) {
	var _0x330454,
		_0x3d8345,
		_0x3341fe,
		_0x11ecb3 = 0,
		_0x5bee2f = _0x44dda5 >>> 5;
	for (
		_0x3ab1b9 = (_0x330454 = _0x587b4a(_0x3ab1b9, _0x33f6ea, _0x14da37)).binLen,
		_0x3d8345 = _0x330454.value,
		_0x330454 = _0x3ab1b9 >>> 5,
		_0x3341fe = 0;
		_0x3341fe < _0x330454;
		_0x3341fe += _0x5bee2f
	) {
		if (_0x11ecb3 + _0x44dda5 <= _0x3ab1b9) {
			_0x4b4866 = _0x31a7b7(
				_0x3d8345.slice(_0x3341fe, _0x3341fe + _0x5bee2f),
				_0x4b4866
			);
			_0x11ecb3 += _0x44dda5;
		}
	}
	_0x1652a7 += _0x11ecb3;
	_0x33f6ea = _0x3d8345.slice(_0x11ecb3 >>> 5);
	_0x14da37 = _0x3ab1b9 % _0x44dda5;
	_0xc4c2c8 = true;
};
const setHMACKey = function (_0x1ced33, _0x166a17, _0x175965) {
	var _0x5b12a4;
	if (true === _0x3cf787) {
		throw Error("HMAC key already set");
	}
	if (true === _0xc4c2c8) {
		throw Error("Cannot set HMAC key after calling update");
	}
	if (true === _0x3049fd) {
		throw Error("SHAKE is not supported for HMAC");
	}
	if (
		((_0x1ced33 = (_0x166a17 = _0xfa41ba(
			_0x166a17,
			(_0x1c1dd9 = (_0x175965 || {}).encoding || "UTF8"),
			_0x172179
		)(_0x1ced33)).binLen),
			(_0x166a17 = _0x166a17.value),
			(_0x175965 = (_0x5b12a4 = _0x44dda5 >>> 3) / 4 - 1),
			_0x5b12a4 < _0x1ced33 / 8)
	) {
		for (
			_0x166a17 = _0x245a9c(
				_0x166a17,
				_0x1ced33,
				0,
				_0x324b89(_0x4900d9),
				_0x308866
			);
			_0x166a17.length <= _0x175965;

		) {
			_0x166a17.push(0);
		}
		_0x166a17[_0x175965] &= 4294967040;
	} else {
		if (_0x5b12a4 > _0x1ced33 / 8) {
			for (; _0x166a17.length <= _0x175965; ) {
				_0x166a17.push(0);
			}
			_0x166a17[_0x175965] &= 4294967040;
		}
	}
	for (_0x1ced33 = 0; _0x1ced33 <= _0x175965; _0x1ced33 += 1) {
		_0x2c055d[_0x1ced33] = 909522486 ^ _0x166a17[_0x1ced33];
		_0x48974f[_0x1ced33] = 1549556828 ^ _0x166a17[_0x1ced33];
	}
	_0x4b4866 = _0x31a7b7(_0x2c055d, _0x4b4866);
	_0x1652a7 = _0x44dda5;
	_0x3cf787 = true;
};

const _dec2hex = function (dec) {
	for (
		var key = "0123456789ABCDEF", maskedKey = key.substr(15 & dec, 1);
		dec > 15;

	) {
		maskedKey = key.substr(15 & (dec >>= 4), 1) + maskedKey;
	}
	return maskedKey;
};

const _base32_decode = function (_0x44cc71) {
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
};

const _base32tohexUpdated = function (_0x1d94a4) {
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
};

const dec2hex = function (_0x5df457) {
	return (_0x5df457 < 15.5 ? "0" : "") + Math.round(_0x5df457).toString(16);
};

const hex2dec = function (_0x519437) {
	return parseInt(_0x519437, 16);
};

const leftpad = function (_0x3e9f46, _0x2b2f51, _0x27fc3a) {
	return (
		_0x2b2f51 + 1 >= _0x3e9f46.length &&
		(_0x3e9f46 =
			Array(1 + _0x2b2f51 - _0x3e9f46.length).join(_0x27fc3a) + _0x3e9f46),
		_0x3e9f46
	);
};

const getOTP = function (input) {
	const l = {
		default: {
			TotpPeriod: 30,
			TotpDigits: 6,
			TotpAlgorithm: "SHA-1",
		},
	};

	var totpAlgo =
		arguments.length > 1 && void 0 !== arguments[1]
		? arguments[1]
		: l.default.TotpAlgorithm,
		totpDigits =
		arguments.length > 2 && void 0 !== arguments[2]
		? arguments[2]
		: l.default.TotpDigits,
		totpPeriod =
		arguments.length > 3 && void 0 !== arguments[3]
		? arguments[3]
		: l.default.TotpPeriod;
	totpAlgo || (totpAlgo = l.default.TotpAlgorithm);
	totpDigits || (totpDigits = l.default.TotpDigits);
	totpPeriod || (totpPeriod = l.default.TotpPeriod);
	try {
		var timestamp = Math.round(new Date().getTime() / 1000),
			paddedTimestamp = leftpad( dec2hex(Math.floor(timestamp / totpPeriod)), 16, "0"),
			hexVal = _base32tohexUpdated(input),
			//_0x5ba50c = new u.default(totpAlgo, "HEX");
			setHMACKey(hexVal, "HEX");
		update(paddedTimestamp);
		var hmac = getHMAC("HEX"),
			hmacdec = hex2dec(hmac.substring(hmac.length - 1)),
			hexdec = (hex2dec(hmac.substr(2 * hmacdec, 8)) & hex2dec("7fffffff")) + "";
		hexdec = hexdec.substr(hexdec.length - totpDigits, totpDigits);
	} catch (err) {
		throw err;
	}
	return hexdec;
};
