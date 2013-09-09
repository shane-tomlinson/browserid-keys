/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

const fs        = require('fs');
const path      = require('path');
const jwcrypto  = require('jwcrypto');

require('jwcrypto/lib/algs/rs');

const DEFAULT_KEY_LENGTH = 256;
const DEFAULT_KEY_ALG = "RS";

var pubKeyPath;
var pubKey;
var privKeyPath;
var privKey;
var logger = noOp;

function noOp() {}

exports.setup = function(options, callback) {
  if (!options) options = {};
  if (!callback) callback = noOp;

  pubKeyPath = options.pubKeyPath;
  privKeyPath = options.privKeyPath;
  logger = options.logger || noOp;

  callback(null);
};

exports.get = function keys(callback) {
  if (!callback) callback = noOp;

  if (pubKey && privKey) {
    callback(null, pubKey, privKey);
  } else if (canLoadKeysFromDisc()) {
    exports.loadFromDisc(callback);
  } else {
    logger('*** Using ephemeral keys ***');
    exports.generate(DEFAULT_KEY_LENGTH, callback);
  }
};

exports.generate = function(length, callback) {
  jwcrypto.generateKeypair({
    algorithm: DEFAULT_KEY_ALG,
    keysize: length
  }, function(err, keypair) {
    if (err) return callback(err);

    pubKey = keypair.publicKey.serialize();
    privKey = keypair.secretKey.serialize();

    callback(null, pubKey, privKey);
  });
};

exports.loadFromDisc = function(callback) {
  pubKey = fs.readFileSync(pubKeyPath).toString();
  privKey = fs.readFileSync(privKeyPath).toString();

  callback(null, pubKey, privKey);
};

function canLoadKeysFromDisc() {
  return (pubKeyPath && privKeyPath &&
              fs.existsSync(pubKeyPath) &&
              fs.existsSync(privKeyPath));
}
