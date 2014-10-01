var crypto = require('crypto');
var zlib = require('zlib');
var through = require('through2');
var util = require('./util');
var request = require('request');

var CONFIG = {
  "SEND_TOKEN": 'https://ws1.dashlane.com/6/authentication/sendtoken',
  "GET_LATEST_BACKUP": 'https://ws1.dashlane.com/12/backup/latest'
};

var decrypt = module.exports.decrypt = function (file, password, callback) {
  var salt = file.slice(0, 32);
  var compressed;
  if (file.slice(32, 36).toString('utf8') == 'KWC3') {
    compressed = true;
    var aes = file.slice(36);
  } else {
    compressed = false;
    var aes = file.slice(32);
  }
  crypto.pbkdf2(password, salt, 10204, 32, function(err, key) {
    if (err) return callback(err);
    var tmp = util.BytesToKey(key, salt.slice(0, 8), 1);
    var iv = tmp.iv;
    if (!compressed) {
      key = tmp.key;
    }
    var decipher = crypto.createDecipheriv('aes256', key, iv);
    var out = decipher;
    if (compressed) {
      out = decipher.pipe(through(function write(chunk, enc, cb) {
        if (this.chunk) {
          this.push(this.chunk);
          this.chunk = chunk;
        } else {
          this.chunk = chunk.slice(6);
        }
        cb();
      }, function end(cb) {
        var chunk = this.chunk;
        this.push(chunk.slice(0, chunk.length - 1));
        cb();
      })).pipe(zlib.createInflateRaw());
    }
    var bufs = [];
    var bufslen = 0;
    out.on('data', function(chunk) {
      bufs.push(chunk);
      bufslen += chunk.length;
    });
    out.on('end', function() {
      callback(null, Buffer.concat(bufs, bufslen));
    });
    decipher.end(aes);
  });
};

var getFullBackup = module.exports.getFullBackup = function(options, callback) {
  var form = {
    login: options.login,
    lock: 'nolock',
    timestamp: 0,
    sharingTimestamp: 0
  };
  if (options.uki)
    form.uki = options.uki;
  else if (options.otp)
    form.otp = options.otp;
  else if (options.token)
    form.token = options.token;
  else
    return callback(new Error("No login provided"));
  request.post(CONFIG.GET_LATEST_BACKUP, { form: form }, function(err, resp, body) {
    if (err) return callback(err);
    var file = new Buffer(JSON.parse(body).fullBackupFile, 'base64');
    decrypt(file, options.password, callback);
  });
};

var sendToken = module.exports.sendToken = function(email, callback) {
  request.post(CONFIG.SEND_TOKEN, {
    form: {
      login: email,
    }
  }, function(err, resp, body) {
    if (err) return callback(err);
    else return callback(null, body); // TODO : Check if body == 'OK'
  });
};
