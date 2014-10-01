var crypto = require('crypto');
var zlib = require('zlib');
var url = require('url');
var http = require('https');
var querystring = require('querystring');
var through = require('through2');
var util = require('./util');

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
  var opts = url.parse(CONFIG.GET_LATEST_BACKUP);
  opts.method = 'POST';
  var req = http.request(opts, function(res) {
    var chunks = [];
    var bodylen = 0;
    res.on('error', function(err) {
      return callback(err);
    });
    res.on('data', function(chunk) {
      chunks.push(chunk);
      bodylen += chunk.length;
    });
    res.on('end', function() {
      var body = Buffer.concat(chunks, bodylen);
      var file = new Buffer(JSON.parse(body).fullBackupFile, 'base64');
      decrypt(file, options.password, callback);
    })
  });
  req.on('error', function(err) {
    return callback(err);
  });
  req.write(querystring.stringify(form));
  req.end();
};

var sendToken = module.exports.sendToken = function(email, callback) {
  var form = { login: email };
  var opts = url.parse(CONFIG.SEND_TOKEN);
  opts.method = 'POST';
  var req = http.request(opts, function(res) {
    var chunks = [];
    var bodylen = 0;
    res.on('error', function(err) {
      return callback(err);
    });
    res.on('data', function(chunk) {
      chunks.push(chunk);
      bodylen += chunk.length;
    });
    res.on('end', function() {
      return callback(null, Buffer.concat(chunks, bodylen).toString());
    });
  });
  req.on('error', function(err) {
    return callback(err);
  });
  req.write(querystring.stringify(form));
  req.end();
};
