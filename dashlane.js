var crypto = require('crypto');
var zlib = require('zlib');
var url = require('url');
var http = require('https');
var querystring = require('querystring');
var through = require('through2');
var uuid = require('uuid');
var os = require('os');
var DOMParser = require('xmldom').DOMParser;
var xpath = require('xpath');
var util = require('./util');

var CONFIG = {
  "SEND_TOKEN": 'https://ws1.dashlane.com/6/authentication/sendtoken',
  "GET_LATEST_BACKUP": 'https://ws1.dashlane.com/12/backup/latest',
  "REGISTER_UKI": 'https://ws1.dashlane.com/6/authentication/registeruki'
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
  crypto.pbkdf2(password, salt, 10204, 32, "sha1", function(err, key) {
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
      callback(null, Buffer.concat(bufs, bufslen).toString());
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

var registerUKI = module.exports.registerUKI = function(options, callback) {
  options.uki = crypto.createHash('md5').update(uuid.v1()).digest('hex') + '-webaccess-' + Date.now();
  options.deviceName = "RedImpala-" + os.hostname();
  options.platform = "RedImpala"; // Maybe os.platform() ?
  options.temporary = 0;
  var opts = url.parse(CONFIG.REGISTER_UKI);
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
      return callback(null, options.uki, Buffer.concat(chunks, bodylen).toString());
    });
  });
  req.on('error', function(err) {
    return callback(err);
  });
  req.write(querystring.stringify(options));
  req.end();
};

var getPassword = module.exports.getPassword = function(file, name, callback) {
  var dom = new DOMParser().parseFromString(file);
  var val = xpath.select('/root/KWDataList/KWAuthentifiant[*[@key="Title"]/text()="' + name + '"]/*[@key="Password"]/text()', dom);
  if (val.length > 0)
    return callback(null, val[0].data);
  else
    return callback(null, null);
};
