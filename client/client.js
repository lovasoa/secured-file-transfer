var https = require("https");
var fs = require("fs");
var crypto = require("crypto");
var assert = require("assert");

// Read the secret hmac key we will use to sign our file
var hmacKey = fs.readFileSync(__dirname + '/hmac-secret.txt');

// Secure connection parameters
var options = {
    hostname: 'minissl-SERVER',
    port:   4443,
    method: 'GET',
    path:   '/secret.txt',
    key:    fs.readFileSync(__dirname + '/minissl-client.key.pem'),
    cert:   fs.readFileSync(__dirname + '/minissl-client.pem'),
    ca:     fs.readFileSync(__dirname + '/minissl-ca.pem'),
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256',
    secureProtocol: 'TLSv1_2_method'
};
// Custom HTTPS agent that supports encoding
options.agent = new https.Agent(options);

// Create an HTTP request (handshake is managed by node)
var req = https.request(options, (res) => {
  // HMAC digest
  var hmac = new Buffer(res.headers['x-hmac'], 'hex'); 
  // AES192 Initialization vector
  var iv = new Buffer(res.headers['x-iv'], 'hex');
  // Compute the HMAC of the result
  var hmacStream = crypto.createHmac('sha256', hmacKey);
  res.pipe(hmacStream);
  hmacStream.on('data', d => {
    if (hmac.equals(d)) {
      console.log("HMAC matched.");
    } else {
      console.warn("HMAC didn't match.");
    }
  });

  // Open write stream to output file
  var out = fs.createWriteStream(__dirname + '/secret.txt.aes192');
  // Write the encrypted file
  res.pipe(out);
  out.on('close', () => console.log("File saved successfully."));
  // Save the input vector as a separate file, throw on error
  fs.writeFile(__dirname + '/secret.txt.iv', iv, e => { if(e) throw e});
});

// Send the request
req.end();
