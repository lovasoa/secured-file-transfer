var https =  require('https'),
    fs =     require('fs'),
    crypto = require('crypto'),
    stream = require('stream');

// Read the secret hmac key we will use to sign our file
var hmacKey = fs.readFileSync(__dirname + '/hmac-secret.txt');
// Read the secret key that will be used to encrypt the file before sending it
var cryptKey = fs.readFileSync(__dirname + '/aes192-key.bin');

var options = {
    // Server auth
    key:    fs.readFileSync(__dirname + '/minissl-server.key.pem'),
    cert:   fs.readFileSync(__dirname + '/minissl-server.pem'),
    ca:     fs.readFileSync(__dirname + '/minissl-ca.pem'),
    requestCert:        true,
    rejectUnauthorized: true, // Reject unauthorized clients
    ciphers: 'ECDHE-RSA-AES128-GCM-SHA256', // Only one cipher
    secureProtocol: 'TLSv1_2_method' // Realize a TLSv1.2 handshake
};

// Create an https server with the server certificate and key
var server = https.createServer(options, function (req, res) {
  // Once the request was received, we are sure the client was authorized
  // Open a stream for reading the file
  var instream = fs.createReadStream(__dirname + '/secret.txt');

  // Start encrypting the file
  var iv = crypto.randomBytes(16); // Initialization vector
  var cryptStream = crypto.createCipheriv('aes192', cryptKey, iv);
  instream.pipe(cryptStream);
  // Create an output stream of encrypted bytes
  var outputStream = cryptStream.pipe(stream.PassThrough());
  
  // Compute the HMAC of the file to an hex string
  var hmac = '';
  var hmacCompute = crypto.createHmac('sha256', hmacKey);
  cryptStream.pipe(hmacCompute);
  hmacCompute.on('data', buf => hmac += buf.toString('hex'));
  hmacCompute.on('end', () => {
    // HMAC was successfully computed
    // Send the HMAC as an HTTP header
    res.setHeader('X-HMAC', hmac);
    // Send the IV as a header
    res.setHeader('X-IV', iv.toString('hex'));
    outputStream.pipe(res);
  });
});

// Log all connections, including the ones that fail
server.on('secureConnection', function(tlsSocket) {
    console.log('secure connection established from ' +
                 tlsSocket.remoteAddress +
                 '\n\tauthorized: ' + tlsSocket.authorized + 
                 '\n\tauthorization error: ' + tlsSocket.authorizationError);
});

server.listen(4443);
