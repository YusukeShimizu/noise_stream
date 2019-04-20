/* eslint-env mocha */
/* eslint prefer-arrow-callback: "off" */

'use strict';
const secp256k1 = require('bcrypto/lib/secp256k1');
const net = require('net');
const assert = require('assert');
const {NoiseStream} = require('../noise-stream');

function makeListener() {
  // First, generate the long-term private keys for the listener.
  const localPriv = secp256k1.privateKeyGenerate();
  const stream = new NoiseStream();
  const listener = net.createServer((socket) => {
    stream.accept(
      socket,
      Buffer.from(localPriv,'hex')
    );
  })
  const Addr = secp256k1.publicKeyCreate(localPriv, true);
  return [listener,stream,Addr]
}

function establishTestConnection() {
  const [listener,stream,Addr] = makeListener();
  const port = 9736;
  listener.listen(port);
  // generate the long-term private keys remote end of the connection
  // within the test.
  const remotePriv = secp256k1.privateKeyGenerate();
  const remoteStream = new NoiseStream();
  const socket = net.connect(port);
  remoteStream.connect(
    socket,
    Buffer.from(remotePriv,'hex'),
    Buffer.from(Addr,'hex')
  );
  return[stream,remoteStream]
}

/*
 * Tests
 */

describe('Noise-stream', () => {
  const [stream,remoteStream] = establishTestConnection();
  it('should test connection establishment', () => {
    const testMessage = "Hello World!";
    remoteStream.once('connect',()=>{
      remoteStream.write(Buffer.from(testMessage));
    })
    stream.once('data', (chunk) => {
      assert.strictEqual(Buffer.from(testMessage),chunk);
    });
  })
});
