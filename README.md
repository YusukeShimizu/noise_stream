# noise-stream

The [Noise Protocol Framework](http://noiseprotocol.org/noise.html) wrapper for lightning network.

## Usage

```js

const NoiseStream = require('@bruwbird/noise_stream');
const net = require('net');
const secp256k1 = require('bcrypto/lib/secp256k1');

const priv = secp256k1.privateKeyGenerate();
const stream = new NoiseStream();
const socket = net.connect(9735);

stream.connect(
  socket,
  Buffer.from(priv,'hex'),
  Buffer.from("<Lightning client addr>",'hex')
);

stream.on('connect',()=>{
  console.log("connected!")
})

```

#### LICENSE

Copyright 2019 Yusuke Shimizu

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
