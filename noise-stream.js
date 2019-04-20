/* !
* noise-stream.js - peer-to-peer communication encryption.
* Copyright (c) 2019, YusukeShimizu (MIT License).
 * Resources:
 *   https://github.com/lightningnetwork/lightning-rfc/blob/master/08-transport.md
 *
 * Parts of this software are based on hsd:
 *   brontide.js - peer-to-peer communication encryption.
 *   Copyright (c) 2018, Christopher Jeffrey (MIT License).
 */

'use strict';

const assert = require('bsert');
const Noise = require('lightning-noise');

/*
 * Constants
 */

const HEADER_SIZE = 20;
const ACT_ONE_SIZE = 50;
const ACT_TWO_SIZE = 50;
const ACT_THREE_SIZE = 66;
const MAX_MESSAGE = 8 * 1000 * 1000 + 9;

const ACT_NONE = 0;
const ACT_ONE = 1;
const ACT_TWO = 2;
const ACT_THREE = 3;
const ACT_DONE = 4;

/**
 * NoiseStream
 * @extends {Noise}
 */

class NoiseStream extends Noise {
  constructor() {
    super();
    this.socket = null;
    this.state = ACT_NONE;
    this.pending = [];
    this.total = 0;
    this.waiting = 0;
    this.hasSize = false;
    this.buffer = [];
    this.onData = data => this.feed(data);
    this.onConnect = () => this.start();
  }

  accept(socket, ourKey) {
    assert(!this.socket);
    assert(socket);
    this.socket = socket;
    this.init(false, ourKey);
    this.socket.on('data', this.onData);
    this.start();
    return this;
  }

  connect(socket, ourKey, theirKey) {
    assert(!this.socket);
    assert(socket);
    this.socket = socket;
    this.init(true, ourKey, theirKey);
    this.socket.on('connect', this.onConnect);
    this.socket.on('data', this.onData);
    return this;
  }

  start() {
    if (this.initiator) {
      this.state = ACT_TWO;
      this.waiting = ACT_TWO_SIZE;
      try {
        this.socket.write(this.genActOne());
      } catch (e) {
        this.destroy();
        this.emit('error', e);
        return this;
      }
    } else {
      this.state = ACT_ONE;
      this.waiting = ACT_ONE_SIZE;
    }
    return this;
  }

  unleash() {
    assert(this.state === ACT_DONE);

    for (const buf of this.buffer)
      this.write(buf);

    this.buffer.length = 0;

    return this;
  }

  destroy() {
    this.state = ACT_NONE;
    this.pending.length = 0;
    this.total = 0;
    this.waiting = 0;
    this.hasSize = false;
    this.buffer.length = 0;
    this.socket.removeListener('connect', this.onConnect);
    this.socket.removeListener('data', this.onData);
    return this;
  }

  write(data) {
    assert(Buffer.isBuffer(data));

    if (this.state === ACT_NONE)
      return false;

    if (this.state !== ACT_DONE) {
      this.buffer.push(data);
      return false;
    }

    assert(data.length <= 0xffffffff);

    const len = Buffer.allocUnsafe(4);
    len.writeUInt32LE(data.length, 0);

    let r = 0;

    const tag1 = this.sendCipher.encrypt(len);

    r |= !this.socket.write(len);
    r |= !this.socket.write(tag1);

    const tag2 = this.sendCipher.encrypt(data);

    r |= !this.socket.write(data);
    r |= !this.socket.write(tag2);

    return !r;
  }

  feed(data) {
    assert(Buffer.isBuffer(data));

    if (this.state === ACT_NONE)
      return;

    this.total += data.length;
    this.pending.push(data);

    while (this.total >= this.waiting) {
      const chunk = this.read(this.waiting);
      if (!this.parse(chunk))
        break;
    }
  }

  read(size) {
    assert((size >>> 0) === size);
    assert(this.total >= size, 'Reading too much.');

    if (size === 0)
      return Buffer.alloc(0);

    const pending = this.pending[0];

    if (pending.length > size) {
      const chunk = pending.slice(0, size);
      this.pending[0] = pending.slice(size);
      this.total -= chunk.length;
      return chunk;
    }

    if (pending.length === size) {
      const chunk = this.pending.shift();
      this.total -= chunk.length;
      return chunk;
    }

    const chunk = Buffer.allocUnsafe(size);

    let off = 0;

    while (off < chunk.length) {
      const pending = this.pending[0];
      const len = pending.copy(chunk, off);
      if (len === pending.length)
        this.pending.shift();
      else
        this.pending[0] = pending.slice(len);
      off += len;
    }

    assert.strictEqual(off, chunk.length);

    this.total -= chunk.length;

    return chunk;
  }

  parse(data) {
    assert(Buffer.isBuffer(data));

    try {
      this._parse(data);
      return true;
    } catch (e) {
      this.destroy();
      this.emit('error', e);
      return false;
    }
  }

  _parse(data) {
    if (this.initiator) {
      switch (this.state) {
        case ACT_TWO:
          this.recvActTwo(data);
          this.socket.write(this.genActThree());
          this.state = ACT_DONE;
          this.waiting = HEADER_SIZE;
          this.unleash();
          this.emit('connect');
          return;
        default:
          assert(this.state === ACT_DONE);
          break;
      }
    } else {
      switch (this.state) {
        case ACT_ONE:
          this.recvActOne(data);
          this.socket.write(this.genActTwo());
          this.state = ACT_THREE;
          this.waiting = ACT_THREE_SIZE;
          return;
        case ACT_THREE:
          this.recvActThree(data);
          this.state = ACT_DONE;
          this.waiting = HEADER_SIZE;
          this.unleash();
          this.emit('connect');
          return;
        default:
          assert(this.state === ACT_DONE);
          break;
      }
    }

    if (!this.hasSize) {
      assert(this.waiting === HEADER_SIZE);
      assert(data.length === HEADER_SIZE);

      const len = data.slice(0, 4);
      const tag = data.slice(4, 20);

      if (!this.recvCipher.decrypt(len, tag))
        throw new Error('Bad tag for header.');

      const size = len.readUInt32LE(0, true);

      if (size > MAX_MESSAGE)
        throw new Error('Bad packet size.');

      this.hasSize = true;
      this.waiting = size + 16;

      return;
    }

    const payload = data.slice(0, this.waiting - 16);
    const tag = data.slice(this.waiting - 16, this.waiting);

    this.hasSize = false;
    this.waiting = HEADER_SIZE;

    if (!this.recvCipher.decrypt(payload, tag))
      throw new Error('Bad tag for message.');

    this.emit('data', payload);
  }

  static fromInbound(socket, ourKey) {
    return new NoiseStream().accept(socket, ourKey);
  }

  static fromOutbound(socket, ourKey, theirKey) {
    return new NoiseStream().connect(socket, ourKey, theirKey);
  }
}

/*
 * Expose
 */

exports.NoiseStream = NoiseStream;
