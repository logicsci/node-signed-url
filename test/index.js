const expect = require('chai').expect;
const sinon = require('sinon');
const signer = require('../src')({ secret: 'hidden' });

describe('index', function () {
  let clock;

  beforeEach(function () {
    clock = sinon.useFakeTimers();
    clock.tick(1570710900371);
  });

  afterEach(function () {
    clock.restore();
  });

  it('should sign a url equal for ignore hostname', function () {
    const ignoreSigner = require('../src')({ secret: 'hidden', ignoreHostname: true });
    const url = 'https://www.example.com/test?a=1&b=2';
    const signed = ignoreSigner.sign(url, { method: 'get', ttl: 600 });
    const url2 = 'https://www.example.com/sub_test/test?a=1&b=2';
    const signed2 = ignoreSigner.sign(url2, { method: 'get', ttl: 600 });

    const urlParams = new URLSearchParams(signed);
    const urlParams2 = new URLSearchParams(signed2);
    expect(urlParams.get('hash')).to.equal(urlParams2.get('hash'));
  });

  it('should sign a url', function () {
    const url = 'https://www.example.com/test?a=1&b=2';
    const signed = signer.sign(url, { method: 'get', ttl: 600, ignoreHostname: true });
    expect(signed).to.equal('https://www.example.com/test?a=1&b=2&hash=L80zv1xETeBTSilIc0WisV3WHQOlSoaFFdovLcPmrUQ.MTU3MDcxMTUwMQ');
  });

  it('should verify a signed url', function () {
    const url = 'https://www.example.com/test?a=1&b=2';
    const signed = signer.sign(url, { method: 'get', ttl: 600 });
    console.log('signed 1: ' + signed);
    expect(signer.verify(signed, { method: 'get' })).to.be.true();
  });

  it('should not verify if the signature is invalid', function () {
    const url = 'https://www.example.com/test?a=1&b=2&hash=fubar';
    expect(signer.verify(url, { method: 'get' })).to.be.false();
  });

  it('should not verify if the signature has expired', function () {
    const url = 'https://www.example.com/test?a=1&b=2';
    const signed = signer.sign(url, { method: 'get', ttl: 600 });
    clock.tick(1570711900371);
    expect(signer.verify(signed, { method: 'get' })).to.be.false();
  });

  it('should not verify if the method is different', function () {
    const url = 'https://www.example.com/test?a=1&b=2';
    const signed = signer.sign(url, { method: 'put', ttl: 600 });
    expect(signer.verify(signed, { method: 'get' })).to.be.false();
  });

  it('should validate a request', function () {
    const next = sinon.stub();
    const req = {
      protocol: 'https',
      get: () => 'www.example.com',
      originalUrl: '/test?a=1&b=2&hash=L80zv1xETeBTSilIc0WisV3WHQOlSoaFFdovLcPmrUQ.MTU3MDcxMTUwMQ',
      method: 'GET'
    };
    const middleware = signer.verifyMiddleware;
    middleware(req, {}, next);
    expect(next).to.have.been.calledWithExactly(/* no arguments */);
  });

  it('should fail a request', function () {
    const next = sinon.stub();
    const req = {
      protocol: 'https',
      get: () => 'www.example.com',
      originalUrl: '/test?a=1&b=2&hash=fubar',
      method: 'GET'
    };
    const middleware = signer.verifyMiddleware;
    middleware(req, {}, next);
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error));
  });
});
