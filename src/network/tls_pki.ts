import crypto from 'node:crypto';

export interface GeneratedTlsCert {
  certPem: string;
  privPem: string;
  keyPair: crypto.KeyPairSyncResult<string, string>;
}

export interface ClusterTlsPki {
  ca: GeneratedTlsCert;
  gateway: GeneratedTlsCert;
  agent: GeneratedTlsCert;
  validators: GeneratedTlsCert[];
  untrustedClient: GeneratedTlsCert;
}

function encodeLength(len: number): Buffer {
  if (len < 128) return Buffer.from([len]);
  const bytes: number[] = [];
  let temp = len;
  while (temp > 0) {
    bytes.unshift(temp & 0xff);
    temp >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function asn1Seq(bufs: Buffer[]): Buffer {
  const body = Buffer.concat(bufs);
  return Buffer.concat([Buffer.from([0x30]), encodeLength(body.length), body]);
}

function asn1Set(bufs: Buffer[]): Buffer {
  const body = Buffer.concat(bufs);
  return Buffer.concat([Buffer.from([0x31]), encodeLength(body.length), body]);
}

function asn1Oid(oidStr: string): Buffer {
  const parts = oidStr.split('.').map(Number);
  const bytes = [parts[0]! * 40 + parts[1]!];
  for (let i = 2; i < parts.length; i++) {
    let val = parts[i]!;
    const sub = [val & 0x7f];
    while ((val >>= 7) > 0) {
      sub.unshift(0x80 | (val & 0x7f));
    }
    bytes.push(...sub);
  }
  const body = Buffer.from(bytes);
  return Buffer.concat([Buffer.from([0x06]), encodeLength(body.length), body]);
}

function asn1Utf8String(str: string): Buffer {
  const buf = Buffer.from(str, 'utf8');
  return Buffer.concat([Buffer.from([0x0c]), encodeLength(buf.length), buf]);
}

function asn1Integer(num: bigint | number): Buffer {
  let bytes: number[] = [];
  let temp = BigInt(num);
  while (temp > 0n) {
    bytes.unshift(Number(temp & 0xffn));
    temp >>= 8n;
  }
  if (bytes.length === 0) bytes = [0];
  if (bytes[0]! >= 0x80) bytes.unshift(0);
  const body = Buffer.from(bytes);
  return Buffer.concat([Buffer.from([0x02]), encodeLength(body.length), body]);
}

function asn1UtcTime(d: Date): Buffer {
  const s =
    d.getUTCFullYear().toString().slice(2) +
    String(d.getUTCMonth() + 1).padStart(2, '0') +
    String(d.getUTCDate()).padStart(2, '0') +
    String(d.getUTCHours()).padStart(2, '0') +
    String(d.getUTCMinutes()).padStart(2, '0') +
    String(d.getUTCSeconds()).padStart(2, '0') +
    'Z';
  const buf = Buffer.from(s, 'ascii');
  return Buffer.concat([Buffer.from([0x17]), encodeLength(buf.length), buf]);
}

function asn1Name(cn: string): Buffer {
  const attrSeq = asn1Seq([asn1Oid('2.5.4.3'), asn1Utf8String(cn)]);
  return asn1Seq([asn1Set([attrSeq])]);
}

export function createTlsCertificate(
  commonName: string,
  isCA: boolean = false,
  issuerName?: string,
  issuerPrivateKey?: crypto.KeyObject
): GeneratedTlsCert {
  const kp = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { format: 'pem', type: 'spki' },
    privateKeyEncoding: { format: 'pem', type: 'pkcs8' },
  });

  const pubKeyObj = crypto.createPublicKey(kp.publicKey);
  const privKeyObj = crypto.createPrivateKey(kp.privateKey);
  const pubDer = pubKeyObj.export({ format: 'der', type: 'spki' });

  const sha256WithRSA = asn1Seq([asn1Oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00])]);
  const version = Buffer.from([0xa0, 0x03, 0x02, 0x01, 0x02]); // v3
  const serial = asn1Integer(Date.now() + Math.floor(Math.random() * 1000000));
  const issuer = asn1Name(issuerName || commonName);
  const now = new Date();
  const later = new Date(now.getTime() + 3650 * 86400000); // 10 years
  const validity = asn1Seq([asn1UtcTime(now), asn1UtcTime(later)]);
  const subject = asn1Name(commonName);
  const spki = pubDer;

  // SAN extension
  const sanOid = asn1Oid('2.5.29.17');
  const dNSName = (n: string) => Buffer.concat([Buffer.from([0x82]), encodeLength(Buffer.byteLength(n)), Buffer.from(n, 'utf8')]);
  const ipAddr = (ip: string) => Buffer.concat([Buffer.from([0x87]), encodeLength(4), Buffer.from(ip.split('.').map(Number))]);
  const sanSeq = asn1Seq([dNSName('localhost'), dNSName(commonName), ipAddr('127.0.0.1')]);
  const sanOctet = Buffer.concat([Buffer.from([0x04]), encodeLength(sanSeq.length), sanSeq]);
  const sanExt = asn1Seq([sanOid, sanOctet]);

  // Basic Constraints extension
  const basicConstraintsOid = asn1Oid('2.5.29.19');
  const bcSeq = isCA ? asn1Seq([Buffer.from([0x01, 0x01, 0xff])]) : asn1Seq([]);
  const bcOctet = Buffer.concat([Buffer.from([0x04]), encodeLength(bcSeq.length), bcSeq]);
  const bcExt = asn1Seq([basicConstraintsOid, Buffer.from([0x01, 0x01, 0xff]), bcOctet]);

  const extsSeq = asn1Seq(isCA ? [bcExt, sanExt] : [sanExt]);
  const exts = Buffer.concat([Buffer.from([0xa3]), encodeLength(extsSeq.length), extsSeq]);

  const tbs = asn1Seq([version, serial, sha256WithRSA, issuer, validity, subject, spki, exts]);
  const signingKey = issuerPrivateKey || privKeyObj;
  const sig = crypto.sign('sha256', tbs, signingKey);
  const sigBitString = Buffer.concat([Buffer.from([0x03]), encodeLength(sig.length + 1), Buffer.from([0x00]), sig]);

  const certDer = asn1Seq([tbs, sha256WithRSA, sigBitString]);
  const certPem =
    '-----BEGIN CERTIFICATE-----\n' +
    (certDer.toString('base64').match(/.{1,64}/g) || []).join('\n') +
    '\n-----END CERTIFICATE-----\n';

  return {
    certPem,
    privPem: kp.privateKey,
    keyPair: kp,
  };
}

export function generateClusterTlsPki(): ClusterTlsPki {
  const ca = createTlsCertificate('Wolverine Root CA', true);
  const caPrivKeyObj = crypto.createPrivateKey(ca.privPem);

  const gateway = createTlsCertificate('wolverine-gateway', false, 'Wolverine Root CA', caPrivKeyObj);
  const agent = createTlsCertificate('wolverine-agent', false, 'Wolverine Root CA', caPrivKeyObj);

  const validators: GeneratedTlsCert[] = [];
  for (let i = 1; i <= 5; i++) {
    validators.push(createTlsCertificate(`validator-0${i}`, false, 'Wolverine Root CA', caPrivKeyObj));
  }

  // Untrusted client signed by rogue CA
  const rogueCa = createTlsCertificate('Rogue Malicious CA', true);
  const rogueCaPrivKeyObj = crypto.createPrivateKey(rogueCa.privPem);
  const untrustedClient = createTlsCertificate('untrusted-client', false, 'Rogue Malicious CA', rogueCaPrivKeyObj);

  return {
    ca,
    gateway,
    agent,
    validators,
    untrustedClient,
  };
}
