import fs from 'node:fs';
import crypto from 'node:crypto';

export class TornWriteSimulator {
  /**
   * Simulates a power failure mid-record append by truncating the file mid-payload.
   */
  public static simulateTornRecordWrite(filePath: string, bytesToKeepFromLastRecord: number = 8): void {
    if (!fs.existsSync(filePath)) return;

    const fileBuf = fs.readFileSync(filePath);
    if (fileBuf.length <= 32) return;

    // Truncate the file slightly before the end to simulate power cut during write()
    const truncatedLength = Math.max(32, fileBuf.length - bytesToKeepFromLastRecord);
    fs.writeFileSync(filePath, fileBuf.subarray(0, truncatedLength));
  }

  /**
   * Simulates corrupted magic header due to torn file creation.
   */
  public static simulateTornHeader(filePath: string): void {
    const corruptedHeader = Buffer.alloc(32, 0x55);
    corruptedHeader.write('WDB:TORN_HEADER_CORRUPT', 0, 'utf8');
    fs.writeFileSync(filePath, corruptedHeader);
  }

  /**
   * Injects a bit-flip in the middle of a completed journal record.
   */
  public static injectBitFlip(filePath: string, byteOffsetFromEnd: number = 20): void {
    if (!fs.existsSync(filePath)) return;

    const fileBuf = fs.readFileSync(filePath);
    if (fileBuf.length <= byteOffsetFromEnd) return;

    const targetIdx = fileBuf.length - byteOffsetFromEnd;
    fileBuf[targetIdx] = (fileBuf[targetIdx] || 0) ^ 0xff; // Invert bits

    fs.writeFileSync(filePath, fileBuf);
  }
}
