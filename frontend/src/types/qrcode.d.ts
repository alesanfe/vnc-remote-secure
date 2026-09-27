/** Minimal declaration for the optional `qrcode` package.
    QR rendering is a progressive enhancement — the share dialog
    works without the dependency (falls back to the text link).
    Install with: npm i qrcode @types/qrcode */
declare module 'qrcode' {
  export function toDataURL(
    text: string,
    opts?: { margin?: number; width?: number },
  ): Promise<string>;
}
