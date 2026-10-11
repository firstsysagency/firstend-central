import QRCode from 'qrcode';

/**
 * Converte string Base32 para Uint8Array de acordo com a RFC 4648.
 */
export function base32ToBytes(base32: string): Uint8Array {
  const clean = base32.toUpperCase().replace(/[^A-Z2-7]/g, '');
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

/**
 * Gera um segredo aleatório em formato Base32 criptograficamente seguro.
 */
export function generateTotpSecret(length: number = 20): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const randomBytes = new Uint8Array(length);
  crypto.getRandomValues(randomBytes);
  let secret = '';
  for (let i = 0; i < length; i++) {
    secret += alphabet[randomBytes[i] % alphabet.length];
  }
  return secret;
}

/**
 * Formata o segredo Base32 em grupos legíveis (ex: ABCD-EFGH-IJKL-MNOP).
 */
export function formatSecretKey(secret: string): string {
  return secret.replace(/(.{4})/g, '$1-').replace(/-$/, '');
}

/**
 * Gera uma URI padrão otpauth:// para aplicativos autenticadores (Google Authenticator, Authy, etc.).
 */
export function generateOtpAuthUrl(
  accountName: string,
  issuer: string,
  secretBase32: string
): string {
  const cleanSecret = secretBase32.replace(/[^A-Z2-7]/gi, '').toUpperCase();
  const encodedIssuer = encodeURIComponent(issuer);
  const encodedAccount = encodeURIComponent(accountName);
  return `otpauth://totp/${encodedIssuer}:${encodedAccount}?secret=${cleanSecret}&issuer=${encodedIssuer}&algorithm=SHA1&digits=6&period=30`;
}

/**
 * Renderiza o QR Code real em formato Data URL (imagem base64 PNG).
 */
export async function generateQrCodeDataUrl(otpAuthUrl: string): Promise<string> {
  return await QRCode.toDataURL(otpAuthUrl, {
    width: 250,
    margin: 2,
    color: {
      dark: '#000000',
      light: '#ffffff'
    },
    errorCorrectionLevel: 'M'
  });
}

/**
 * Calcula o código TOTP de 6 dígitos para um timestamp usando Web Crypto API nativa (RFC 6238 / RFC 4226).
 */
export async function generateTOTP(
  secretBase32: string,
  timestampMs: number = Date.now(),
  timeStepSeconds: number = 30
): Promise<string> {
  const keyBytes = base32ToBytes(secretBase32);
  const counter = Math.floor(timestampMs / 1000 / timeStepSeconds);

  // 8 bytes (64-bit integer big-endian)
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBytes as unknown as BufferSource,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign('HMAC', cryptoKey, buffer);
  const hmac = new Uint8Array(signature);

  // Truncamento dinâmico (RFC 4226)
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = binary % 1000000;
  return otp.toString().padStart(6, '0');
}

/**
 * Valida se o código de 6 dígitos fornecido é matematicamente válido para o segredo no momento atual.
 * Utiliza uma janela de tolerância de +/- 1 período (90 segundos no total) para compensar drift de relógio.
 */
export async function verifyTOTP(
  code: string,
  secretBase32: string,
  toleranceWindow: number = 4
): Promise<boolean> {
  const cleanCode = code.trim().replace(/\s/g, '');
  if (cleanCode.length !== 6 || !/^\d{6}$/.test(cleanCode)) {
    return false;
  }

  const cleanSecret = secretBase32.replace(/[^A-Z2-7]/gi, '').toUpperCase();
  const now = Date.now();
  const stepMs = 30 * 1000;

  for (let i = -toleranceWindow; i <= toleranceWindow; i++) {
    const generated = await generateTOTP(cleanSecret, now + i * stepMs);
    if (generated === cleanCode) {
      return true;
    }
  }

  return false;
}
