import crypto from 'crypto';

const algorithm = 'aes-256-cbc';

const secretKey = process.env.ENCRYPTION_KEY;

if (!secretKey || secretKey.length !== 32) {
  throw new Error('ENCRYPTION_KEY must be a 32-character string in your .env file');
}

export const encrypt = (text: string | null | undefined): string => {
  if (!text || typeof text !== 'string') {
    console.warn('Skipping encryption — invalid input:', text);
    return '';
  }

  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    algorithm,
    Buffer.from(secretKey),
    iv,
  );

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
};

export const decrypt = (encryptedText: string | null | undefined): string => {
    if (!encryptedText || typeof encryptedText !== 'string' || !encryptedText.includes(':')) {
      return '';
    }
  
    try {
      const [ivHex, encrypted] = encryptedText.split(':');
      const decipher = crypto.createDecipheriv(
        algorithm,
        Buffer.from(secretKey),
        Buffer.from(ivHex, 'hex'),
      );
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      return decrypted;
    } catch (err) {
      // Fix: narrow the type to Error
      if (err instanceof Error) {
        console.warn('Decryption failed:', err.message);
      } else {
        console.warn('Decryption failed with unknown error:', err);
      }
      return '';
    }
  };
  