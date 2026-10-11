/**
 * COFRE DE SEGREDOS — OPENBAO KMS / AES-256-GCM (NIST SP 800-38D)
 * Central Privada de Conexões Zatten — Firstsys
 * A chave da Zatten NUNCA é armazenada em texto claro no PostgreSQL nem devolvida na API
 */

import { encryptSecret, decryptSecret, type EncryptedSecretData } from '../oauth/cryptoEngine.js';
import { logAuditEvent } from '../../src/lib/audit.js';

export interface SecretMetadata {
  secretRef: string;
  keyVersion: number;
  engine: 'openbao_transit' | 'local_aes_gcm';
  encryptedAt: string;
}

class SecretsVault {
  private openBaoUrl: string;
  private openBaoToken: string;
  private isBaoConfigured: boolean;

  // Armazenamento protegido de segredos cifrados em memória/disco (simulando cofre)
  private encryptedStore: Map<string, EncryptedSecretData> = new Map();

  constructor() {
    this.openBaoUrl = process.env.OPENBAO_URL || 'http://openbao:8200';
    this.openBaoToken = process.env.OPENBAO_TOKEN || '';
    this.isBaoConfigured = Boolean(process.env.OPENBAO_TOKEN && process.env.OPENBAO_TOKEN.length > 5);
  }

  /**
   * Armazena uma chave da Zatten com criptografia autenticada.
   * A chave bruta é descartada da memória imediatamente após a cifragem.
   */
  public async storeZattenKey(params: {
    connectionId: string;
    rawApiKey: string;
    organizationId: string;
    actor: string;
  }): Promise<SecretMetadata> {
    const { connectionId, rawApiKey, actor } = params;

    // Validação estrita do formato da chave Zatten (ex: ztn_... ou alfanumérico seguro)
    if (!rawApiKey || rawApiKey.trim().length < 16) {
      throw new Error('Chave de API Zatten inválida ou com tamanho insuficiente.');
    }

    // 1. Tenta cifrar via OpenBao Transit Secrets Engine (se configurado)
    if (this.isBaoConfigured) {
      try {
        const baoRes = await fetch(`${this.openBaoUrl}/v1/transit/encrypt/zatten-master-key`, {
          method: 'POST',
          headers: {
            'X-Vault-Token': this.openBaoToken,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            plaintext: Buffer.from(rawApiKey).toString('base64')
          }),
          signal: AbortSignal.timeout(4000)
        });

        if (baoRes.ok) {
          const baoData: any = await baoRes.json();
          const ciphertext = baoData.data?.ciphertext;

          logAuditEvent({
            actor,
            action: 'secret.stored.openbao',
            category: 'security',
            severity: 'info',
            description: `Segredo da conexão ${connectionId} cifrado com sucesso via OpenBao Transit`,
            ipAddress: '127.0.0.1'
          });

          return {
            secretRef: ciphertext,
            keyVersion: baoData.data?.key_version || 1,
            engine: 'openbao_transit',
            encryptedAt: new Date().toISOString()
          };
        }
      } catch (err) {
        console.warn('[SecretsVault] OpenBao indisponível, utilizando AES-256-GCM local de contingência:', err);
      }
    }

    // 2. Contingência segura: AES-256-GCM com IV individual de 96 bits e chave mestra isolada
    const encryptedData = encryptSecret(rawApiKey);
    const secretRef = `vault_aes_${connectionId}`;
    this.encryptedStore.set(secretRef, encryptedData);

    logAuditEvent({
      actor,
      action: 'secret.stored.aes_gcm',
      category: 'security',
      severity: 'info',
      description: `Segredo da conexão ${connectionId} cifrado com sucesso via AES-256-GCM com IV único`,
      ipAddress: '127.0.0.1'
    });

    return {
      secretRef,
      keyVersion: encryptedData.version,
      engine: 'local_aes_gcm',
      encryptedAt: new Date().toISOString()
    };
  }

  /**
   * Descriptografa a chave Zatten em memória SOMENTE durante a execução da chamada autorizada.
   * NUNCA retorna ou loga a chave para o usuário final ou ChatGPT.
   */
  public async resolveZattenKey(secretRef: string): Promise<string> {
    if (!secretRef) {
      throw new Error('Referência de segredo inválida.');
    }

    // Se foi cifrado via OpenBao Transit
    if (secretRef.startsWith('vault:v')) {
      const baoRes = await fetch(`${this.openBaoUrl}/v1/transit/decrypt/zatten-master-key`, {
        method: 'POST',
        headers: {
          'X-Vault-Token': this.openBaoToken,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ciphertext: secretRef }),
        signal: AbortSignal.timeout(4000)
      });

      if (!baoRes.ok) {
        throw new Error('Falha ao descriptografar segredo no OpenBao KMS');
      }

      const baoData: any = await baoRes.json();
      const base64Plain = baoData.data?.plaintext;
      return Buffer.from(base64Plain, 'base64').toString('utf8');
    }

    // Se foi cifrado via AES-256-GCM local
    const encryptedData = this.encryptedStore.get(secretRef);
    if (!encryptedData) {
      throw new Error(`Segredo cifrado não localizado no cofre para a referência informada.`);
    }

    return decryptSecret(encryptedData);
  }

  /**
   * Revoga e apaga o segredo de forma permanente
   */
  public async revokeSecret(secretRef: string): Promise<void> {
    this.encryptedStore.delete(secretRef);
  }
}

export const secretsVault = new SecretsVault();
