import { Storage } from "../storage/storage.ts";
import { generateAndStorePlatformKeyPair } from "../auth/keys.ts";

import type { Platform, ToolOptions } from "../types.ts";

export async function registerPlatform(storage: Storage, aesKey: CryptoKey, platform: Platform, options?: ToolOptions): Promise<Platform> {

  const existing = await storage.getPlatform(platform.url, platform.clientId);
  if (existing) {
    if (options?.debug) console.debug(`Existing platform for url ${platform.url} and clientId ${platform.clientId}`);
    return existing;
  }

  const kid = buildKeyId(platform);
  if (options?.debug) console.debug(`KID: ${kid}`);
  await generateAndStorePlatformKeyPair(kid, storage, aesKey);

  await storage.savePlatform(platform);
  return platform;
}

/**
 * Delete a platform. The platform will be marked as inactive but the data will be
 * left in the storage.
 *
 * @param {string} url The url, or iss, of the plaform to be deleted.
 * @param {string} clientId The clientId of the platform to be deleted.
 *
 * @return {Promise} A promise which will be fulfilled when the deletion has completed
 */
export async function deletePlatform(storage: Storage, url: string, clientId: string): Promise<void> {
  await storage.setPlatformActive(url, clientId, false);
}

export const buildKeyId = (platform: Platform): string => `${platform.url}\$\$${platform.clientId}`;
