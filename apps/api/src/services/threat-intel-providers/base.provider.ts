import {
  NormalizedIndicator,
  ThreatIntelIndicatorType,
  ThreatIntelProviderResult,
} from '@cyberwatch/shared';

export interface ThreatIntelligenceProvider {
  readonly id: string;
  readonly name: string;
  readonly supportedTypes: ThreatIntelIndicatorType[];

  isConfigured(): boolean;
  lookup(indicator: NormalizedIndicator): Promise<ThreatIntelProviderResult>;
}

export function sanitizeMetadata(data: any): Record<string, unknown> {
  if (!data || typeof data !== 'object') return {};
  try {
    const serialized = JSON.stringify(data, (key, value) => {
      // Redact sensitive headers, API keys, tokens
      const lower = key.toLowerCase();
      if (
        lower.includes('key') ||
        lower.includes('token') ||
        lower.includes('secret') ||
        lower.includes('authorization') ||
        lower.includes('password') ||
        lower.includes('cookie')
      ) {
        return '[REDACTED]';
      }
      return value;
    });
    return JSON.parse(serialized);
  } catch {
    return { sanitized: true };
  }
}
