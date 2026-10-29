import * as dns from 'node:dns/promises';
import { getRegistrableDomain, isPrivateOrReservedIp } from './scan.service';

export interface DnsRecordsCollection {
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: Array<{ exchange: string; priority: number }>;
  ns: string[];
  txt: string[];
}

export interface DomainIntelligenceResult {
  domain: string;
  hostname: string;
  isDirectIp: boolean;
  isPrivate: boolean;

  // Domain Registration / RDAP
  registrar?: string;
  registrationDate?: string;
  expirationDate?: string;
  updatedDate?: string;
  domainAgeDays?: number;
  domainAgeFormatted?: string;
  isNewlyRegistered: boolean;
  domainStatus: string[];
  nameservers: string[];

  // Real DNS Records
  dnsRecords: DnsRecordsCollection;
  dnsResolved: boolean;
  dnsError?: string;

  rdapStatus: 'OBSERVED' | 'NOT AVAILABLE' | 'LOOKUP_FAILED';
  rdapSource?: string;
  details: string;
}

export class DomainIntelligenceService {
  /**
   * Perform comprehensive DNS resolution and authoritative RDAP query.
   * NEVER fabricates fake data — returns NOT AVAILABLE when unobserved.
   */
  public async analyzeDomain(hostname: string, targetRegistrableDomain?: string): Promise<DomainIntelligenceResult> {
    const cleanHost = (hostname || '').trim().toLowerCase();
    const isDirectIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(cleanHost) || cleanHost.includes(':');
    const isPrivate = isDirectIp ? isPrivateOrReservedIp(cleanHost) : false;
    const domain = targetRegistrableDomain || getRegistrableDomain(cleanHost) || cleanHost;

    const dnsRecords: DnsRecordsCollection = {
      a: [],
      aaaa: [],
      cname: [],
      mx: [],
      ns: [],
      txt: [],
    };

    let dnsResolved = false;
    let dnsError: string | undefined = undefined;

    // 1. If Direct IP or Private, skip external DNS / RDAP queries for SSRF safety
    if (isDirectIp || isPrivate || cleanHost === 'localhost' || cleanHost.endsWith('.localhost')) {
      if (isDirectIp) {
        if (cleanHost.includes(':')) {
          dnsRecords.aaaa.push(cleanHost);
        } else {
          dnsRecords.a.push(cleanHost);
        }
      }
      return {
        domain,
        hostname: cleanHost,
        isDirectIp,
        isPrivate: isPrivate || cleanHost === 'localhost',
        isNewlyRegistered: false,
        domainStatus: [],
        nameservers: [],
        dnsRecords,
        dnsResolved: isDirectIp,
        rdapStatus: 'NOT AVAILABLE',
        details: isPrivate
          ? 'Private or internal network address target. External RDAP registration lookup skipped.'
          : 'Direct IP address destination. RDAP domain registration is not applicable to raw IP targets.',
      };
    }

    // 2. Resolve DNS Records in Parallel (A, AAAA, CNAME, MX, NS, TXT)
    try {
      const [aRes, aaaaRes, cnameRes, mxRes, nsRes, txtRes] = await Promise.allSettled([
        dns.resolve4(cleanHost),
        dns.resolve6(cleanHost),
        dns.resolveCname(cleanHost),
        dns.resolveMx(domain),
        dns.resolveNs(domain),
        dns.resolveTxt(cleanHost),
      ]);

      if (aRes.status === 'fulfilled') {
        dnsRecords.a = Array.from(new Set(aRes.value));
        dnsResolved = true;
      }
      if (aaaaRes.status === 'fulfilled') {
        dnsRecords.aaaa = Array.from(new Set(aaaaRes.value));
        dnsResolved = true;
      }
      if (cnameRes.status === 'fulfilled') {
        dnsRecords.cname = Array.from(new Set(cnameRes.value));
      }
      if (mxRes.status === 'fulfilled') {
        dnsRecords.mx = mxRes.value.map((m) => ({ exchange: m.exchange, priority: m.priority }));
      }
      if (nsRes.status === 'fulfilled') {
        dnsRecords.ns = Array.from(new Set(nsRes.value));
      }
      if (txtRes.status === 'fulfilled') {
        dnsRecords.txt = txtRes.value.map((chunks) => chunks.join(''));
      }

      // Check if host resolved to private IP (SSRF)
      const hasPrivateIp = [...dnsRecords.a, ...dnsRecords.aaaa].some((ip) => isPrivateOrReservedIp(ip));
      if (hasPrivateIp) {
        return {
          domain,
          hostname: cleanHost,
          isDirectIp: false,
          isPrivate: true,
          isNewlyRegistered: false,
          domainStatus: [],
          nameservers: dnsRecords.ns,
          dnsRecords,
          dnsResolved: true,
          rdapStatus: 'NOT AVAILABLE',
          details: 'Domain resolved to private internal network range (SSRF Protection).',
        };
      }
    } catch (err: any) {
      dnsError = err.message || 'DNS resolution failed';
    }

    // 3. Query RDAP for Domain Registration Info (rdap.org lookup with strict timeout)
    let registrar: string | undefined = undefined;
    let registrationDate: string | undefined = undefined;
    let expirationDate: string | undefined = undefined;
    let updatedDate: string | undefined = undefined;
    let domainAgeDays: number | undefined = undefined;
    let domainAgeFormatted: string | undefined = undefined;
    let isNewlyRegistered = false;
    let domainStatus: string[] = [];
    const rdapNameservers: string[] = [];
    let rdapStatus: 'OBSERVED' | 'NOT AVAILABLE' | 'LOOKUP_FAILED' = 'NOT AVAILABLE';
    let rdapSource: string | undefined = undefined;

    if (domain && domain.includes('.')) {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 4000);

        const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
        const res = await fetch(rdapUrl, {
          method: 'GET',
          headers: {
            'Accept': 'application/rdap+json, application/json',
            'User-Agent': 'CyberWatch-RDAP-Client/2.0',
          },
          signal: controller.signal,
        });

        clearTimeout(timeout);

        if (res.ok) {
          const rdapData = await res.json() as any;
          rdapStatus = 'OBSERVED';
          rdapSource = 'RDAP (ICANN / Authoritative Registry)';

          // Extract Status
          if (Array.isArray(rdapData.status)) {
            domainStatus = rdapData.status.map(String);
          }

          // Extract Registrar entity
          if (Array.isArray(rdapData.entities)) {
            const registrarEntity = rdapData.entities.find((e: any) =>
              Array.isArray(e.roles) && e.roles.some((r: string) => r.toLowerCase() === 'registrar')
            );
            if (registrarEntity) {
              if (registrarEntity.vcardArray && Array.isArray(registrarEntity.vcardArray[1])) {
                const fnEntry = registrarEntity.vcardArray[1].find((prop: any) => Array.isArray(prop) && prop[0] === 'fn');
                if (fnEntry && fnEntry[3]) {
                  registrar = String(fnEntry[3]);
                }
              }
              if (!registrar && registrarEntity.handle) {
                registrar = String(registrarEntity.handle);
              }
              if (!registrar && registrarEntity.legalName) {
                registrar = String(registrarEntity.legalName);
              }
            }
          }

          // Extract Events (Registration, Expiration, Last Changed)
          if (Array.isArray(rdapData.events)) {
            for (const ev of rdapData.events) {
              const action = (ev.eventAction || '').toLowerCase();
              const dateStr = ev.eventDate ? String(ev.eventDate) : undefined;
              if (!dateStr) continue;

              if (action === 'registration' || action === 'created' || action === 'transfer') {
                if (!registrationDate) registrationDate = dateStr;
              } else if (action === 'expiration' || action === 'expires') {
                if (!expirationDate) expirationDate = dateStr;
              } else if (action === 'last changed' || action === 'last update' || action === 'updated') {
                if (!updatedDate) updatedDate = dateStr;
              }
            }
          }

          // Extract Nameservers
          if (Array.isArray(rdapData.nameservers)) {
            for (const ns of rdapData.nameservers) {
              const name = ns.ldhName || ns.handle;
              if (name && typeof name === 'string') {
                rdapNameservers.push(name.toLowerCase());
              }
            }
          }

          // Calculate Domain Age
          if (registrationDate) {
            const createdTime = new Date(registrationDate).getTime();
            const now = Date.now();
            if (!isNaN(createdTime) && createdTime < now) {
              domainAgeDays = Math.floor((now - createdTime) / (1000 * 60 * 60 * 24));
              isNewlyRegistered = domainAgeDays < 30;

              if (domainAgeDays >= 365) {
                const years = (domainAgeDays / 365.25).toFixed(1);
                domainAgeFormatted = `${domainAgeDays.toLocaleString()} days (${years} years)`;
              } else if (domainAgeDays >= 30) {
                const months = (domainAgeDays / 30.4).toFixed(1);
                domainAgeFormatted = `${domainAgeDays} days (${months} months)`;
              } else {
                domainAgeFormatted = `${domainAgeDays} day${domainAgeDays === 1 ? '' : 's'} (Newly Registered)`;
              }
            }
          }
        } else if (res.status === 404) {
          rdapStatus = 'NOT AVAILABLE';
        } else {
          rdapStatus = 'LOOKUP_FAILED';
        }
      } catch {
        rdapStatus = 'LOOKUP_FAILED';
      }
    }

    const combinedNameservers = Array.from(new Set([...dnsRecords.ns, ...rdapNameservers]));

    let details = '';
    if (rdapStatus === 'OBSERVED' && domainAgeFormatted) {
      details = `Domain ${domain} registered with ${registrar || 'Authoritative Registrar'}, age: ${domainAgeFormatted}.`;
    } else if (dnsResolved) {
      details = `Domain ${domain} resolved to ${dnsRecords.a.length} IPv4 / ${dnsRecords.aaaa.length} IPv6 record(s). RDAP registration data not publicly published.`;
    } else {
      details = `Domain intelligence query completed for ${domain}.`;
    }

    return {
      domain,
      hostname: cleanHost,
      isDirectIp: false,
      isPrivate: false,
      registrar,
      registrationDate,
      expirationDate,
      updatedDate,
      domainAgeDays,
      domainAgeFormatted,
      isNewlyRegistered,
      domainStatus,
      nameservers: combinedNameservers,
      dnsRecords,
      dnsResolved,
      dnsError,
      rdapStatus,
      rdapSource,
      details,
    };
  }
}

export const domainIntelligenceService = new DomainIntelligenceService();
