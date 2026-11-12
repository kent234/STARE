// Маппинг Observation (бэкенд) → типы/подписи для графа и таблицы.

export const OBSERVATION_TYPES = ['threat', 'vuln', 'reputation', 'service', 'info'];

const SOURCE_TYPES = {
  urlhaus: 'threat',
  threatfox: 'threat',
  feodo: 'threat',
  osv: 'vuln',
  shodan: 'service',
  greynoise: 'reputation',
  abuseipdb: 'reputation',
  ipinfo: 'info',
};

const TYPE_LABELS = {
  threat: 'THREAT',
  vuln: 'VULN',
  reputation: 'REPUTATION',
  service: 'SERVICE',
  info: 'INFO',
};

export function normalizeIndicator(value) {
  if (!value) return '';
  let s = String(value).trim().toLowerCase();
  if (s.includes('://')) {
    try { s = new URL(s).hostname; } catch { /* keep as-is */ }
  }
  if (s.startsWith('[') && s.includes(']')) {
    s = s.slice(1, s.indexOf(']'));
  } else if (s.split(':').length === 2) {
    const colon = s.lastIndexOf(':');
    if (colon > 0 && /^\d+$/.test(s.slice(colon + 1))) s = s.slice(0, colon);
  }
  return s;
}

export function observationType(obs) {
  return SOURCE_TYPES[obs?.source] || 'info';
}

export function observationTypeLabel(obs) {
  return TYPE_LABELS[observationType(obs)] || 'INFO';
}

export function observationLabel(obs) {
  const p = obs?.payload || {};
  const ind = p.indicator || p.url || p.id || obs?.source || '?';
  switch (obs?.source) {
    case 'osv':
      return p.id || ind;
    case 'abuseipdb':
      return `${ind} · ${p.score ?? '?'}`;
    case 'greynoise':
      return `${ind} · ${p.classification || 'unknown'}`;
    case 'shodan':
      return `${ind} · ${(p.ports || []).length} ports`;
    case 'ipinfo':
      return `${ind} · ${p.asn || p.country || 'info'}`;
    case 'feodo':
      return `${ind}${p.port ? `:${p.port}` : ''}`;
    default:
      return ind;
  }
}

export function observationSummary(obs) {
  const p = obs?.payload || {};
  switch (obs?.source) {
    case 'urlhaus':
      return [p.threat, p.status, (p.tags || []).join(', ')].filter(Boolean).join(' · ');
    case 'threatfox':
      return [
        p.malware || p.malware_printable,
        p.threat_type,
        p.confidence_level != null ? `conf ${p.confidence_level}` : '',
      ].filter(Boolean).join(' · ');
    case 'feodo':
      return [p.malware, p.status, p.as_name || p.country].filter(Boolean).join(' · ');
    case 'osv':
      return [(p.severity || [])[0], p.summary].filter(Boolean).join(' · ');
    case 'shodan':
      return [
        p.org || p.isp,
        (p.vulns || []).length ? `${p.vulns.length} vulns` : '',
        (p.services || []).map(s => s.product).filter(Boolean).slice(0, 3).join(', '),
      ].filter(Boolean).join(' · ');
    case 'greynoise':
      return [p.classification, p.name, p.last_seen].filter(Boolean).join(' · ');
    case 'abuseipdb':
      return [
        `score ${p.score ?? '?'}`,
        `${p.total_reports ?? 0} reports`,
        p.isp || p.country,
      ].filter(Boolean).join(' · ');
    case 'ipinfo':
      return [p.as_name, p.city, p.country].filter(Boolean).join(' · ');
    default:
      return Object.keys(p).slice(0, 3).join(', ');
  }
}

export function observationDetails(obs) {
  return {
    Source: obs?.source,
    Type: observationTypeLabel(obs),
    Confidence: obs?.confidence_tier,
    FetchedAt: obs?.fetched_at,
    Payload: obs?.payload || {},
  };
}
