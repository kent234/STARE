// Детерминированный синтетический граф для замеров производительности.
// Форма совпадает с ответом /api/scan, поэтому используется тем же GraphVisualizer.

export function buildBenchData(totalNodes = 5000) {
  const target = 'bench.local';
  const nSub = Math.floor(totalNodes * 0.35);
  const nIP = Math.floor(totalNodes * 0.25);
  const nPorts = Math.floor(totalNodes * 0.2);
  const nObs = Math.max(0, totalNodes - nSub - nIP - nPorts - 2);

  const subdomains = [];
  const subdomainIPs = {};
  for (let i = 0; i < nSub; i++) {
    const sub = `host${i}.bench.local`;
    subdomains.push(sub);
    subdomainIPs[sub] = [`10.${(i >> 8) & 255}.${i & 255}.1`];
  }

  const ips = [];
  for (let i = 0; i < nIP; i++) {
    ips.push(`10.${(i >> 8) & 255}.${i & 255}.1`);
  }

  const ports = {};
  for (let i = 0; i < nPorts; i++) {
    ports[ips[i % ips.length]] = [80 + (i % 3) * 363];
  }

  const sources = ['ipinfo', 'shodan', 'abuseipdb', 'greynoise', 'urlhaus'];
  const observations = [];
  for (let i = 0; i < nObs; i++) {
    const source = sources[i % sources.length];
    observations.push({
      source,
      fetched_at: '2026-01-01T00:00:00Z',
      confidence_tier: i % 3 === 0 ? 'low' : 'high',
      payload: { indicator: ips[i % ips.length], threat: 'benchmark', score: i % 100 },
    });
  }

  return { target, subdomains, subdomain_ips: subdomainIPs, ips, ports, observations, vulnerabilities: [] };
}
