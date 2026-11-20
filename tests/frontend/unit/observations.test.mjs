import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeIndicator,
  observationType,
  observationLabel,
  observationSummary,
} from '../../../client/src/assets/features/graph/observations.js';

describe('observations mapping', () => {
  test('normalizeIndicator extracts host and strips IPv4 port', () => {
    assert.equal(normalizeIndicator('https://Example.COM/path?q=1'), 'example.com');
    assert.equal(normalizeIndicator('1.2.3.4:443'), '1.2.3.4');
  });

  test('normalizeIndicator keeps IPv6 intact', () => {
    assert.equal(normalizeIndicator('2a00:1450:4025:401::79'), '2a00:1450:4025:401::79');
    assert.equal(normalizeIndicator('[2a00:1450::1]:443'), '2a00:1450::1');
  });

  test('classifies sources and builds labels', () => {
    const ipinfo = { source: 'ipinfo', payload: { indicator: '1.1.1.1', asn: 'AS13335' } };
    const urlhaus = { source: 'urlhaus', payload: { indicator: 'evil.example', threat: 'malware_download' } };
    assert.equal(observationType(ipinfo), 'info');
    assert.equal(observationType(urlhaus), 'threat');
    assert.match(observationLabel(ipinfo), /1\.1\.1\.1/);
    assert.match(observationSummary(urlhaus), /malware_download/);
  });
});
