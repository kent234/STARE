import { test } from 'node:test';
import assert from 'node:assert/strict';
import { detectPeopleKind } from '../../../client/src/assets/features/people/detect.js';

const cases = [
  ['john_doe', 'username'],
  ['john@example.com', 'email'],
  ['+7 (900) 123-45-67', 'phone'],
  ['John Doe', 'real_name'],
  ['https://vk.com/durov', 'profile_url'],
  ['github.com/torvalds', 'profile_url'],
  ['example.com', null],
  ['', null],
];

for (const [input, expected] of cases) {
  test(`detectPeopleKind(${JSON.stringify(input)}) -> ${expected}`, () => {
    assert.equal(detectPeopleKind(input), expected);
  });
}
