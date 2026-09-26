import { checkGrounding } from '../src/domain/ai/aiGrounding';
test.each(['Observed 203.0.113.77.', 'Observed 2001:db8::2.', 'Observed attacker.security.', 'Domain malware.zip.', 'Host: phantom', 'Observed https://EXAMPLE.com/A', 'Observed PHANTOM-WORKSTATION', 'Contact intruder@example.com', 'Device aa:bb:cc:dd:ee:ff', 'Fetched ftp://example.com/payload'])('sentence punctuation and less common indicators cannot bypass grounding: %s', text => {
  expect(checkGrounding(text, ['https://example.com/a']).status).toBe('UNGROUNDED');
});
test.each(['PHANTOM-WORKSTATION', 'intruder@example.com', 'aa:bb:cc:dd:ee:ff', 'ftp://example.com/payload'])('accepts concrete indicators present in source: %s', value => {
  expect(checkGrounding(`Observed ${value}`, [value]).status).toBe('GROUNDED');
});
