/**
 * iocRecall.ts - is an expected (ground-truth) IOC present in the stored IOC set?
 *
 * Expected values are plain strings, so `|` is ambiguous. In the real ground truth it is a delimiter in exactly one
 * place: the `user` entry (@ATTEMPTED_USER = "any of the attempted users", values joined with "|"). Everywhere else it
 * is part of the value (e.g. the TC-08 COMMAND_LINE `curl ... | base64 -d | bash`). So `|` is treated as an
 * alternatives delimiter ONLY for the user type; every other type is compared as one complete value. An exact
 * (whole-string) match always counts, so a user name that itself contains `|` is still found.
 */
export const ALTERNATIVES_DELIMITED_TYPES: readonly string[] = ["user"];

export function expectedIocAlternatives(expected: { type: string; value: string }): string[] {
  const whole = expected.value.toLowerCase();
  return ALTERNATIVES_DELIMITED_TYPES.includes(expected.type.toLowerCase()) ? [whole, ...whole.split("|")] : [whole];
}

export function isExpectedIocPresent(expected: { type: string; value: string }, stored: { iocValue: string }[]): boolean {
  const accepted = expectedIocAlternatives(expected);
  return stored.some((s) => accepted.includes(s.iocValue.toLowerCase()));
}
