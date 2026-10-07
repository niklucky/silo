/**
 * Password generator. Two styles: random characters for the most strength per
 * character, and pronounceable groups that are easy to type on a phone. Both
 * draw from crypto.getRandomValues without modulo bias, and report their
 * entropy exactly, so the strength shown is what the generator produced, not
 * a guess about the result.
 */

export type GeneratorStyle = "easy" | "random";

export interface Generated {
  style: GeneratorStyle;
  password: string;
  /** log2 of the number of passwords this style can produce. */
  bits: number;
}

export interface Strength {
  label: "weak" | "fair" | "strong" | "very strong";
  /** 1 to 4, for a four-segment meter. */
  level: 1 | 2 | 3 | 4;
}

const LOWER = "abcdefghijkmnopqrstuvwxyz"; // no l
const UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
const DIGITS = "23456789"; // no 0, 1
const SYMBOLS = "-_.!@#$%*+=?";
const RANDOM_LENGTH = 20;

const CONSONANTS = "bdfghjklmnprstvz";
const VOWELS = "aeiou";
const GROUPS = 4;
const SYLLABLES_PER_GROUP = 3;

export function generate(style: GeneratorStyle): Generated {
  return style === "random" ? randomPassword() : easyPassword();
}

export function strength(bits: number): Strength {
  if (bits < 50) return { label: "weak", level: 1 };
  if (bits < 70) return { label: "fair", level: 2 };
  if (bits < 100) return { label: "strong", level: 3 };
  return { label: "very strong", level: 4 };
}

/** 20 characters with at least one of each class; look-alikes (l, I, O, 0, 1) left out. */
function randomPassword(): Generated {
  const classes = [LOWER, UPPER, DIGITS, SYMBOLS];
  const alphabet = classes.join("");
  for (;;) {
    let password = "";
    for (let i = 0; i < RANDOM_LENGTH; i++) password += pick(alphabet);
    if (classes.every((set) => [...password].some((c) => set.includes(c)))) {
      // Rejection removes under 1% of the space; round down to stay honest.
      return { style: "random", password, bits: Math.floor(RANDOM_LENGTH * Math.log2(alphabet.length)) - 1 };
    }
  }
}

/** Like `Bakomi-tuvela-rosedu7-fanipo`: consonant-vowel syllables, one capital, one digit. */
function easyPassword(): Generated {
  const groups: string[] = [];
  for (let g = 0; g < GROUPS; g++) {
    let group = "";
    for (let s = 0; s < SYLLABLES_PER_GROUP; s++) group += pick(CONSONANTS) + pick(VOWELS);
    groups.push(group);
  }
  const capital = below(GROUPS);
  const digitAt = below(GROUPS);
  const shaped = groups.map((group, i) => {
    const cased = i === capital ? group.charAt(0).toUpperCase() + group.slice(1) : group;
    return i === digitAt ? cased + String(below(10)) : cased;
  });
  const syllableBits = GROUPS * SYLLABLES_PER_GROUP * Math.log2(CONSONANTS.length * VOWELS.length);
  const bits = Math.floor(syllableBits + Math.log2(GROUPS) + Math.log2(GROUPS * 10));
  return { style: "easy", password: shaped.join("-"), bits };
}

function pick(set: string): string {
  return set.charAt(below(set.length));
}

/** Uniform integer in [0, n), rejecting the biased tail of a 32-bit draw. */
function below(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    const draw = buf[0] ?? limit;
    if (draw < limit) return draw % n;
  }
}
