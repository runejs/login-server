const VALID_CHARS = [
    '_',
    'a',
    'b',
    'c',
    'd',
    'e',
    'f',
    'g',
    'h',
    'i',
    'j',
    'k',
    'l',
    'm',
    'n',
    'o',
    'p',
    'q',
    'r',
    's',
    't',
    'u',
    'v',
    'w',
    'x',
    'y',
    'z',
    '0',
    '1',
    '2',
    '3',
    '4',
    '5',
    '6',
    '7',
    '8',
    '9',
    '!',
    '@',
    '#',
    '$',
    '%',
    '^',
    '&',
    '*',
    '(',
    ')',
    '-',
    '+',
    '=',
    ':',
    ';',
    '.',
    '>',
    '<',
    ',',
    '"',
    '[',
    ']',
    '|',
    '?',
    '/',
    '`',
];

export function longToString(input: bigint): string {
    let ac = '';
    while (input !== BigInt(0)) {
        const l1 = input;
        const nameLong = BigInt(input) / BigInt(37);
        ac +=
            VALID_CHARS[
                Number.parseInt(l1.toString()) -
                    Number.parseInt(nameLong.toString()) * 37
            ];
    }

    return ac.split('').reverse().join('');
}
