import { join } from 'node:path';
import { existsSync, readFileSync } from 'node:fs';
import { logger } from '@runejs/common';

interface PlayerSave {
    username: string;
    passwordHash: string;
}

export function loadPlayerSave(
    playerSaveDir: string,
    username: string,
): PlayerSave {
    const fileName = `${username.toLowerCase()}.json`;
    const filePath = join(playerSaveDir, fileName);

    if (!existsSync(filePath)) {
        return null;
    }

    const fileData = readFileSync(filePath, 'utf8');

    if (!fileData) {
        return null;
    }

    try {
        return JSON.parse(fileData) as PlayerSave;
    } catch (error) {
        logger.error(`Malformed player save data for ${username}.`);
        return null;
    }
}
