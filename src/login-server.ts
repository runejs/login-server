import { logger, ByteBuffer } from '@runejs/common';
import { parseServerConfig, SocketServer } from '@runejs/common/net';
import type { Socket } from 'node:net';
import BigInteger from 'bigi';
import * as bcrypt from 'bcrypt';

import { longToString } from './util';
import { loadPlayerSave } from './saves';

interface ServerConfig {
    loginServerHost: string;
    loginServerPort: number;
    rsaMod: string;
    rsaExp: string;
    checkCredentials: boolean;
    playerSavePath: string;
}

enum ConnectionStage {
    HANDSHAKE = 'handshake',
    ACTIVE = 'active',
}

/**
 * Codes for user login attempts that are sent back to the game client
 * to inform the user of the status of their login attempt.
 */
export enum LoginResponseCode {
    SUCCESS = 2,
    INVALID_CREDENTIALS = 3,
    ACCOUNT_DISABLED = 4,
    ALREADY_LOGGED_IN = 5,
    GAME_UPDATED = 6,
    WORLD_FULL = 7,
    LOGIN_SERVER_OFFLINE = 8,
    LOGIN_LIMIT_EXCEEDED = 9,
    BAD_SESSION_ID = 10,
    // @TODO the rest
}

class LoginServerConnection extends SocketServer {
    private readonly rsaModulus = BigInteger(
        this.loginServer.serverConfig.rsaMod,
    );
    private readonly rsaExponent = BigInteger(
        this.loginServer.serverConfig.rsaExp,
    );
    private connectionStage: ConnectionStage = ConnectionStage.HANDSHAKE;
    private serverKey: bigint;

    public constructor(
        private readonly loginServer: LoginServer,
        gameServerSocket: Socket,
    ) {
        super(gameServerSocket);
    }

    public initialHandshake(buffer: ByteBuffer): boolean {
        buffer.get('byte', 'u'); // Name hash

        this.serverKey = BigInt(Math.floor(Math.random() * 999999));

        // @TODO error cases

        const outputBuffer = new ByteBuffer(9);
        outputBuffer.put(0, 'byte'); // Initial server login response -> 0 for OK
        outputBuffer.put(this.serverKey, 'long');
        this.socket.write(outputBuffer);

        this.connectionStage = ConnectionStage.ACTIVE;

        return true;
    }

    public decodeMessage(buffer: ByteBuffer): void {
        const loginType = buffer.get('byte', 'u');

        if (loginType !== 16 && loginType !== 18) {
            throw new Error(`Invalid login type ${loginType}`);
        }

        let loginEncryptedSize = buffer.get('byte', 'u') - (36 + 1 + 1 + 2);

        if (loginEncryptedSize <= 0) {
            throw new Error(
                `Invalid login packet length ${loginEncryptedSize}`,
            );
        }

        const gameVersion = buffer.get('int');

        if (gameVersion !== 435) {
            throw new Error(`Invalid game version ${gameVersion}`);
        }

        const isLowDetail: boolean = buffer.get('byte') === 1;

        for (let i = 0; i < 13; i++) {
            buffer.get('int'); // Cache indices
            // @TODO validate these against the filestore
        }

        loginEncryptedSize--;

        const rsaBytes = buffer.get('byte', 'u');

        const encryptedBytes: Buffer = Buffer.alloc(rsaBytes);
        buffer.copy(encryptedBytes, 0, buffer.readerIndex);
        const decrypted = new ByteBuffer(
            BigInteger.fromBuffer(encryptedBytes)
                .modPow(this.rsaExponent, this.rsaModulus)
                .toBuffer(),
        );

        const blockId = decrypted.get('byte');

        if (blockId !== 10) {
            throw new Error(`Invalid block id ${blockId}`);
        }

        const clientKey1 = decrypted.get('int');
        const clientKey2 = decrypted.get('int');
        const incomingServerKey = BigInt(decrypted.get('long'));

        if (this.serverKey !== incomingServerKey) {
            throw new Error(
                `Server key mismatch - ${this.serverKey} !== ${incomingServerKey}`,
            );
        }

        const gameClientId = decrypted.get('int');
        const usernameLong = BigInt(decrypted.get('long'));
        const username = longToString(usernameLong);
        const password = decrypted.getString();

        logger.info(`Login request: ${username}/${password}`);

        const credentialsResponseCode = this.checkCredentials(
            username,
            password,
        );
        if (credentialsResponseCode === -1) {
            this.sendLogin(
                [clientKey1, clientKey2],
                gameClientId,
                username,
                password,
                isLowDetail,
            );
        } else {
            logger.info(
                `${username} attempted to login but received error code ${credentialsResponseCode}.`,
            );
            this.sendLoginResponse(credentialsResponseCode);
        }
    }

    public connectionDestroyed(): void {}

    /**
     * Logs a user in and notifies their game server of a successful login.
     * @param clientKeys The user's client keys (sent by the client).
     * @param gameClientId The user's game client ID (sent by the client).
     * @param username The user's username.
     * @param password The user's password.
     * @param isLowDetail Whether or not the user selected the "Low Detail" option.
     */
    private sendLogin(
        clientKeys: [number, number],
        gameClientId: number,
        username: string,
        password: string,
        isLowDetail: boolean,
    ): void {
        const outputBuffer = new ByteBuffer(400);
        outputBuffer.put(LoginResponseCode.SUCCESS);
        outputBuffer.put(clientKeys[0], 'int');
        outputBuffer.put(clientKeys[1], 'int');
        outputBuffer.put(gameClientId, 'int');
        outputBuffer.putString(username);
        outputBuffer.putString(bcrypt.hashSync(password, bcrypt.genSaltSync()));
        outputBuffer.put(isLowDetail ? 1 : 0);
        this.socket.write(outputBuffer.getSlice(0, outputBuffer.writerIndex));
    }

    /**
     * Sends a simple login response code to the game server.
     * @param responseCode The specific response code to send.
     */
    private sendLoginResponse(responseCode: number): void {
        const outputBuffer = new ByteBuffer(1);
        outputBuffer.put(responseCode, 'byte');
        this.socket.write(outputBuffer);
    }

    /**
     * Validates an incoming user's credentials and returns an error code if a problem occurs.
     * This also checks if the user is already online.
     * @param username The incoming user's username input.
     * @param password The incoming user's password input.
     */
    private checkCredentials(
        inputUsername: string,
        inputPassword: string,
    ): number {
        if (!this.loginServer.serverConfig.checkCredentials) {
            return -1;
        }

        if (!inputUsername || !inputPassword) {
            return LoginResponseCode.INVALID_CREDENTIALS;
        }

        const username = inputUsername.trim().toLowerCase();
        const password = inputPassword.trim();

        if (username === '' || password === '') {
            return LoginResponseCode.INVALID_CREDENTIALS;
        }

        const playerSave = loadPlayerSave(
            this.loginServer.serverConfig.playerSavePath,
            username,
        );
        if (playerSave) {
            const playerPasswordHash = playerSave.passwordHash;
            if (playerPasswordHash) {
                if (!bcrypt.compareSync(password, playerPasswordHash)) {
                    return LoginResponseCode.INVALID_CREDENTIALS;
                }
            } else if (this.loginServer.serverConfig.checkCredentials) {
                logger.warn(
                    `User ${username} has no password hash saved - their password will now be saved.`,
                );
            }
        }

        return -1;
    }
}

class LoginServer {
    public readonly serverConfig: ServerConfig;

    public constructor(configDir?: string) {
        this.serverConfig = parseServerConfig<ServerConfig>({ configDir });
    }
}

export const launchLoginServer = (configDir?: string) => {
    const loginServer = new LoginServer(configDir);
    const { loginServerHost, loginServerPort } = loginServer.serverConfig;
    SocketServer.launch<LoginServerConnection>(
        'Login Server',
        loginServerHost,
        loginServerPort,
        (socket) => new LoginServerConnection(loginServer, socket),
    );
};
