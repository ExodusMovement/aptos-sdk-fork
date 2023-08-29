// Copyright © Aptos Foundation
// SPDX-License-Identifier: Apache-2.0

import {
    AccountAddress,
    EntryFunctionABI,
    FeePayerRawTransaction, Identifier,
    MultiAgentRawTransaction,
    SignedTransaction,
    SigningMessage,
    TransactionArgument,
    TransactionAuthenticatorMultiEd25519,
    TransactionPayload,
    TransactionPayloadEntryFunction, TransactionPayloadScript,
    TransactionScriptABI, TypeTagParser,
    ChainId, EntryFunction, Script, Ed25519PublicKey, TransactionAuthenticatorEd25519
} from "../aptos_types";
import {Ed25519Signature} from "../aptos_types";
import {MultiEd25519PublicKey, MultiEd25519Signature} from "../aptos_types";
import {ScriptABI} from "../aptos_types";
import {bcsToBytes, Bytes, Deserializer, Serializer, Uint64, Uint8} from "../bcs";
import {DEFAULT_MAX_GAS_AMOUNT, DEFAULT_TXN_EXP_SEC_FROM_NOW, HexString, MaybeHexString} from "../utils";
import {RawTransaction} from "../aptos_types";
import { sha3_256 as sha3Hash } from "@noble/hashes/sha3";
import {argToTransactionArgument, serializeArg} from "./builder_utils";

const RAW_TRANSACTION_SALT = "APTOS::RawTransaction";
const RAW_TRANSACTION_WITH_DATA_SALT = "APTOS::RawTransactionWithData";

export type SigningFn = (txn: SigningMessage) => Ed25519Signature | MultiEd25519Signature;
export type AnyRawTransaction = RawTransaction | MultiAgentRawTransaction | FeePayerRawTransaction;

export class TransactionBuilder<F extends SigningFn> {
    protected readonly signingFunction: F;

    constructor(signingFunction: F, public readonly rawTxnBuilder?: TransactionBuilderABI) {
        this.signingFunction = signingFunction;
    }

    /**
     * Builds a RawTransaction. Relays the call to TransactionBuilderABI.build
     * @param func
     * @param ty_tags
     * @param args
     */
    build(func: string, ty_tags: string[], args: any[]): RawTransaction {
        if (!this.rawTxnBuilder) {
            throw new Error("this.rawTxnBuilder doesn't exist.");
        }

        return this.rawTxnBuilder.build(func, ty_tags, args);
    }

    /** Generates a Signing Message out of a raw transaction. */
    static getSigningMessage(rawTxn: AnyRawTransaction): SigningMessage {
        const hash = sha3Hash.create();
        if (rawTxn instanceof RawTransaction) {
            hash.update(RAW_TRANSACTION_SALT);
        } else if (rawTxn instanceof MultiAgentRawTransaction) {
            hash.update(RAW_TRANSACTION_WITH_DATA_SALT);
        } else if (rawTxn instanceof FeePayerRawTransaction) {
            hash.update(RAW_TRANSACTION_WITH_DATA_SALT);
        } else {
            throw new Error("Unknown transaction type.");
        }

        const prefix = hash.digest();

        const body = bcsToBytes(rawTxn);

        const mergedArray = new Uint8Array(prefix.length + body.length);
        mergedArray.set(prefix);
        mergedArray.set(body, prefix.length);

        return mergedArray;
    }
}

/**
 * Provides signing method for signing a raw transaction with single public key.
 */
export class TransactionBuilderEd25519 extends TransactionBuilder<SigningFn> {
    private readonly publicKey: Uint8Array;

    constructor(signingFunction: SigningFn, publicKey: Uint8Array, rawTxnBuilder?: TransactionBuilderABI) {
        super(signingFunction, rawTxnBuilder);
        this.publicKey = publicKey;
    }

    rawToSigned(rawTxn: RawTransaction): SignedTransaction {
        const signingMessage = TransactionBuilder.getSigningMessage(rawTxn);
        const signature = this.signingFunction(signingMessage);

        const authenticator = new TransactionAuthenticatorEd25519(
            new Ed25519PublicKey(this.publicKey),
            signature as Ed25519Signature,
        );

        return new SignedTransaction(rawTxn, authenticator);
    }

    /** Signs a raw transaction and returns a bcs serialized transaction. */
    sign(rawTxn: RawTransaction): Bytes {
        return bcsToBytes(this.rawToSigned(rawTxn));
    }
}

export class TransactionBuilderMultiEd25519 extends TransactionBuilder<SigningFn> {
    private readonly publicKey: MultiEd25519PublicKey;

    constructor(signingFunction: SigningFn, publicKey: MultiEd25519PublicKey) {
        super(signingFunction);
        this.publicKey = publicKey;
    }

    rawToSigned(rawTxn: RawTransaction): SignedTransaction {
        const signingMessage = TransactionBuilder.getSigningMessage(rawTxn);
        const signature = this.signingFunction(signingMessage);

        const authenticator = new TransactionAuthenticatorMultiEd25519(this.publicKey, signature as MultiEd25519Signature);

        return new SignedTransaction(rawTxn, authenticator);
    }

    /** Signs a raw transaction and returns a bcs serialized transaction. */
    sign(rawTxn: RawTransaction): Bytes {
        return bcsToBytes(this.rawToSigned(rawTxn));
    }
}

/**
 * Config for creating raw transactions.
 */
export interface ABIBuilderConfig {
    sender: MaybeHexString | AccountAddress;
    sequenceNumber: Uint64 | string;
    gasUnitPrice: Uint64 | string;
    maxGasAmount?: Uint64 | string;
    expSecFromNow?: number | string;
    chainId: Uint8 | string;
}

/**
 * Builds raw transactions based on ABI
 */
export class TransactionBuilderABI {
    private readonly abiMap: Map<string, ScriptABI>;

    private readonly builderConfig: Partial<ABIBuilderConfig>;

    /**
     * Constructs a TransactionBuilderABI instance
     * @param abis List of binary ABIs.
     * @param builderConfig Configs for creating a raw transaction.
     */
    constructor(abis: Bytes[], builderConfig?: ABIBuilderConfig) {
        this.abiMap = new Map<string, ScriptABI>();

        abis.forEach((abi) => {
            const deserializer = new Deserializer(abi);
            const scriptABI = ScriptABI.deserialize(deserializer);
            let k: string;
            if (scriptABI instanceof EntryFunctionABI) {
                const funcABI = scriptABI as EntryFunctionABI;
                const { address: addr, name: moduleName } = funcABI.module_name;
                k = `${HexString.fromUint8Array(addr.address).toShortString()}::${moduleName.value}::${funcABI.name}`;
            } else {
                const funcABI = scriptABI as TransactionScriptABI;
                k = funcABI.name;
            }

            if (this.abiMap.has(k)) {
                throw new Error("Found conflicting ABI interfaces");
            }

            this.abiMap.set(k, scriptABI);
        });

        this.builderConfig = {
            maxGasAmount: BigInt(DEFAULT_MAX_GAS_AMOUNT),
            expSecFromNow: DEFAULT_TXN_EXP_SEC_FROM_NOW,
            ...builderConfig,
        };
    }

    private static toBCSArgs(abiArgs: any[], args: any[]): Bytes[] {
        if (abiArgs.length !== args.length) {
            throw new Error("Wrong number of args provided.");
        }

        return args.map((arg, i) => {
            const serializer = new Serializer();
            serializeArg(arg, abiArgs[i].type_tag, serializer);
            return serializer.getBytes();
        });
    }

    private static toTransactionArguments(abiArgs: any[], args: any[]): TransactionArgument[] {
        if (abiArgs.length !== args.length) {
            throw new Error("Wrong number of args provided.");
        }

        return args.map((arg, i) => argToTransactionArgument(arg, abiArgs[i].type_tag));
    }

    setSequenceNumber(seqNumber: Uint64 | string) {
        this.builderConfig.sequenceNumber = BigInt(seqNumber);
    }

    /**
     * Builds a TransactionPayload. For dApps, chain ID and account sequence numbers are only known to the wallet.
     * Instead of building a RawTransaction (requires chainID and sequenceNumber), dApps can build a TransactionPayload
     * and pass the payload to the wallet for signing and sending.
     * @param func Fully qualified func names, e.g. 0x1::aptos_account::transfer
     * @param ty_tags TypeTag strings
     * @param args Function arguments
     * @returns TransactionPayload
     */
    buildTransactionPayload(func: string, ty_tags: string[], args: any[]): TransactionPayload {
        const typeTags = ty_tags.map((ty_arg) => new TypeTagParser(ty_arg).parseTypeTag());

        let payload: TransactionPayload;

        if (!this.abiMap.has(func)) {
            throw new Error(`Cannot find function: ${func}`);
        }

        const scriptABI = this.abiMap.get(func);

        if (scriptABI instanceof EntryFunctionABI) {
            const funcABI = scriptABI as EntryFunctionABI;
            const bcsArgs = TransactionBuilderABI.toBCSArgs(funcABI.args, args);
            payload = new TransactionPayloadEntryFunction(
                new EntryFunction(funcABI.module_name, new Identifier(funcABI.name), typeTags, bcsArgs),
            );
        } else if (scriptABI instanceof TransactionScriptABI) {
            const funcABI = scriptABI as TransactionScriptABI;
            const scriptArgs = TransactionBuilderABI.toTransactionArguments(funcABI.args, args);

            payload = new TransactionPayloadScript(new Script(funcABI.code, typeTags, scriptArgs));
        } else {
            /* istanbul ignore next */
            throw new Error("Unknown ABI format.");
        }

        return payload;
    }

    /**
     * Builds a RawTransaction
     * @param func Fully qualified func names, e.g. 0x1::aptos_account::transfer
     * @param ty_tags TypeTag strings.
     * @example Below are valid value examples
     * ```
     * // Structs are in format `AccountAddress::ModuleName::StructName`
     * 0x1::aptos_coin::AptosCoin
     * // Vectors are in format `vector<other_tag_string>`
     * vector<0x1::aptos_coin::AptosCoin>
     * bool
     * u8
     * u16
     * u32
     * u64
     * u128
     * u256
     * address
     * ```
     * @param args Function arguments
     * @returns RawTransaction
     */
    build(func: string, ty_tags: string[], args: any[]): RawTransaction {
        const { sender, sequenceNumber, gasUnitPrice, maxGasAmount, expSecFromNow, chainId } = this.builderConfig;

        if (!gasUnitPrice) {
            throw new Error("No gasUnitPrice provided.");
        }

        const senderAccount = sender instanceof AccountAddress ? sender : AccountAddress.fromHex(sender!);
        const expTimestampSec = BigInt(Math.floor(Date.now() / 1000) + Number(expSecFromNow));
        const payload = this.buildTransactionPayload(func, ty_tags, args);

        if (payload) {
            return new RawTransaction(
                senderAccount,
                BigInt(sequenceNumber!),
                payload,
                BigInt(maxGasAmount!),
                BigInt(gasUnitPrice!),
                expTimestampSec,
                new ChainId(Number(chainId)),
            );
        }

        throw new Error("Invalid ABI.");
    }
}
