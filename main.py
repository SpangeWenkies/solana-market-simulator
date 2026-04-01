# create JSON holding transactions
# create chain that stores subsequent blocks
# create proof of stake algorithm
# create proof of history algorithm (maybe this is the same as verifying the chain is valid)
# create a way to add new transactions to the chain
# create a way to verify the chain is valid
# create a way to resolve conflicts between chains
# create a way to register nodes in the network
# create a way to reach consensus between nodes
# create a random transaction request loop to test the blockchain
# create transaction data using benford's law to simulate real-world transactions
# flask import is maybe not needed if we are just simulating the blockchain and not creating an API for it, but it could be useful for testing and interacting with the blockchain through HTTP requests. We can decide later if we want to keep it or not.
# create statistics such as total number of transactions, total value of transactions, average transaction value, etc. to analyze the blockchain data and see if it follows expected patterns.
# create a way to visualize the blockchain data, such as a graph or dashboard, to make it easier to understand and analyze the data.
# create a way to simulate different scenarios, such as a sudden increase in transactions, a network attack, or a change in the proof of stake algorithm, to see how the blockchain would react and adapt to these changes.
# implement the stateless architecture of solana, where each node only needs to store a small portion of the blockchain data and can quickly verify transactions without needing to download the entire chain.
# implement the schedular cost model of solana, where the cost of executing a transaction is based on the computational resources it requires, rather than a fixed fee. This can help to prevent spam and ensure that the network is used efficiently. it is equal to the signature cost + write lock cost + data bytes cost + programs execution cost + loaded accounts data size cost, not included is the runtime compute unit metering, which is a separate mechanism that limits the total amount of computational resources that can be used in a single transaction.
# create statistics such as the distribution of transaction values, the distribution of transaction fees, the distribution of transaction types, etc. to analyze the blockchain data and see if it follows expected patterns and to identify any anomalies or outliers in the data.
# create statistics such as total security budget, total security budget spent, average security budget per transaction, etc. to analyze the security of the blockchain and see if it is being used effectively to protect the network from attacks and malicious actors.
# optionally create players using smart contracts that can be executed on the blockchain to automate certain processes and create new functionalities. This can include things like decentralized finance (DeFi) applications, non-fungible tokens (NFTs), and other types of decentralized applications (dApps).

"""
First simulation layer for a Solana-like blockchain.

Use Python dictionaries as the in-memory source of truth.
Serialize them to JSON only when saving to disk, sending over HTTP, or printing.
"""

import hashlib
import json
import struct
import time
from copy import deepcopy
from typing import Any
from uuid import uuid4

# following constants come from solana docs and are simplified for this simulation

LAMPORTS_PER_SOL = 1_000_000_000

PACKET_DATA_SIZE = 1_232
MAX_ACCOUNTS_PER_TRANSACTION = 256
RUNTIME_MAX_ACCOUNTS_PER_TRANSACTION = 64
MAX_SIGNATURES_PER_PACKET = 12
MAX_PROCESSING_AGE = 150

DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT = 200_000
MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT = 3_000
MAX_COMPUTE_UNIT_LIMIT = 1_400_000
DEFAULT_LAMPORTS_PER_SIGNATURE = 5_000

MAX_ACCOUNT_DATA_LEN = 10_485_760
MAX_ACCOUNT_DATA_GROWTH_PER_TRANSACTION = 20_971_520
MAX_PERMITTED_DATA_INCREASE = 10_240
TRANSACTION_ACCOUNT_BASE_SIZE = 64
MAX_INSTRUCTION_DATA_LEN = 10_240
RENT_EXEMPT_RENT_EPOCH = (1 << 64) - 1

LEGACY_TRANSACTION_FORMAT = "legacy"
VERSIONED_V0_TRANSACTION_FORMAT = "v0"

# In Solana, a program is executable on-chain code. Transactions do not contain the logic
# themselves; they point to a program, and the runtime invokes that program on the provided
# accounts and instruction data.
# A program_id is the address of the on-chain program that should execute an instruction.
# It also appears as the owner of accounts whose data that program controls.
SYSTEM_PROGRAM_ID = "11111111111111111111111111111111"
STAKE_PROGRAM_ID = "Stake11111111111111111111111111111111111111"
VOTE_PROGRAM_ID = "Vote111111111111111111111111111111111111111"
CONFIG_PROGRAM_ID = "Config1111111111111111111111111111111111111"
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
ADDRESS_LOOKUP_TABLE_PROGRAM_ID = "AddressLookupTab1e1111111111111111111111111"
MARKET_SIM_PROGRAM_ID = "MarketSim1111111111111111111111111111111111"

# Builtin programs are core programs provided by the Solana runtime itself rather than by a
# user-deployed BPF/ELF program. Their scheduling and default compute treatment differ.
NON_MIGRATED_BUILTIN_PROGRAM_IDS = {
    SYSTEM_PROGRAM_ID,
    STAKE_PROGRAM_ID,
    VOTE_PROGRAM_ID,
    CONFIG_PROGRAM_ID,
    COMPUTE_BUDGET_PROGRAM_ID,
}


def now_ms() -> int:
    return int(time.time() * 1000)


def make_id(prefix: str) -> str:
    return f"{prefix}_{uuid4().hex}"


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def to_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True)


def make_address(name: str) -> str:
    # In Solana, an address is a public key that identifies an account or program.
    return f"addr_{name}"


def shortvec_length(value: int) -> int:
    """
    Return how many bytes Solana's shortvec variable-length integer encoding would use.

    Solana uses shortvec to encode lengths such as:
    - number of signatures
    - number of account keys
    - number of instructions
    - number of bytes in instruction data

    This helper does not serialize the value itself; it only tells us how many bytes the
    encoded length prefix would occupy so we can estimate transaction size.
    """
    if value < 0:
        raise ValueError("shortvec values must be non-negative")

    length = 1
    remaining = value >> 7
    while remaining:
        length += 1
        remaining >>= 7
    return length


def message_hash(message: dict[str, Any]) -> str:
    return stable_hash(message)


def simulate_signature_for_signer(message: dict[str, Any], signer_pubkey: str) -> str:
    # The payload is the exact byte string we pretend the signer is authorizing:
    # the compiled message bytes plus the signer's public key as a stand-in for signer-specific input.
    payload = json.dumps(message, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload += signer_pubkey.encode("utf-8")
    # We use blake2b here as a fast deterministic placeholder for a real Ed25519 signature.
    # This is not how Solana actually signs transactions; it is only a simulator-friendly stand-in.
    return hashlib.blake2b(payload, digest_size=64).hexdigest()


def transaction_hash(transaction: dict[str, Any]) -> str:
    return stable_hash(transaction)


def build_account_state(
    lamports: int,
    owner: str,
    data: list[int] | None = None,
    executable: bool = False,
    rent_epoch: int = RENT_EXEMPT_RENT_EPOCH,
) -> dict[str, Any]:
    """
    Build a simplified Solana account state object.

    In Solana, an account is the basic state container on the chain. Accounts can hold:
    - lamports, which are the native SOL-denominated balance units
    - arbitrary data bytes
    - an owner program_id that is allowed to interpret and mutate that data
    - an executable flag, which marks program accounts
    - a rent_epoch value used by the runtime's rent rules

    This function models the account fields documented by Solana in a Python dictionary so
    the simulator can attach balances and program-owned state to addresses.
    """
    raw_data = list(data or [])
    if len(raw_data) > MAX_ACCOUNT_DATA_LEN:
        raise ValueError("account data exceeds MAX_ACCOUNT_DATA_LEN")

    return {
        "lamports": lamports,
        "data": raw_data,
        "owner": owner,
        "executable": executable,
        "rent_epoch": rent_epoch,
    }


def build_account_meta(
    pubkey: str,
    is_signer: bool,
    is_writable: bool,
) -> dict[str, Any]:
    """
    Build AccountMeta-style data for an instruction.

    `pubkey` identifies which account the instruction touches.
    `is_signer` tells the runtime that this account must authorize the transaction.
    `is_writable` tells the runtime and scheduler that the instruction may modify this
    account's lamports or data, which affects account locking and message header counts.
    """
    return {
        "pubkey": pubkey,
        "is_signer": is_signer,
        "is_writable": is_writable,
    }


def build_instruction(
    program_id: str,
    accounts: list[dict[str, Any]],
    data: list[int],
) -> dict[str, Any]:
    """
    Build a simplified Solana instruction object.

    Arguments:
    - `program_id`: which on-chain program should execute this instruction
    - `accounts`: the AccountMeta entries the program will read from or write to
    - `data`: the raw instruction payload bytes interpreted by that program
    """
    if len(data) > MAX_INSTRUCTION_DATA_LEN:
        raise ValueError("instruction data exceeds MAX_INSTRUCTION_DATA_LEN")

    return {
        "program_id": program_id,
        "accounts": deepcopy(accounts),
        "data": list(data),
    }


def encode_system_transfer_data(lamports: int) -> list[int]:
    # We use `struct.pack` because Solana instruction data is binary, not JSON.
    # "<IQ" means little-endian: `I` = 4-byte unsigned int for the System Program
    # instruction discriminator, and `Q` = 8-byte unsigned long long for lamports.
    return list(struct.pack("<IQ", 2, lamports))


def encode_market_swap_data(side: str, amount_in: int, min_amount_out: int) -> list[int]:
    side_flag = 0 if side == "buy" else 1
    # We use `struct.pack` to produce deterministic binary instruction data.
    # "<BQQ" means little-endian: `B` = 1-byte side flag, then two `Q` values for the
    # 8-byte unsigned integers `amount_in` and `min_amount_out`.
    return list(struct.pack("<BQQ", side_flag, amount_in, min_amount_out))


def build_system_transfer_instruction(
    sender: str,
    recipient: str,
    lamports: int,
) -> dict[str, Any]:
    return build_instruction(
        program_id=SYSTEM_PROGRAM_ID,
        accounts=[
            build_account_meta(sender, is_signer=True, is_writable=True),
            build_account_meta(recipient, is_signer=False, is_writable=True),
        ],
        data=encode_system_transfer_data(lamports),
    )


def build_market_swap_instruction(
    trader: str,
    open_orders: str,
    event_queue: str,
    market_state: str,
    bids: str,
    asks: str,
    oracle: str,
    usdc_vault: str,
    sol_vault: str,
    amount_in: int,
    min_amount_out: int,
) -> dict[str, Any]:
    """
    Build a sample non-builtin market instruction for the simulator.

    This represents a trader submitting a swap against a market program. The instruction
    includes:
    - the trader authority account that signs
    - writable market-side state such as open orders and event queue
    - read-only market reference accounts such as bids, asks, and oracle
    - token vaults that the program may debit or credit
    - binary data describing the trade side and quantity constraints
    """
    return build_instruction(
        program_id=MARKET_SIM_PROGRAM_ID,
        accounts=[
            build_account_meta(trader, is_signer=True, is_writable=True),
            build_account_meta(open_orders, is_signer=False, is_writable=True),
            build_account_meta(event_queue, is_signer=False, is_writable=True),
            build_account_meta(market_state, is_signer=False, is_writable=False),
            build_account_meta(bids, is_signer=False, is_writable=False),
            build_account_meta(asks, is_signer=False, is_writable=False),
            build_account_meta(oracle, is_signer=False, is_writable=False),
            build_account_meta(usdc_vault, is_signer=False, is_writable=True),
            build_account_meta(sol_vault, is_signer=False, is_writable=True),
        ],
        data=encode_market_swap_data("buy", amount_in, min_amount_out),
    )


def build_address_lookup_table(account_key: str, addresses: list[str]) -> dict[str, Any]:
    return {
        "account_key": account_key,
        "addresses": list(addresses),
    }


def build_transaction_request(
    agent_id: str,
    fee_payer: str,
    instructions: list[dict[str, Any]],
    message_format: str = LEGACY_TRANSACTION_FORMAT,
    recent_blockhash: str | None = None,
    address_lookup_tables: list[dict[str, Any]] | None = None,
    requested_compute_unit_limit: int | None = None,
    compute_unit_price_micro_lamports: int = 0,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if message_format not in {LEGACY_TRANSACTION_FORMAT, VERSIONED_V0_TRANSACTION_FORMAT}:
        raise ValueError("message_format must be 'legacy' or 'v0'")

    return {
        "request_id": make_id("txreq"),
        "agent_id": agent_id,
        "submitted_at_ms": now_ms(),
        "message_format": message_format,
        "fee_payer": fee_payer,
        "instructions": deepcopy(instructions),
        "recent_blockhash": recent_blockhash
        or stable_hash({"agent_id": agent_id, "submitted_at_ms": now_ms()}),
        "address_lookup_tables": deepcopy(address_lookup_tables or []),
        "compute_budget": {
            "requested_compute_unit_limit": requested_compute_unit_limit,
            "compute_unit_price_micro_lamports": compute_unit_price_micro_lamports,
        },
        "metadata": metadata or {},
    }


def is_builtin_program(program_id: str) -> bool:
    """Return True when the instruction targets a runtime-provided builtin program."""
    return program_id in NON_MIGRATED_BUILTIN_PROGRAM_IDS


def default_compute_unit_limit(instructions: list[dict[str, Any]]) -> int:
    total = 0
    for instruction in instructions:
        if is_builtin_program(instruction["program_id"]):
            total += MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT
        else:
            total += DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT
    return min(total, MAX_COMPUTE_UNIT_LIMIT)


def effective_compute_unit_limit(request_tx: dict[str, Any]) -> int:
    requested = request_tx["compute_budget"]["requested_compute_unit_limit"]
    if requested is None:
        return default_compute_unit_limit(request_tx["instructions"])
    return min(requested, MAX_COMPUTE_UNIT_LIMIT)


def estimate_instruction_compute_units(instruction: dict[str, Any]) -> int:
    """
    Estimate instruction compute usage with a simple deterministic heuristic.

    This is only a simulator approximation. The estimate increases with:
    - signer count, because authorization has cost
    - writable account count, because writes and account locks are more expensive
    - total account count, because more account metadata must be resolved
    - instruction data size, because more bytes must be decoded and processed

    Builtin programs use a much smaller base than custom programs because their default
    compute allocation is lower in Solana's compute-budget rules.
    """
    signer_count = sum(1 for account in instruction["accounts"] if account["is_signer"])
    writable_count = sum(1 for account in instruction["accounts"] if account["is_writable"])
    data_size = len(instruction["data"])

    if is_builtin_program(instruction["program_id"]):
        base_cost = 1_200
        return base_cost + (250 * signer_count) + (400 * writable_count) + (8 * data_size)

    base_cost = 25_000
    return (
        base_cost
        + (1_500 * signer_count)
        + (3_000 * writable_count)
        + (800 * len(instruction["accounts"]))
        + (20 * data_size)
    )


def estimate_transaction_compute_units(instructions: list[dict[str, Any]]) -> int:
    return sum(estimate_instruction_compute_units(instruction) for instruction in instructions)


def estimate_fee_lamports(
    signature_count: int,
    requested_compute_unit_limit: int,
    compute_unit_price_micro_lamports: int,
) -> int:
    base_fee = signature_count * DEFAULT_LAMPORTS_PER_SIGNATURE
    priority_fee = (
        requested_compute_unit_limit * compute_unit_price_micro_lamports
    ) // 1_000_000
    return base_fee + priority_fee


def account_permission_group(account: dict[str, Any]) -> int:
    if account["is_signer"] and account["is_writable"]:
        return 0
    if account["is_signer"] and not account["is_writable"]:
        return 1
    if not account["is_signer"] and account["is_writable"]:
        return 2
    return 3


def collect_transaction_accounts(
    fee_payer: str,
    instructions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Gather every account referenced by a transaction and order them into Solana message order.

    The result is used to build the transaction message header and account key list.
    We start with the fee payer, then merge in all program ids and instruction accounts.
    If an account appears multiple times, we merge its permissions so any signer or writable
    requirement is preserved.
    """
    account_map: dict[str, dict[str, Any]] = {
        fee_payer: {
            "pubkey": fee_payer,
            "is_signer": True,
            "is_writable": True,
            "is_program": False,
            "first_seen": 0,
        }
    }
    next_seen = 1

    def upsert(pubkey: str, is_signer: bool, is_writable: bool, is_program: bool) -> None:
        """
        Insert a newly seen account or widen its permissions if we already saw it.

        For example, if one instruction uses an account read-only and another uses it
        writable, the final transaction account must be writable.
        """
        nonlocal next_seen
        if pubkey not in account_map:
            account_map[pubkey] = {
                "pubkey": pubkey,
                "is_signer": is_signer,
                "is_writable": is_writable,
                "is_program": is_program,
                "first_seen": next_seen,
            }
            next_seen += 1
            return

        account_map[pubkey]["is_signer"] = account_map[pubkey]["is_signer"] or is_signer
        account_map[pubkey]["is_writable"] = account_map[pubkey]["is_writable"] or is_writable
        account_map[pubkey]["is_program"] = account_map[pubkey]["is_program"] or is_program

    for instruction in instructions:
        upsert(instruction["program_id"], is_signer=False, is_writable=False, is_program=True)
        for account in instruction["accounts"]:
            upsert(
                account["pubkey"],
                is_signer=account["is_signer"],
                is_writable=account["is_writable"],
                is_program=False,
            )

    ordered_accounts = sorted(
        account_map.values(),
        key=lambda account: (account_permission_group(account), account["first_seen"]),
    )

    return ordered_accounts


def build_message_header(accounts: list[dict[str, Any]]) -> dict[str, int]:
    # A transaction message is the signable payload of a Solana transaction:
    # header + account keys + recent_blockhash + compiled instructions,
    # and for v0 messages also address table lookups.
    return {
        "num_required_signatures": sum(1 for account in accounts if account["is_signer"]),
        "num_readonly_signed_accounts": sum(
            1 for account in accounts if account["is_signer"] and not account["is_writable"]
        ),
        "num_readonly_unsigned_accounts": sum(
            1 for account in accounts if not account["is_signer"] and not account["is_writable"]
        ),
    }


def compile_instructions(
    instructions: list[dict[str, Any]],
    account_index: dict[str, int],
) -> list[dict[str, Any]]:
    compiled = []
    for instruction in instructions:
        compiled.append(
            {
                "program_id_index": account_index[instruction["program_id"]],
                "accounts": [account_index[account["pubkey"]] for account in instruction["accounts"]],
                "data": list(instruction["data"]),
            }
        )
    return compiled


def split_static_and_lookup_accounts(
    ordered_accounts: list[dict[str, Any]],
    address_lookup_tables: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Split ordered transaction accounts into v0 static accounts and lookup-table-loaded accounts.

    In a v0 transaction, signer accounts and program ids must stay in the static account list.
    Some non-signer accounts can instead be loaded from Address Lookup Tables to save space.

    Returns:
    - static accounts that stay directly in the message
    - loaded writable accounts
    - loaded read-only accounts
    - the address_table_lookups section to embed into the v0 message
    """
    lookup_registry: dict[str, tuple[str, int]] = {}
    for table in address_lookup_tables:
        for index, address in enumerate(table["addresses"]):
            lookup_registry.setdefault(address, (table["account_key"], index))

    table_hits: dict[str, dict[str, list[dict[str, Any]]]] = {
        table["account_key"]: {"writable": [], "readonly": []} for table in address_lookup_tables
    }

    static_accounts: list[dict[str, Any]] = []
    for account in ordered_accounts:
        if account["is_signer"] or account["is_program"]:
            static_accounts.append(account)
            continue

        lookup_match = lookup_registry.get(account["pubkey"])
        if lookup_match is None:
            static_accounts.append(account)
            continue

        table_key, table_index = lookup_match
        lookup_account = dict(account)
        lookup_account["lookup_table_account"] = table_key
        lookup_account["lookup_index"] = table_index

        if account["is_writable"]:
            table_hits[table_key]["writable"].append(lookup_account)
        else:
            table_hits[table_key]["readonly"].append(lookup_account)

    address_table_lookups: list[dict[str, Any]] = []
    loaded_writable_accounts: list[dict[str, Any]] = []
    loaded_readonly_accounts: list[dict[str, Any]] = []

    for table in address_lookup_tables:
        table_key = table["account_key"]
        writable_accounts = sorted(
            table_hits[table_key]["writable"], key=lambda account: account["first_seen"]
        )
        readonly_accounts = sorted(
            table_hits[table_key]["readonly"], key=lambda account: account["first_seen"]
        )

        if not writable_accounts and not readonly_accounts:
            continue

        address_table_lookups.append(
            {
                "account_key": table_key,
                "writable_indexes": [account["lookup_index"] for account in writable_accounts],
                "readonly_indexes": [account["lookup_index"] for account in readonly_accounts],
            }
        )
        loaded_writable_accounts.extend(writable_accounts)
        loaded_readonly_accounts.extend(readonly_accounts)

    return static_accounts, loaded_writable_accounts, loaded_readonly_accounts, address_table_lookups


# Legacy messages keep every account key directly in `account_keys`.
# V0 messages keep only static accounts directly in the message and can pull additional
# non-signer accounts from address lookup tables to reduce serialized size.
def compile_legacy_transaction(
    request_tx: dict[str, Any],
) -> tuple[dict[str, Any], list[str], list[str]]:
    """
    Compile a simulator request into a legacy Solana transaction.

    A legacy transaction has:
    - signatures
    - a message with `header`, `account_keys`, `recent_blockhash`, and compiled instructions

    It does not use address lookup tables, so every referenced account must appear in
    `account_keys`.
    """
    ordered_accounts = collect_transaction_accounts(
        fee_payer=request_tx["fee_payer"],
        instructions=request_tx["instructions"],
    )
    account_keys = [account["pubkey"] for account in ordered_accounts]
    account_index = {pubkey: index for index, pubkey in enumerate(account_keys)}
    message = {
        "header": build_message_header(ordered_accounts),
        "account_keys": account_keys,
        "recent_blockhash": request_tx["recent_blockhash"],
        "instructions": compile_instructions(request_tx["instructions"], account_index),
    }
    signer_pubkeys = [
        account["pubkey"] for account in ordered_accounts if account["is_signer"]
    ]
    transaction = {
        "signatures": [
            simulate_signature_for_signer(message, signer) for signer in signer_pubkeys
        ],
        "message": message,
    }
    return transaction, account_keys, signer_pubkeys


def compile_v0_transaction(
    request_tx: dict[str, Any],
) -> tuple[dict[str, Any], list[str], list[str]]:
    """
    Compile a simulator request into a versioned v0 Solana transaction.

    A v0 transaction still has signatures plus a signable message, but the message differs
    from legacy format by containing:
    - `version: 0`
    - `static_account_keys` instead of one flat `account_keys` list
    - `address_table_lookups` for extra non-signer accounts resolved from lookup tables
    """
    ordered_accounts = collect_transaction_accounts(
        fee_payer=request_tx["fee_payer"],
        instructions=request_tx["instructions"],
    )
    (
        static_accounts,
        loaded_writable_accounts,
        loaded_readonly_accounts,
        address_table_lookups,
    ) = split_static_and_lookup_accounts(
        ordered_accounts,
        request_tx["address_lookup_tables"],
    )

    static_account_keys = [account["pubkey"] for account in static_accounts]
    resolved_account_keys = static_account_keys + [
        account["pubkey"] for account in loaded_writable_accounts
    ] + [account["pubkey"] for account in loaded_readonly_accounts]
    account_index = {pubkey: index for index, pubkey in enumerate(resolved_account_keys)}

    message = {
        "version": 0,
        "header": build_message_header(static_accounts),
        "static_account_keys": static_account_keys,
        "recent_blockhash": request_tx["recent_blockhash"],
        "instructions": compile_instructions(request_tx["instructions"], account_index),
        "address_table_lookups": address_table_lookups,
    }
    signer_pubkeys = [account["pubkey"] for account in static_accounts if account["is_signer"]]
    transaction = {
        "signatures": [
            simulate_signature_for_signer(message, signer) for signer in signer_pubkeys
        ],
        "message": message,
    }
    return transaction, resolved_account_keys, signer_pubkeys


def estimate_compiled_instruction_size(compiled_instruction: dict[str, Any]) -> int:
    """Estimate the serialized size of one compiled instruction inside a Solana message."""
    return (
        1
        + shortvec_length(len(compiled_instruction["accounts"]))
        + len(compiled_instruction["accounts"])
        + shortvec_length(len(compiled_instruction["data"]))
        + len(compiled_instruction["data"])
    )


def estimate_legacy_transaction_size(transaction: dict[str, Any]) -> int:
    """
    Estimate serialized byte size for a legacy transaction.

    Formula:
    - shortvec length of the signature count
    - 64 bytes per signature
    - 3 bytes for the message header fields
    - shortvec length of the account key count
    - 32 bytes per account key
    - 32 bytes for the recent blockhash
    - shortvec length of the instruction count
    - size of each compiled instruction
    """
    message = transaction["message"]
    message_size = (
        3
        + shortvec_length(len(message["account_keys"]))
        + (32 * len(message["account_keys"]))
        + 32
        + shortvec_length(len(message["instructions"]))
        + sum(
            estimate_compiled_instruction_size(compiled_instruction)
            for compiled_instruction in message["instructions"]
        )
    )
    return shortvec_length(len(transaction["signatures"])) + (
        64 * len(transaction["signatures"])
    ) + message_size


def estimate_v0_transaction_size(transaction: dict[str, Any]) -> int:
    """
    Estimate serialized byte size for a v0 transaction.

    Formula:
    - shortvec length of the signature count
    - 64 bytes per signature
    - 1 byte for the version prefix
    - 3 bytes for the message header fields
    - shortvec length of the static account key count
    - 32 bytes per static account key
    - 32 bytes for the recent blockhash
    - shortvec length of the instruction count
    - size of each compiled instruction
    - shortvec length of the address table lookup count
    - for each lookup: 32 bytes for the lookup table address plus shortvec-prefixed writable
      and readonly index arrays
    """
    message = transaction["message"]
    lookup_size = shortvec_length(len(message["address_table_lookups"]))
    for lookup in message["address_table_lookups"]:
        lookup_size += 32
        lookup_size += shortvec_length(len(lookup["writable_indexes"])) + len(lookup["writable_indexes"])
        lookup_size += shortvec_length(len(lookup["readonly_indexes"])) + len(lookup["readonly_indexes"])

    message_size = (
        1
        + 3
        + shortvec_length(len(message["static_account_keys"]))
        + (32 * len(message["static_account_keys"]))
        + 32
        + shortvec_length(len(message["instructions"]))
        + sum(
            estimate_compiled_instruction_size(compiled_instruction)
            for compiled_instruction in message["instructions"]
        )
        + lookup_size
    )
    return shortvec_length(len(transaction["signatures"])) + (
        64 * len(transaction["signatures"])
    ) + message_size


def materialize_transaction(
    request_tx: dict[str, Any],
    validator_id: str,
    slot: int,
) -> dict[str, Any]:
    """
    Turn a submitted request into a validator-processed transaction record.

    This stage compiles the request into either legacy or v0 wire format, computes
    deterministic message and transaction hashes, estimates compute and fees, checks
    packet-size and compute-budget constraints, and returns the transaction object that
    a block would store.
    """
    if request_tx["message_format"] == LEGACY_TRANSACTION_FORMAT:
        transaction, resolved_account_keys, signer_pubkeys = compile_legacy_transaction(request_tx)
        serialized_size_bytes = estimate_legacy_transaction_size(transaction)
    else:
        transaction, resolved_account_keys, signer_pubkeys = compile_v0_transaction(request_tx)
        serialized_size_bytes = estimate_v0_transaction_size(transaction)

    compiled_message_hash = message_hash(transaction["message"])
    compiled_transaction_hash = transaction_hash(transaction)
    requested_compute_unit_limit = effective_compute_unit_limit(request_tx)
    compute_units_consumed = estimate_transaction_compute_units(request_tx["instructions"])
    fee_lamports = estimate_fee_lamports(
        signature_count=len(signer_pubkeys),
        requested_compute_unit_limit=requested_compute_unit_limit,
        compute_unit_price_micro_lamports=request_tx["compute_budget"][
            "compute_unit_price_micro_lamports"
        ],
    )

    err = None
    status = "confirmed"
    if compute_units_consumed > requested_compute_unit_limit:
        err = {
            "compute_budget_exceeded": {
                "requested_compute_unit_limit": requested_compute_unit_limit,
                "compute_units_consumed": compute_units_consumed,
            }
        }
        status = "rejected"
    elif serialized_size_bytes > PACKET_DATA_SIZE:
        err = {
            "packet_too_large": {
                "serialized_size_bytes": serialized_size_bytes,
                "packet_data_size_limit": PACKET_DATA_SIZE,
            }
        }
        status = "rejected"

    return {
        "transaction_id": compiled_transaction_hash,
        "request_id": request_tx["request_id"],
        "slot": slot,
        "validator_id": validator_id,
        "included_at_ms": now_ms(),
        "status": status,
        "transaction_format": request_tx["message_format"],
        "transaction": transaction,
        "meta": {
            "fee_lamports": fee_lamports,
            "message_hash": compiled_message_hash,
            "transaction_hash": compiled_transaction_hash,
            "requested_compute_unit_limit": requested_compute_unit_limit,
            "compute_units_consumed": compute_units_consumed,
            "compute_unit_price_micro_lamports": request_tx["compute_budget"][
                "compute_unit_price_micro_lamports"
            ],
            "resolved_account_keys": resolved_account_keys,
            "serialized_size_bytes": serialized_size_bytes,
            "fits_packet_data_size": serialized_size_bytes <= PACKET_DATA_SIZE,
            "err": err,
            "log_messages": [
                f"validator {validator_id} processed request {request_tx['request_id']}",
                f"transaction format: {request_tx['message_format']}",
            ],
        },
        "metadata": deepcopy(request_tx["metadata"]),
        "block_id": None,
        "block_hash": None,
    }


def create_block(
    slot: int,
    leader_id: str,
    parent_block_hash: str,
    transactions: list[dict[str, Any]],
) -> dict[str, Any]:
    block = {
        "block_id": make_id("block"),
        "slot": slot,
        "leader_id": leader_id,
        "created_at_ms": now_ms(),
        "parent_block_hash": parent_block_hash,
        "transaction_count": len(transactions),
        "total_fees_lamports": sum(tx["meta"]["fee_lamports"] for tx in transactions),
        "transactions": deepcopy(transactions),
    }
    block["block_hash"] = stable_hash(block)

    for transaction in block["transactions"]:
        transaction["block_id"] = block["block_id"]
        transaction["block_hash"] = block["block_hash"]

    return block


def sample_accounts() -> dict[str, dict[str, Any]]:
    """
    Build a small sample account set for the simulator.

    These accounts are not meant to be exact replicas of mainnet accounts. They exist so the
    sample transactions have realistic participants:
    - user wallets that hold lamports and pay fees
    - program-owned state accounts for the market
    - token-vault-like writable accounts
    - an address lookup table account for the v0 example
    - the executable program account itself
    """
    accounts = {
        # Market maker wallet that funds liquidity movements and pays fees.
        make_address("market_maker"): build_account_state(
            lamports=25 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Destination pool account that receives transferred liquidity.
        make_address("liquidity_pool"): build_account_state(
            lamports=100 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Retail trader wallet used as the fee payer and signer in the swap example.
        make_address("retail_trader"): build_account_state(
            lamports=8 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Simple recipient wallet included to show a normal user-owned system account.
        make_address("merchant"): build_account_state(
            lamports=3 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Program-owned order state for the simulated market program.
        make_address("open_orders"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[1, 2, 3, 4],
        ),
        # Writable queue-like state where simulated fills or events would accumulate.
        make_address("event_queue"): build_account_state(
            lamports=4 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[9, 8, 7],
        ),
        # Read-mostly market configuration/state account.
        make_address("market_state"): build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[10, 20, 30],
        ),
        # Sample bids slab/account for the order book side.
        make_address("bids"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[5],
        ),
        # Sample asks slab/account for the order book side.
        make_address("asks"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[6],
        ),
        # Oracle-like price reference account used read-only by the market instruction.
        make_address("oracle"): build_account_state(
            lamports=LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[42, 42],
        ),
        # Writable vault-like account representing one side of the market inventory.
        make_address("usdc_vault"): build_account_state(
            lamports=20 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[11, 12],
        ),
        # Writable vault-like account representing the other side of the market inventory.
        make_address("sol_vault"): build_account_state(
            lamports=15 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[13, 14],
        ),
        # Address Lookup Table account used by the v0 example to compress account references.
        make_address("market_alt"): build_account_state(
            lamports=2_000_000,
            owner=ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            data=[99, 100],
        ),
        # This final entry is the executable program account itself. Its owner is the
        # upgradeable BPF loader, which is the loader program responsible for storing and
        # dispatching upgradeable Solana programs.
        MARKET_SIM_PROGRAM_ID: build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner="BPFLoaderUpgradeable11111111111111111111111",
            executable=True,
        ),
    }
    return accounts


def sample_transaction_requests() -> list[dict[str, Any]]:
    market_lookup_table = build_address_lookup_table(
        account_key=make_address("market_alt"),
        addresses=[
            make_address("event_queue"),
            make_address("market_state"),
            make_address("bids"),
            make_address("asks"),
            make_address("oracle"),
        ],
    )

    return [
        build_transaction_request(
            agent_id="agent_market_maker",
            fee_payer=make_address("market_maker"),
            instructions=[
                build_system_transfer_instruction(
                    sender=make_address("market_maker"),
                    recipient=make_address("liquidity_pool"),
                    lamports=2 * LAMPORTS_PER_SOL,
                )
            ],
            message_format=LEGACY_TRANSACTION_FORMAT,
            compute_unit_price_micro_lamports=10_000,
            metadata={"intent": "rebalance_pool"},
        ),
        build_transaction_request(
            agent_id="agent_retail_trader",
            fee_payer=make_address("retail_trader"),
            instructions=[
                build_market_swap_instruction(
                    trader=make_address("retail_trader"),
                    open_orders=make_address("open_orders"),
                    event_queue=make_address("event_queue"),
                    market_state=make_address("market_state"),
                    bids=make_address("bids"),
                    asks=make_address("asks"),
                    oracle=make_address("oracle"),
                    usdc_vault=make_address("usdc_vault"),
                    sol_vault=make_address("sol_vault"),
                    amount_in=250_000_000,
                    min_amount_out=249_000_000,
                )
            ],
            message_format=VERSIONED_V0_TRANSACTION_FORMAT,
            address_lookup_tables=[market_lookup_table],
            compute_unit_price_micro_lamports=5_000,
            metadata={"intent": "swap_usdc_for_sol"},
        ),
    ]


def sample_block_from_requests(
    requests: list[dict[str, Any]],
    leader_id: str = "validator_alpha",
    slot: int = 1,
    parent_block_hash: str = "genesis",
) -> dict[str, Any]:
    executed_transactions = [
        materialize_transaction(request_tx, validator_id=leader_id, slot=slot)
        for request_tx in requests
    ]
    return create_block(
        slot=slot,
        leader_id=leader_id,
        parent_block_hash=parent_block_hash,
        transactions=executed_transactions,
    )


def main() -> None:
    accounts = sample_accounts()
    requests = sample_transaction_requests()
    block = sample_block_from_requests(requests)

    print("ACCOUNTS")
    print(to_json(accounts))
    print()
    print("TRANSACTION REQUESTS")
    print(to_json(requests))
    print()
    print("FINALIZED BLOCK")
    print(to_json(block))


if __name__ == "__main__":
    main()
