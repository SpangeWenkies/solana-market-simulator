# create JSON holding transactions
# create chain that stores subsequent blocks
# create proof of stake algorithm
# create proof of history algorithm (maybe this is the same as verifying the chain is valid)
# create a way to add new transactions to the chain
# create a way to verify the chain is valid
# create a way to resolve conflicts between chains
# create a way to register nodes in the network
# create a way to reach consensus between nodes
# create liquidity pools and a way to swap between them
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

Always be wary of when a function expects raw bytes or hex strings. Solana protocol sizes are based on byte lengths,
but for readability we often use hex strings in the simulator. When estimating transaction sizes, be sure to use the 
underlying byte lengths and not the string lengths of any hex-encoded values.
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

PUBKEY_BYTES = 32
BLOCKHASH_BYTES = 32
HASH_BYTES = 32
SIGNATURE_BYTES = 64

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
TOKEN_PROGRAM_ID = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
STAKE_PROGRAM_ID = "Stake11111111111111111111111111111111111111"
VOTE_PROGRAM_ID = "Vote111111111111111111111111111111111111111"
CONFIG_PROGRAM_ID = "Config1111111111111111111111111111111111111"
COMPUTE_BUDGET_PROGRAM_ID = "ComputeBudget111111111111111111111111111111"
ADDRESS_LOOKUP_TABLE_PROGRAM_ID = "AddressLookupTab1e1111111111111111111111111"
AMM_SIM_PROGRAM_ID = "AmmSim111111111111111111111111111111111111"
MARKET_SIM_PROGRAM_ID = "MarketSim1111111111111111111111111111111111"

# Later change some of these into enums or more structured types if it seems helpful, but for now we can just use string constants.

SWAP_MODE_EXACT_INPUT = "exact_in"
SWAP_MODE_EXACT_OUTPUT = "exact_out"

POOL_TYPE_CONSTANT_PRODUCT = "constant_product"
POOL_TYPE_STABLE_SWAP = "stable_swap"
POOL_TYPE_WEIGHTED = "weighted"

MARKET_SIDE_BUY = "buy"
MARKET_SIDE_SELL = "sell"
MARKET_ORDER_TYPE_MARKET = "market"
MARKET_ORDER_TYPE_LIMIT = "limit"

PLAYER_TYPE_MARKET_MAKER = "market_maker"
PLAYER_TYPE_LIQUIDITY_PROVIDER = "liquidity_provider"
PLAYER_TYPE_RETAIL_USER = "retail_user"
PLAYER_TYPE_ARBITRAGEUR = "arbitrageur"
PLAYER_TYPE_ROUTER = "router"
PLAYER_TYPE_REBALANCER = "rebalancer"

INTENT_TYPE_SYSTEM_TRANSFER = "system_transfer"
INTENT_TYPE_POOL_SWAP = "pool_swap"
INTENT_TYPE_POOL_LIQUIDITY_ADD = "pool_liquidity_add"
INTENT_TYPE_MARKET_TRADE = "market_trade"

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


def placeholder_digest_hex(payload: bytes, digest_size_bytes: int) -> str:
    """
    Return a hex-encoded placeholder digest of a specific byte width.

    The digest width is expressed in bytes because Solana protocol sizes are byte-based.
    The returned string is hex text for readability, so its Python string length is twice
    the underlying byte length. Code that estimates protocol size must therefore use the
    byte-width constants above, not `len()` of the returned hex string.
    """
    return hashlib.blake2b(payload, digest_size=digest_size_bytes).hexdigest()


def stable_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return placeholder_digest_hex(encoded, HASH_BYTES)


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
    
    7 bits of the value are encoded per byte, and the high bit is a continuation flag.
    The helper keeps shifting by 7 bits until the remaining value is zero, counting how many bytes that takes.
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
    return placeholder_digest_hex(payload, SIGNATURE_BYTES)


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
    # the number 2 is the System Program's "Transfer" instruction discriminator, which tells the program which action to perform.
    return list(struct.pack("<IQ", 2, lamports))


def encode_pool_swap_data(
    swap_mode: str,
    amount: int,
    other_amount_threshold: int,
) -> list[int]:
    """
    Encode a generic AMM swap payload.

    `swap_mode` controls whether `amount` is interpreted as the exact input amount or the
    exact output amount. `other_amount_threshold` is the slippage guard on the opposite side:
    - exact_in: minimum acceptable output amount
    - exact_out: maximum acceptable input amount

    The pool itself determines the pricing curve from its on-chain state, so the instruction
    data does not need to include pool type or a buy/sell flag.
    """
    if swap_mode == SWAP_MODE_EXACT_INPUT:
        swap_mode_flag = 0
    elif swap_mode == SWAP_MODE_EXACT_OUTPUT:
        swap_mode_flag = 1
    else:
        raise ValueError("swap_mode must be 'exact_in' or 'exact_out'")
    # We use `struct.pack` to produce deterministic binary instruction data.
    # "<BQQ" means little-endian: `B` = 1-byte swap mode flag, then two `Q` values for the
    # 8-byte unsigned integers `amount` and `other_amount_threshold`.
    return list(struct.pack("<BQQ", swap_mode_flag, amount, other_amount_threshold))


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


def build_pool_swap_instruction(
    trader_authority: str,
    trader_source_account: str,
    trader_destination_account: str,
    pool_state: str,
    pool_vaults: list[str],
    pool_lp_mint: str,
    pool_fee_vault: str,
    swap_mode: str,
    amount: int,
    other_amount_threshold: int,
    oracle_account: str | None = None,
) -> dict[str, Any]:
    """
    Build a generic AMM pool-swap instruction for the simulator.

    This represents a trader swapping against a pool program. The instruction
    includes:
    - the trader authority account that signs
    - the trader's source and destination token accounts
    - the pool state account that defines the pricing curve and fee rules
    - pool vault accounts that hold the pooled assets
    - the LP mint and fee vault for pool accounting
    - an optional oracle account for pricing or guard-rail logic

    The same instruction shape can be used for:
    - constant product pools
    - stable swap pools
    - weighted / multi-token pools

    The difference between those pool types lives in the pool state, not in the swap
    instruction arguments.
    """
    accounts = [
        build_account_meta(trader_authority, is_signer=True, is_writable=False),
        build_account_meta(trader_source_account, is_signer=False, is_writable=True),
        build_account_meta(trader_destination_account, is_signer=False, is_writable=True),
        build_account_meta(pool_state, is_signer=False, is_writable=True),
    ]
    accounts.extend(
        build_account_meta(pool_vault, is_signer=False, is_writable=True)
        for pool_vault in pool_vaults
    )
    accounts.extend(
        [
            build_account_meta(pool_lp_mint, is_signer=False, is_writable=False),
            build_account_meta(pool_fee_vault, is_signer=False, is_writable=True),
        ]
    )
    if oracle_account is not None:
        accounts.append(build_account_meta(oracle_account, is_signer=False, is_writable=False))

    return build_instruction(
        program_id=AMM_SIM_PROGRAM_ID,
        accounts=accounts,
        data=encode_pool_swap_data(swap_mode, amount, other_amount_threshold),
    )


def encode_pool_liquidity_add_data(
    max_token_a_amount: int,
    max_token_b_amount: int,
    min_lp_tokens_out: int,
) -> list[int]:
    """
    Encode a minimal two-token liquidity-add payload.

    This is a first LP-oriented instruction shape for the simulator:
    - the LP supplies up to two token amounts
    - the LP expects at least some minimum LP shares back
    """
    return list(struct.pack("<QQQ", max_token_a_amount, max_token_b_amount, min_lp_tokens_out))


def build_pool_liquidity_add_instruction(
    trader_authority: str,
    trader_source_accounts: list[str],
    pool_state: str,
    pool_vaults: list[str],
    pool_lp_mint: str,
    trader_lp_receipt_account: str,
    pool_fee_vault: str,
    max_token_amounts: list[int],
    min_lp_tokens_out: int,
    oracle_account: str | None = None,
) -> dict[str, Any]:
    """
    Build a minimal LP deposit instruction for a two-token pool.

    This gives liquidity providers a distinct on-chain interaction pattern from traders:
    they contribute assets to pool vaults and receive LP tokens instead of swapping one
    asset for another.
    """
    if len(trader_source_accounts) != 2 or len(pool_vaults) != 2 or len(max_token_amounts) != 2:
        raise ValueError("pool_liquidity_add currently supports exactly two pool assets")

    accounts = [
        build_account_meta(trader_authority, is_signer=True, is_writable=False),
        build_account_meta(trader_source_accounts[0], is_signer=False, is_writable=True),
        build_account_meta(trader_source_accounts[1], is_signer=False, is_writable=True),
        build_account_meta(pool_state, is_signer=False, is_writable=True),
        build_account_meta(pool_vaults[0], is_signer=False, is_writable=True),
        build_account_meta(pool_vaults[1], is_signer=False, is_writable=True),
        build_account_meta(pool_lp_mint, is_signer=False, is_writable=True),
        build_account_meta(trader_lp_receipt_account, is_signer=False, is_writable=True),
        build_account_meta(pool_fee_vault, is_signer=False, is_writable=True),
    ]
    if oracle_account is not None:
        accounts.append(build_account_meta(oracle_account, is_signer=False, is_writable=False))

    return build_instruction(
        program_id=AMM_SIM_PROGRAM_ID,
        accounts=accounts,
        data=encode_pool_liquidity_add_data(
            max_token_a_amount=max_token_amounts[0],
            max_token_b_amount=max_token_amounts[1],
            min_lp_tokens_out=min_lp_tokens_out,
        ),
    )


def encode_market_swap_data(
    side: str,
    order_type: str,
    base_amount: int,
    quote_amount_limit: int,
    limit_price: int = 0,
) -> list[int]:
    """
    Encode an orderbook-style market interaction payload.

    This is separate from pool swaps. Here the simulator assumes the instruction interacts
    with a market state containing bids, asks, an event queue, and open-orders state.

    Fields:
    - `side`: buy or sell
    - `order_type`: market or limit
    - `base_amount`: amount of the base asset the trader wants to trade
    - `quote_amount_limit`: max quote spent for buys or min quote received for sells
    - `limit_price`: optional price guard for limit orders; zero for market orders
    """
    if side == MARKET_SIDE_BUY:
        side_flag = 0
    elif side == MARKET_SIDE_SELL:
        side_flag = 1
    else:
        raise ValueError("side must be 'buy' or 'sell'")

    if order_type == MARKET_ORDER_TYPE_MARKET:
        order_type_flag = 0
    elif order_type == MARKET_ORDER_TYPE_LIMIT:
        order_type_flag = 1
    else:
        raise ValueError("order_type must be 'market' or 'limit'")

    return list(struct.pack("<BBQQQ", side_flag, order_type_flag, base_amount, quote_amount_limit, limit_price))


def build_market_swap_instruction(
    trader_authority: str,
    trader_base_account: str,
    trader_quote_account: str,
    open_orders: str,
    event_queue: str,
    market_state: str,
    bids: str,
    asks: str,
    base_vault: str,
    quote_vault: str,
    oracle_account: str,
    side: str,
    order_type: str,
    base_amount: int,
    quote_amount_limit: int,
    limit_price: int = 0,
) -> dict[str, Any]:
    """
    Build an orderbook-style market instruction for the simulator.

    Unlike an AMM pool swap, this instruction assumes the program maintains explicit market
    state:
    - open orders per trader
    - bids and asks books
    - an event queue for fills and cancellations
    - market vaults that hold settlement assets

    This lets the simulator support player types such as market makers, retail traders,
    routers, and arbitrageurs that may interact with both CLOB-like markets and AMM pools.
    """
    return build_instruction(
        program_id=MARKET_SIM_PROGRAM_ID,
        accounts=[
            build_account_meta(trader_authority, is_signer=True, is_writable=False),
            build_account_meta(trader_base_account, is_signer=False, is_writable=True),
            build_account_meta(trader_quote_account, is_signer=False, is_writable=True),
            build_account_meta(open_orders, is_signer=False, is_writable=True),
            build_account_meta(event_queue, is_signer=False, is_writable=True),
            build_account_meta(market_state, is_signer=False, is_writable=True),
            build_account_meta(bids, is_signer=False, is_writable=True),
            build_account_meta(asks, is_signer=False, is_writable=True),
            build_account_meta(base_vault, is_signer=False, is_writable=True),
            build_account_meta(quote_vault, is_signer=False, is_writable=True),
            build_account_meta(oracle_account, is_signer=False, is_writable=False),
        ],
        data=encode_market_swap_data(
            side=side,
            order_type=order_type,
            base_amount=base_amount,
            quote_amount_limit=quote_amount_limit,
            limit_price=limit_price,
        ),
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


def build_pool_definition(
    pool_name: str,
    pool_type: str,
    pool_state_account: str,
    pool_vault_accounts: list[str],
    pool_lp_mint: str,
    pool_fee_vault: str,
    token_symbols: list[str],
    oracle_account: str | None = None,
    amplification_factor: int | None = None,
    normalized_weights_bps: list[int] | None = None,
) -> dict[str, Any]:
    """
    Build decoded pool metadata for the simulator.

    The instruction accounts point to on-chain state, but the simulator also benefits from a
    decoded pool object that tells us what curve the pool uses:
    - constant product pools rely on reserve balances
    - stable swap pools also need an amplification parameter
    - weighted pools need normalized token weights and may have more than two vaults
    """
    return {
        "pool_name": pool_name,
        "pool_type": pool_type,
        "pool_state_account": pool_state_account,
        "pool_vault_accounts": list(pool_vault_accounts),
        "pool_lp_mint": pool_lp_mint,
        "pool_fee_vault": pool_fee_vault,
        "token_symbols": list(token_symbols),
        "oracle_account": oracle_account,
        "amplification_factor": amplification_factor,
        "normalized_weights_bps": list(normalized_weights_bps or []),
    }


def build_market_definition(
    market_name: str,
    market_state_account: str,
    open_orders_account: str,
    event_queue_account: str,
    bids_account: str,
    asks_account: str,
    base_vault_account: str,
    quote_vault_account: str,
    oracle_account: str,
    base_symbol: str,
    quote_symbol: str,
) -> dict[str, Any]:
    """
    Build decoded market metadata for an orderbook-style venue in the simulator.

    This sits alongside pool definitions so the overall simulator can support both:
    - pool-based swaps
    - orderbook / market-based trading
    """
    return {
        "market_name": market_name,
        "market_state_account": market_state_account,
        "open_orders_account": open_orders_account,
        "event_queue_account": event_queue_account,
        "bids_account": bids_account,
        "asks_account": asks_account,
        "base_vault_account": base_vault_account,
        "quote_vault_account": quote_vault_account,
        "oracle_account": oracle_account,
        "base_symbol": base_symbol,
        "quote_symbol": quote_symbol,
    }


def build_player_profile(
    player_id: str,
    player_type: str,
    authority_account: str,
    token_accounts: dict[str, str] | None = None,
    default_message_format: str = LEGACY_TRANSACTION_FORMAT,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a simulator-side player profile.

    A player profile lives above the on-chain layer. It describes who the actor is, which
    authority account they control, and which token accounts they typically use. Players do
    not directly become transactions; they generate intents, and those intents are later
    compiled into Solana-style transaction requests.
    """
    return {
        "player_id": player_id,
        "player_type": player_type,
        "authority_account": authority_account,
        "token_accounts": dict(token_accounts or {}),
        "default_message_format": default_message_format,
        "metadata": metadata or {},
    }


def build_player_intent(
    player_id: str,
    intent_type: str,
    parameters: dict[str, Any],
    venue_type: str = "system",
    venue_id: str | None = None,
    execution_preferences: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a high-level intent generated by a simulated player.

    This is the separation point between strategy behavior and on-chain execution:
    - intent layer: "what the player wants to do"
    - request layer: "how that becomes a Solana transaction"

    The compiler later translates an intent into concrete instructions, account metas,
    message format choices, and fee preferences.
    """
    return {
        "intent_id": make_id("intent"),
        "player_id": player_id,
        "intent_type": intent_type,
        "venue_type": venue_type,
        "venue_id": venue_id,
        "parameters": deepcopy(parameters),
        "execution_preferences": deepcopy(execution_preferences or {}),
        "metadata": metadata or {},
    }


def build_lookup_tables_for_intent(
    intent: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Build any v0 address lookup tables needed for a compiled intent.

    Intents stay high-level. Lookup tables are execution details, so they are resolved only
    when the intent is compiled into a request.
    """
    execution_preferences = intent["execution_preferences"]
    if execution_preferences.get("message_format") != VERSIONED_V0_TRANSACTION_FORMAT:
        return []

    lookup_table_account = execution_preferences.get("lookup_table_account")
    if lookup_table_account is None:
        return []

    if intent["intent_type"] in {INTENT_TYPE_POOL_SWAP, INTENT_TYPE_POOL_LIQUIDITY_ADD}:
        pool = pools[intent["venue_id"]]
        addresses = [
            pool["pool_state_account"],
            *pool["pool_vault_accounts"],
            pool["pool_lp_mint"],
            pool["pool_fee_vault"],
        ]
        if pool["oracle_account"] is not None:
            addresses.append(pool["oracle_account"])
        return [build_address_lookup_table(account_key=lookup_table_account, addresses=addresses)]

    if intent["intent_type"] == INTENT_TYPE_MARKET_TRADE:
        market = markets[intent["venue_id"]]
        return [
            build_address_lookup_table(
                account_key=lookup_table_account,
                addresses=[
                    market["open_orders_account"],
                    market["event_queue_account"],
                    market["market_state_account"],
                    market["bids_account"],
                    market["asks_account"],
                    market["base_vault_account"],
                    market["quote_vault_account"],
                    market["oracle_account"],
                ],
            )
        ]

    return []


def compile_player_intent_to_request(
    intent: dict[str, Any],
    players: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """
    Compile one player intent into a transaction request.

    This function is the bridge between the strategic simulation layer and the blockchain
    execution layer. Different player types can emit different intents, but once compiled they
    all become concrete Solana-style transaction requests that validators can process.
    """
    player = players[intent["player_id"]]
    parameters = intent["parameters"]
    execution_preferences = intent["execution_preferences"]

    if intent["intent_type"] == INTENT_TYPE_SYSTEM_TRANSFER:
        instructions = [
            build_system_transfer_instruction(
                sender=player["authority_account"],
                recipient=parameters["recipient"],
                lamports=parameters["lamports"],
            )
        ]
    elif intent["intent_type"] == INTENT_TYPE_POOL_SWAP:
        pool = pools[intent["venue_id"]]
        instructions = [
            build_pool_swap_instruction(
                trader_authority=player["authority_account"],
                trader_source_account=player["token_accounts"][parameters["source_symbol"]],
                trader_destination_account=player["token_accounts"][parameters["destination_symbol"]],
                pool_state=pool["pool_state_account"],
                pool_vaults=pool["pool_vault_accounts"],
                pool_lp_mint=pool["pool_lp_mint"],
                pool_fee_vault=pool["pool_fee_vault"],
                swap_mode=parameters["swap_mode"],
                amount=parameters["amount"],
                other_amount_threshold=parameters["other_amount_threshold"],
                oracle_account=pool["oracle_account"],
            )
        ]
    elif intent["intent_type"] == INTENT_TYPE_POOL_LIQUIDITY_ADD:
        pool = pools[intent["venue_id"]]
        if len(pool["token_symbols"]) != 2:
            raise ValueError("pool_liquidity_add currently supports exactly two-token pools")
        instructions = [
            build_pool_liquidity_add_instruction(
                trader_authority=player["authority_account"],
                trader_source_accounts=[
                    player["token_accounts"][pool["token_symbols"][0]],
                    player["token_accounts"][pool["token_symbols"][1]],
                ],
                pool_state=pool["pool_state_account"],
                pool_vaults=pool["pool_vault_accounts"],
                pool_lp_mint=pool["pool_lp_mint"],
                trader_lp_receipt_account=parameters["lp_receipt_account"],
                pool_fee_vault=pool["pool_fee_vault"],
                max_token_amounts=parameters["max_token_amounts"],
                min_lp_tokens_out=parameters["min_lp_tokens_out"],
                oracle_account=pool["oracle_account"],
            )
        ]
    elif intent["intent_type"] == INTENT_TYPE_MARKET_TRADE:
        market = markets[intent["venue_id"]]
        instructions = [
            build_market_swap_instruction(
                trader_authority=player["authority_account"],
                trader_base_account=player["token_accounts"][market["base_symbol"]],
                trader_quote_account=player["token_accounts"][market["quote_symbol"]],
                open_orders=market["open_orders_account"],
                event_queue=market["event_queue_account"],
                market_state=market["market_state_account"],
                bids=market["bids_account"],
                asks=market["asks_account"],
                base_vault=market["base_vault_account"],
                quote_vault=market["quote_vault_account"],
                oracle_account=market["oracle_account"],
                side=parameters["side"],
                order_type=parameters["order_type"],
                base_amount=parameters["base_amount"],
                quote_amount_limit=parameters["quote_amount_limit"],
                limit_price=parameters.get("limit_price", 0),
            )
        ]
    else:
        raise ValueError(f"unsupported intent_type: {intent['intent_type']}")

    return build_transaction_request(
        agent_id=player["player_id"],
        fee_payer=player["authority_account"],
        instructions=instructions,
        message_format=execution_preferences.get(
            "message_format", player["default_message_format"]
        ),
        address_lookup_tables=build_lookup_tables_for_intent(intent, pools, markets),
        requested_compute_unit_limit=execution_preferences.get("requested_compute_unit_limit"),
        compute_unit_price_micro_lamports=execution_preferences.get(
            "compute_unit_price_micro_lamports", 0
        ),
        metadata={
            "intent_id": intent["intent_id"],
            "player_id": player["player_id"],
            "player_type": player["player_type"],
            "intent_type": intent["intent_type"],
            "venue_type": intent["venue_type"],
            "venue_id": intent["venue_id"],
            **player["metadata"],
            **intent["metadata"],
        },
    )


def compile_player_intents_to_requests(
    intents: list[dict[str, Any]],
    players: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Compile a list of player intents into transaction requests."""
    return [
        compile_player_intent_to_request(intent, players, pools, markets)
        for intent in intents
    ]


def generate_market_maker_intents(
    player: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a market maker.

    Market makers typically place market-venue liquidity and move inventory where needed. In
    this first pass we model that as:
    - funding a general liquidity wallet
    - posting a limit-style market trade on the spot venue
    """
    del pools
    del markets
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_SYSTEM_TRANSFER,
            parameters={
                "recipient": make_address("liquidity_pool"),
                "lamports": 2 * LAMPORTS_PER_SOL,
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": 10_000,
            },
            metadata={"intent_label": "fund_liquidity_pool"},
        ),
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_MARKET_TRADE,
            venue_type="market",
            venue_id="sol_usdc_spot",
            parameters={
                "side": MARKET_SIDE_SELL,
                "order_type": MARKET_ORDER_TYPE_LIMIT,
                "base_amount": 75_000_000,
                "quote_amount_limit": 82_000_000,
                "limit_price": 1_093_000,
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": 9_000,
            },
            metadata={"intent_label": "post_market_maker_offer"},
        ),
    ]


def generate_liquidity_provider_intents(
    player: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a liquidity provider.

    LPs interact with pools rather than central-limit-order-book style markets. Their first
    modeled behavior is adding inventory to a volatile constant-product pool.
    """
    del pools
    del markets
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_LIQUIDITY_ADD,
            venue_type="pool",
            venue_id="volatile_sol_usdc",
            parameters={
                "max_token_amounts": [400_000_000, 900_000_000],
                "min_lp_tokens_out": 150_000_000,
                "lp_receipt_account": make_address("cp_lp_receipt_account"),
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": 8_000,
            },
            metadata={"intent_label": "provide_volatile_pool_liquidity"},
        )
    ]


def generate_retail_user_intents(
    player: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a retail user.

    Retail flow is usually mixed: ordinary payments plus venue interaction. We model both a
    merchant payment and a spot-market market order from the same player profile.
    """
    del pools
    del markets
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_SYSTEM_TRANSFER,
            parameters={
                "recipient": make_address("merchant"),
                "lamports": 250_000_000,
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": 0,
            },
            metadata={"intent_label": "merchant_payment"},
        ),
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_MARKET_TRADE,
            venue_type="market",
            venue_id="sol_usdc_spot",
            parameters={
                "side": MARKET_SIDE_BUY,
                "order_type": MARKET_ORDER_TYPE_MARKET,
                "base_amount": 120_000_000,
                "quote_amount_limit": 125_000_000,
                "limit_price": 0,
            },
            execution_preferences={
                "message_format": VERSIONED_V0_TRANSACTION_FORMAT,
                "lookup_table_account": make_address("market_alt"),
                "compute_unit_price_micro_lamports": 6_000,
            },
            metadata={"intent_label": "spot_market_buy"},
        ),
    ]


def generate_arbitrageur_intents(
    player: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for an arbitrageur.

    Arbitrageurs care about fast pool-to-price dislocations, so they emit high-priority swap
    flow against volatile pools.
    """
    del pools
    del markets
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_SWAP,
            venue_type="pool",
            venue_id="volatile_sol_usdc",
            parameters={
                "source_symbol": "USDC",
                "destination_symbol": "SOL",
                "swap_mode": SWAP_MODE_EXACT_INPUT,
                "amount": 250_000_000,
                "other_amount_threshold": 120_000_000,
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": 10_000,
            },
            metadata={"intent_label": "arbitrage_pool_swap"},
        )
    ]


def generate_router_intents(
    player: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a router.

    Routers optimize path selection and execution quality, so this sample sends a v0 stable-pool
    swap using a lookup table and exact-output semantics.
    """
    del pools
    del markets
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_SWAP,
            venue_type="pool",
            venue_id="stable_usdc_usdt",
            parameters={
                "source_symbol": "USDC",
                "destination_symbol": "USDT",
                "swap_mode": SWAP_MODE_EXACT_OUTPUT,
                "amount": 100_000_000,
                "other_amount_threshold": 100_200_000,
            },
            execution_preferences={
                "message_format": VERSIONED_V0_TRANSACTION_FORMAT,
                "lookup_table_account": make_address("stable_pool_alt"),
                "compute_unit_price_micro_lamports": 5_000,
            },
            metadata={"intent_label": "stable_pool_swap"},
        )
    ]


def generate_rebalancer_intents(
    player: dict[str, Any],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a portfolio rebalancer.

    Rebalancers trade toward target allocations rather than short-term prices, so this sample
    interacts with the weighted multi-token pool.
    """
    del pools
    del markets
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_SWAP,
            venue_type="pool",
            venue_id="weighted_sol_jup_usdc",
            parameters={
                "source_symbol": "USDC",
                "destination_symbol": "SOL",
                "swap_mode": SWAP_MODE_EXACT_INPUT,
                "amount": 180_000_000,
                "other_amount_threshold": 75_000_000,
            },
            execution_preferences={
                "message_format": VERSIONED_V0_TRANSACTION_FORMAT,
                "lookup_table_account": make_address("weighted_pool_alt"),
                "compute_unit_price_micro_lamports": 7_500,
            },
            metadata={"intent_label": "weighted_pool_rebalance"},
        )
    ]


PLAYER_INTENT_GENERATORS = {
    PLAYER_TYPE_MARKET_MAKER: generate_market_maker_intents,
    PLAYER_TYPE_LIQUIDITY_PROVIDER: generate_liquidity_provider_intents,
    PLAYER_TYPE_RETAIL_USER: generate_retail_user_intents,
    PLAYER_TYPE_ARBITRAGEUR: generate_arbitrageur_intents,
    PLAYER_TYPE_ROUTER: generate_router_intents,
    PLAYER_TYPE_REBALANCER: generate_rebalancer_intents,
}


def generate_player_intents(
    players: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate player intents from player profiles.

    This is the strategy layer entry point. Each player type uses its own generator, which means
    market makers, LPs, retailers, routers, arbitrageurs, and rebalancers can all emit different
    pre-transaction behavior before anything is compiled into Solana execution data.
    """
    intents: list[dict[str, Any]] = []
    for player in players.values():
        generator = PLAYER_INTENT_GENERATORS.get(player["player_type"])
        if generator is None:
            continue
        intents.extend(generator(player, pools, markets))
    return intents


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
    """
    Estimate the serialized size of one compiled instruction inside a Solana message.
    The first byte is the program_id_index, then comes a shortvec-prefixed list of account indices,
    and finally a shortvec-prefixed list of instruction data bytes. In total:
    
    program_id_index — 1 fixed byte
    num_accounts — compact-u16 / shortvec
    account_indices — num_accounts bytes
    data_len — compact-u16 / shortvec
    data — data_len bytes

    program_id_index is the index into the transaction's account-key list telling the runtime
    which program executes the instruction
    
    len(compiled_instruction["accounts"]) is the number of accounts the instruction touches.
    It is enough to use len() here because the account indices are used and not the full public keys.
    The indexing is into the transaction's account key list, which is limited to 256 accounts.
    
    len(compiled_instruction["data"]) is the number of bytes in the instruction data payload, 
    which is limited to 10,240 bytes by our simulator and Solana's current limits. It is
    enough to use len() here because the instruction data is used as raw bytes 
    and not interpreted as higher-level types.

    Reader walks through the account indices and data bytes by first reading the shortvec length
    prefixes, which tell how many bytes to read for each section.
    """
    return (
        1
        + shortvec_length(len(compiled_instruction["accounts"]))
        + len(compiled_instruction["accounts"])
        + shortvec_length(len(compiled_instruction["data"]))
        + len(compiled_instruction["data"])
    )


def estimate_legacy_transaction_size(transaction: dict[str, Any]) -> int:
    """
    Estimate serialized byte size for a legacy transaction (not just one instruction).

    Formula:
    - shortvec length of the signature count
    - `SIGNATURE_BYTES` bytes per signature
    - 3 bytes for the message header fields
    - shortvec length of the account key count
    - `PUBKEY_BYTES` bytes per account key
    - `BLOCKHASH_BYTES` bytes for the recent blockhash
    - shortvec length of the instruction count
    - size of each compiled instruction

    The 3 bytes is for: num_required_signatures + num_readonly_signed_accounts + num_readonly_unsigned_accounts.

    Our simulator may use placeholder hex strings (for example from blake2b) to represent
    pubkeys, blockhashes, or signatures. That does not affect this estimator because it does
    not use the string lengths of those values; it uses Solana's actual serialized wire sizes:
    32 bytes per pubkey, 32 bytes per recent blockhash, and 64 bytes per signature. However,
    any variable-length byte fields (such as instruction data) must be measured in actual bytes,
    not hex-character length.
    """
    message = transaction["message"]
    message_size = (
        3
        + shortvec_length(len(message["account_keys"]))
        + (PUBKEY_BYTES * len(message["account_keys"]))
        + BLOCKHASH_BYTES
        + shortvec_length(len(message["instructions"]))
        + sum(
            estimate_compiled_instruction_size(compiled_instruction)
            for compiled_instruction in message["instructions"]
        )
    )
    return shortvec_length(len(transaction["signatures"])) + (
        SIGNATURE_BYTES * len(transaction["signatures"])
    ) + message_size


def estimate_v0_transaction_size(transaction: dict[str, Any]) -> int:
    """
    Estimate serialized byte size for a v0 transaction.

    Formula:
    - shortvec length of the signature count
    - `SIGNATURE_BYTES` bytes per signature
    - 1 byte for the version prefix
    - 3 bytes for the message header fields
    - shortvec length of the static account key count
    - `PUBKEY_BYTES` bytes per static account key
    - `BLOCKHASH_BYTES` bytes for the recent blockhash
    - shortvec length of the instruction count
    - size of each compiled instruction
    - shortvec length of the address table lookup count
    - for each lookup: `PUBKEY_BYTES` bytes for the lookup table address plus shortvec-prefixed writable
      and readonly index arrays
      
    A lookup table is added, so some account keys are moved from the static account key list into the address table lookups section. 
    The static account keys still use 32 bytes each, but the lookup accounts only use 1 byte each because they are indices into 
    the lookup table. Each lookup also adds 32 bytes for the lookup table address and some additional bytes for the shortvec 
    lengths of the writable and readonly index arrays.
    
    The version prefix byte can not equal the first byte of the legacy message header, this is ensured as the version prefix is 0x80,
    and the legacy message header's first byte is a shortvec encoding of the signature count,
    and as Solana’s transaction limits cap signatures per packet at 12, the legacy first byte is effectively in the range 0..12, 
    which keeps the top bit clear (top bit is 1 for v0, 0 for legacy).
    """
    message = transaction["message"]
    lookup_size = shortvec_length(len(message["address_table_lookups"]))
    for lookup in message["address_table_lookups"]:
        lookup_size += PUBKEY_BYTES
        lookup_size += shortvec_length(len(lookup["writable_indexes"])) + len(lookup["writable_indexes"])
        lookup_size += shortvec_length(len(lookup["readonly_indexes"])) + len(lookup["readonly_indexes"])

    message_size = (
        1
        + 3
        + shortvec_length(len(message["static_account_keys"]))
        + (PUBKEY_BYTES * len(message["static_account_keys"]))
        + BLOCKHASH_BYTES
        + shortvec_length(len(message["instructions"]))
        + sum(
            estimate_compiled_instruction_size(compiled_instruction)
            for compiled_instruction in message["instructions"]
        )
        + lookup_size
    )
    return shortvec_length(len(transaction["signatures"])) + (
        SIGNATURE_BYTES * len(transaction["signatures"])
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


def sample_pools() -> dict[str, dict[str, Any]]:
    """
    Build decoded sample pool definitions for the simulator.

    These pool objects are not the raw on-chain account bytes. They are higher-level simulator
    metadata describing which pricing curve each pool uses and which accounts belong to it.
    This lets the same transaction layer support:
    - volatile constant product pools
    - stable swap pools
    - weighted multi-token pools
    """
    return {
        "volatile_sol_usdc": build_pool_definition(
            pool_name="volatile_sol_usdc",
            pool_type=POOL_TYPE_CONSTANT_PRODUCT,
            pool_state_account=make_address("cp_sol_usdc_pool_state"),
            pool_vault_accounts=[
                make_address("cp_sol_vault"),
                make_address("cp_usdc_vault"),
            ],
            pool_lp_mint=make_address("cp_lp_mint"),
            pool_fee_vault=make_address("cp_fee_vault"),
            token_symbols=["SOL", "USDC"],
            oracle_account=make_address("volatile_oracle"),
        ),
        "stable_usdc_usdt": build_pool_definition(
            pool_name="stable_usdc_usdt",
            pool_type=POOL_TYPE_STABLE_SWAP,
            pool_state_account=make_address("stable_usdc_usdt_pool_state"),
            pool_vault_accounts=[
                make_address("stable_usdc_vault"),
                make_address("stable_usdt_vault"),
            ],
            pool_lp_mint=make_address("stable_lp_mint"),
            pool_fee_vault=make_address("stable_fee_vault"),
            token_symbols=["USDC", "USDT"],
            oracle_account=make_address("stable_oracle"),
            amplification_factor=120,
        ),
        "weighted_sol_jup_usdc": build_pool_definition(
            pool_name="weighted_sol_jup_usdc",
            pool_type=POOL_TYPE_WEIGHTED,
            pool_state_account=make_address("weighted_sol_jup_usdc_pool_state"),
            pool_vault_accounts=[
                make_address("weighted_sol_vault"),
                make_address("weighted_jup_vault"),
                make_address("weighted_usdc_vault"),
            ],
            pool_lp_mint=make_address("weighted_lp_mint"),
            pool_fee_vault=make_address("weighted_fee_vault"),
            token_symbols=["SOL", "JUP", "USDC"],
            oracle_account=make_address("weighted_oracle"),
            normalized_weights_bps=[5_000, 2_000, 3_000],
        ),
    }


def sample_markets() -> dict[str, dict[str, Any]]:
    """
    Build decoded sample market definitions for the simulator.

    These are the orderbook-style venues that live next to the pool definitions so the
    simulator can represent different classes of Solana trading venues at the same time.
    """
    return {
        "sol_usdc_spot": build_market_definition(
            market_name="sol_usdc_spot",
            market_state_account=make_address("market_state"),
            open_orders_account=make_address("open_orders"),
            event_queue_account=make_address("event_queue"),
            bids_account=make_address("bids"),
            asks_account=make_address("asks"),
            base_vault_account=make_address("sol_vault"),
            quote_vault_account=make_address("usdc_vault"),
            oracle_account=make_address("oracle"),
            base_symbol="SOL",
            quote_symbol="USDC",
        )
    }


def sample_players() -> dict[str, dict[str, Any]]:
    """
    Build sample player profiles for the simulator.

    These are strategy-level actors, not transactions. They hold the accounts they control and
    later emit intents that get compiled into transaction requests.
    """
    return {
        "player_market_maker": build_player_profile(
            player_id="player_market_maker",
            player_type=PLAYER_TYPE_MARKET_MAKER,
            authority_account=make_address("market_maker"),
            token_accounts={
                "SOL": make_address("market_maker_sol_account"),
                "USDC": make_address("market_maker_usdc_account"),
            },
            metadata={"style": "two_sided_liquidity"},
        ),
        "player_liquidity_provider": build_player_profile(
            player_id="player_liquidity_provider",
            player_type=PLAYER_TYPE_LIQUIDITY_PROVIDER,
            authority_account=make_address("liquidity_provider"),
            token_accounts={
                "SOL": make_address("liquidity_provider_sol_account"),
                "USDC": make_address("liquidity_provider_usdc_account"),
            },
            metadata={"style": "yield_seeking_lp"},
        ),
        "player_retail_trader": build_player_profile(
            player_id="player_retail_trader",
            player_type=PLAYER_TYPE_RETAIL_USER,
            authority_account=make_address("retail_trader"),
            token_accounts={
                "SOL": make_address("retail_trader_sol_account"),
                "USDC": make_address("retail_trader_usdc_account"),
            },
            default_message_format=VERSIONED_V0_TRANSACTION_FORMAT,
            metadata={"style": "retail_flow"},
        ),
        "player_arb_bot": build_player_profile(
            player_id="player_arb_bot",
            player_type=PLAYER_TYPE_ARBITRAGEUR,
            authority_account=make_address("arb_bot"),
            token_accounts={
                "SOL": make_address("arb_bot_sol_account"),
                "USDC": make_address("arb_bot_usdc_account"),
            },
            metadata={"style": "latency_sensitive"},
        ),
        "player_stable_router": build_player_profile(
            player_id="player_stable_router",
            player_type=PLAYER_TYPE_ROUTER,
            authority_account=make_address("stable_router"),
            token_accounts={
                "USDC": make_address("stable_router_usdc_account"),
                "USDT": make_address("stable_router_usdt_account"),
            },
            default_message_format=VERSIONED_V0_TRANSACTION_FORMAT,
            metadata={"style": "best_execution_router"},
        ),
        "player_index_rebalancer": build_player_profile(
            player_id="player_index_rebalancer",
            player_type=PLAYER_TYPE_REBALANCER,
            authority_account=make_address("index_rebalancer"),
            token_accounts={
                "SOL": make_address("index_rebalancer_sol_account"),
                "USDC": make_address("index_rebalancer_usdc_account"),
                "JUP": make_address("index_rebalancer_jup_account"),
            },
            default_message_format=VERSIONED_V0_TRANSACTION_FORMAT,
            metadata={"style": "portfolio_rebalance"},
        ),
    }


def sample_accounts() -> dict[str, dict[str, Any]]:
    """
    Build a broad sample account set for the simulator.

    These accounts are meant to support multiple interacting venue types:
    - regular wallets such as market makers, retail traders, merchants, and LPs
    - token accounts used by both pool swaps and market-based trading
    - pool state accounts owned by the AMM program
    - orderbook-style market accounts such as open orders, bids, asks, and event queue
    - lookup table accounts for v0 transaction examples
    - executable program accounts for both venue types
    """
    accounts = {
        # Earlier high-level participants kept in the simulation because they are useful actor archetypes.
        make_address("market_maker"): build_account_state(
            lamports=25 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("liquidity_pool"): build_account_state(
            lamports=100 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("retail_trader"): build_account_state(
            lamports=8 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("merchant"): build_account_state(
            lamports=3 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Trader authority wallets. These are normal system accounts used to sign transactions.
        make_address("arb_bot"): build_account_state(
            lamports=12 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("stable_router"): build_account_state(
            lamports=10 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("index_rebalancer"): build_account_state(
            lamports=14 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Liquidity provider wallet kept here as a foundation for later LP behavior simulation.
        make_address("liquidity_provider"): build_account_state(
            lamports=30 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Trader token accounts. In a real Solana deployment these would normally be owned by
        # the SPL Token program and hold fungible token balances rather than arbitrary program state.
        make_address("arb_bot_sol_account"): build_account_state(
            lamports=1_500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[1, 0, 0, 0],
        ),
        make_address("arb_bot_usdc_account"): build_account_state(
            lamports=4_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[2, 0, 0, 0],
        ),
        make_address("stable_router_usdc_account"): build_account_state(
            lamports=8_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[3, 0, 0, 0],
        ),
        make_address("stable_router_usdt_account"): build_account_state(
            lamports=8_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[4, 0, 0, 0],
        ),
        make_address("index_rebalancer_usdc_account"): build_account_state(
            lamports=9_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[5, 0, 0, 0],
        ),
        make_address("index_rebalancer_sol_account"): build_account_state(
            lamports=2_500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[6, 0, 0, 0],
        ),
        make_address("index_rebalancer_jup_account"): build_account_state(
            lamports=7_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 0, 0, 0],
        ),
        # Token accounts for the restored market-maker and retail-trader participants.
        make_address("market_maker_sol_account"): build_account_state(
            lamports=6_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 1, 0, 0],
        ),
        make_address("market_maker_usdc_account"): build_account_state(
            lamports=25_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 2, 0, 0],
        ),
        make_address("retail_trader_sol_account"): build_account_state(
            lamports=1_200_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 3, 0, 0],
        ),
        make_address("retail_trader_usdc_account"): build_account_state(
            lamports=5_500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 4, 0, 0],
        ),
        make_address("liquidity_provider_sol_account"): build_account_state(
            lamports=9_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 5, 0, 0],
        ),
        make_address("liquidity_provider_usdc_account"): build_account_state(
            lamports=18_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[7, 6, 0, 0],
        ),
        # LP receipt accounts are included so later we can model LP share balances and behavior.
        make_address("cp_lp_receipt_account"): build_account_state(
            lamports=500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[8, 0],
        ),
        make_address("stable_lp_receipt_account"): build_account_state(
            lamports=500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[9, 0],
        ),
        make_address("weighted_lp_receipt_account"): build_account_state(
            lamports=500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[10, 0],
        ),
        # Constant product pool state and reserves for a volatile SOL/USDC pool.
        make_address("cp_sol_usdc_pool_state"): build_account_state(
            lamports=3 * LAMPORTS_PER_SOL,
            owner=AMM_SIM_PROGRAM_ID,
            data=[11, 1, 0, 1],
        ),
        make_address("cp_sol_vault"): build_account_state(
            lamports=80 * LAMPORTS_PER_SOL,
            owner=TOKEN_PROGRAM_ID,
            data=[12, 1],
        ),
        make_address("cp_usdc_vault"): build_account_state(
            lamports=140_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[13, 1],
        ),
        make_address("cp_lp_mint"): build_account_state(
            lamports=2_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[14, 1],
        ),
        make_address("cp_fee_vault"): build_account_state(
            lamports=300_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[15, 1],
        ),
        # Stable swap pool state and reserves. This pool can later use an amplification factor.
        make_address("stable_usdc_usdt_pool_state"): build_account_state(
            lamports=3 * LAMPORTS_PER_SOL,
            owner=AMM_SIM_PROGRAM_ID,
            data=[21, 2, 0, 1],
        ),
        make_address("stable_usdc_vault"): build_account_state(
            lamports=250_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[22, 2],
        ),
        make_address("stable_usdt_vault"): build_account_state(
            lamports=248_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[23, 2],
        ),
        make_address("stable_lp_mint"): build_account_state(
            lamports=2_500_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[24, 2],
        ),
        make_address("stable_fee_vault"): build_account_state(
            lamports=400_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[25, 2],
        ),
        # Weighted multi-token pool state and reserves for a three-asset basket.
        make_address("weighted_sol_jup_usdc_pool_state"): build_account_state(
            lamports=4 * LAMPORTS_PER_SOL,
            owner=AMM_SIM_PROGRAM_ID,
            data=[31, 3, 0, 1],
        ),
        make_address("weighted_sol_vault"): build_account_state(
            lamports=60 * LAMPORTS_PER_SOL,
            owner=TOKEN_PROGRAM_ID,
            data=[32, 3],
        ),
        make_address("weighted_jup_vault"): build_account_state(
            lamports=90_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[33, 3],
        ),
        make_address("weighted_usdc_vault"): build_account_state(
            lamports=110_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[34, 3],
        ),
        make_address("weighted_lp_mint"): build_account_state(
            lamports=2_800_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[35, 3],
        ),
        make_address("weighted_fee_vault"): build_account_state(
            lamports=450_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[36, 3],
        ),
        # Orderbook-style market accounts restored so the simulation can support market-based trading.
        make_address("open_orders"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[61, 1, 0, 0],
        ),
        make_address("event_queue"): build_account_state(
            lamports=4 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[62, 1, 0, 0],
        ),
        make_address("market_state"): build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[63, 1, 0, 0],
        ),
        make_address("bids"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[64, 1, 0, 0],
        ),
        make_address("asks"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[65, 1, 0, 0],
        ),
        make_address("oracle"): build_account_state(
            lamports=LAMPORTS_PER_SOL,
            owner=MARKET_SIM_PROGRAM_ID,
            data=[66, 1, 0, 0],
        ),
        make_address("usdc_vault"): build_account_state(
            lamports=120_000_000_000,
            owner=TOKEN_PROGRAM_ID,
            data=[67, 1, 0, 0],
        ),
        make_address("sol_vault"): build_account_state(
            lamports=70 * LAMPORTS_PER_SOL,
            owner=TOKEN_PROGRAM_ID,
            data=[68, 1, 0, 0],
        ),
        # Optional oracle-style accounts that later simulations can use for pricing or guard rails.
        make_address("volatile_oracle"): build_account_state(
            lamports=LAMPORTS_PER_SOL,
            owner=AMM_SIM_PROGRAM_ID,
            data=[41, 1],
        ),
        make_address("stable_oracle"): build_account_state(
            lamports=LAMPORTS_PER_SOL,
            owner=AMM_SIM_PROGRAM_ID,
            data=[42, 1],
        ),
        make_address("weighted_oracle"): build_account_state(
            lamports=LAMPORTS_PER_SOL,
            owner=AMM_SIM_PROGRAM_ID,
            data=[43, 1],
        ),
        # Address lookup table accounts used by the v0 examples to compress non-signer pool references.
        make_address("stable_pool_alt"): build_account_state(
            lamports=2_000_000,
            owner=ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            data=[51, 1],
        ),
        make_address("weighted_pool_alt"): build_account_state(
            lamports=2_000_000,
            owner=ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            data=[52, 1],
        ),
        make_address("market_alt"): build_account_state(
            lamports=2_000_000,
            owner=ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
            data=[53, 1],
        ),
        # The executable AMM program account itself. Its owner is the upgradeable BPF loader,
        # which is the loader program responsible for storing and dispatching upgradeable Solana programs.
        AMM_SIM_PROGRAM_ID: build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner="BPFLoaderUpgradeable11111111111111111111111",
            executable=True,
        ),
        # The executable market program account for orderbook-style trading instructions.
        MARKET_SIM_PROGRAM_ID: build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner="BPFLoaderUpgradeable11111111111111111111111",
            executable=True,
        ),
    }
    return accounts


def sample_player_intents(
    players: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Build sample high-level intents emitted by different player types.

    This keeps the main demo flow explicit:
    players -> player intents -> transaction requests -> executed transactions -> blocks
    """
    return generate_player_intents(players, pools, markets)


def sample_transaction_requests(
    player_intents: list[dict[str, Any]],
    players: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    return compile_player_intents_to_requests(player_intents, players, pools, markets)


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
    pools = sample_pools()
    markets = sample_markets()
    players = sample_players()
    player_intents = sample_player_intents(players, pools, markets)
    accounts = sample_accounts()
    requests = sample_transaction_requests(player_intents, players, pools, markets)
    block = sample_block_from_requests(requests)

    print("POOLS")
    print(to_json(pools))
    print()
    print("MARKETS")
    print(to_json(markets))
    print()
    print("PLAYERS")
    print(to_json(players))
    print()
    print("PLAYER INTENTS")
    print(to_json(player_intents))
    print()
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
