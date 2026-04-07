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
import math
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
DEFAULT_SLOTS_PER_EPOCH = 32
STAKE_WARMUP_COOLDOWN_RATE = 0.25
MARKET_PRICE_SCALE = 1_000_000
CONSTANT_PRODUCT_SWAP_FEE_BPS = 30
STABLE_SWAP_FEE_BPS = 4
WEIGHTED_SWAP_FEE_BPS = 20

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

REGISTRY_STATUS_ACTIVE = "active"
REGISTRY_STATUS_INACTIVE = "inactive"
REGISTRY_STATUS_EXITING = "exiting"
REGISTRY_STATUS_DEREGISTERED = "deregistered"

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


def decode_system_transfer_data(data: list[int]) -> dict[str, int]:
    discriminator, lamports = struct.unpack("<IQ", bytes(data))
    if discriminator != 2:
        raise ValueError("unsupported system instruction discriminator")
    return {"lamports": lamports}


def decode_pool_swap_data(data: list[int]) -> dict[str, int | str]:
    swap_mode_flag, amount, other_amount_threshold = struct.unpack("<BQQ", bytes(data))
    if swap_mode_flag == 0:
        swap_mode = SWAP_MODE_EXACT_INPUT
    elif swap_mode_flag == 1:
        swap_mode = SWAP_MODE_EXACT_OUTPUT
    else:
        raise ValueError("unsupported pool swap mode flag")
    return {
        "swap_mode": swap_mode,
        "amount": amount,
        "other_amount_threshold": other_amount_threshold,
    }


def decode_pool_liquidity_add_data(data: list[int]) -> dict[str, int]:
    max_token_a_amount, max_token_b_amount, min_lp_tokens_out = struct.unpack("<QQQ", bytes(data))
    return {
        "max_token_a_amount": max_token_a_amount,
        "max_token_b_amount": max_token_b_amount,
        "min_lp_tokens_out": min_lp_tokens_out,
    }


def decode_market_swap_data(data: list[int]) -> dict[str, int | str]:
    side_flag, order_type_flag, base_amount, quote_amount_limit, limit_price = struct.unpack(
        "<BBQQQ", bytes(data)
    )
    if side_flag == 0:
        side = MARKET_SIDE_BUY
    elif side_flag == 1:
        side = MARKET_SIDE_SELL
    else:
        raise ValueError("unsupported market side flag")

    if order_type_flag == 0:
        order_type = MARKET_ORDER_TYPE_MARKET
    elif order_type_flag == 1:
        order_type = MARKET_ORDER_TYPE_LIMIT
    else:
        raise ValueError("unsupported market order type flag")

    return {
        "side": side,
        "order_type": order_type,
        "base_amount": base_amount,
        "quote_amount_limit": quote_amount_limit,
        "limit_price": limit_price,
    }


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


def build_validator_profile(
    validator_id: str,
    identity_account: str,
    vote_account: str,
    activated_stake_lamports: int,
    self_stake_lamports: int = 0,
    commission_bps: int = 0,
    delegator_count: int = 0,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a simplified validator registry entry.

    Validators are network participants that receive transaction flow, produce blocks, and later
    can participate in stake-weighted leader selection and consensus logic.

    For a more Solana-like PoS model, it is important to separate the validator itself from the
    stake delegated to it:
    - the identity account represents the validator operator
    - the vote account is the on-chain account that receives delegated stake
    - activated stake is the currently effective stake weight behind that vote account

    Real Solana staking uses separate stake accounts with stake / withdraw authorities and epoch
    warmup-cooldown behavior. This validator object is therefore a summary view, not the full
    stake-account model, but it now keeps the fields you will want later for PoS scheduling.
    """
    if self_stake_lamports > activated_stake_lamports:
        raise ValueError("self_stake_lamports cannot exceed activated_stake_lamports")

    return {
        "validator_id": validator_id,
        "identity_account": identity_account,
        "vote_account": vote_account,
        "activated_stake_lamports": activated_stake_lamports,
        "self_stake_lamports": self_stake_lamports,
        "delegated_stake_lamports": activated_stake_lamports - self_stake_lamports,
        "activating_stake_lamports": 0,
        "deactivating_stake_lamports": 0,
        # Keep the old name as a compatibility alias while the rest of the simulator still grows.
        "stake_lamports": activated_stake_lamports,
        "commission_bps": commission_bps,
        "delegator_count": delegator_count,
        "fees_earned_lamports": 0,
        "staking_rewards_earned_lamports": 0,
        "withdrawable_stake_lamports": 0,
        "produced_block_count": 0,
        "last_produced_slot": None,
        "last_vote_slot": None,
        "root_slot": None,
        "epoch_credits": [],
        "is_delinquent": False,
        "status": REGISTRY_STATUS_ACTIVE,
        "deactivation_requested_epoch": None,
        "effective_exit_epoch": None,
        "deregistered_at_slot": None,
        "metadata": metadata or {},
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
        "status": REGISTRY_STATUS_ACTIVE,
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
    _pools: dict[str, dict[str, Any]],
    _markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a market maker.

    Market makers typically place market-venue liquidity and move inventory where needed. In
    this first pass we model that as:
    - funding a general liquidity wallet
    - posting a limit-style market trade on the spot venue
    """
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
    _pools: dict[str, dict[str, Any]],
    _markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a liquidity provider.

    LPs interact with pools rather than central-limit-order-book style markets. Their first
    modeled behavior is adding inventory to a volatile constant-product pool.
    """
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_LIQUIDITY_ADD,
            venue_type="pool",
            venue_id="volatile_sol_usdc",
            parameters={
                "max_token_amounts": [400_000_000, 900_000_000],
                "min_lp_tokens_out": 9_500_000,
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
    _pools: dict[str, dict[str, Any]],
    _markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a retail user.

    Retail flow is usually mixed: ordinary payments plus venue interaction. We model both a
    merchant payment and a spot-market market order from the same player profile.
    """
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
    _pools: dict[str, dict[str, Any]],
    _markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for an arbitrageur.

    Arbitrageurs care about fast pool-to-price dislocations, so they emit high-priority swap
    flow against volatile pools.
    """
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
    _pools: dict[str, dict[str, Any]],
    _markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a router.

    Routers optimize path selection and execution quality, so this sample sends a v0 stable-pool
    swap using a lookup table and exact-output semantics.
    """
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
                "other_amount_threshold": 101_000_000,
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
    _pools: dict[str, dict[str, Any]],
    _markets: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Generate sample intents for a portfolio rebalancer.

    Rebalancers trade toward target allocations rather than short-term prices, so this sample
    interacts with the weighted multi-token pool.
    """
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
                "other_amount_threshold": 58_000_000,
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
        "confirmed_transaction_count": sum(tx["status"] == "confirmed" for tx in transactions),
        "rejected_transaction_count": sum(tx["status"] == "rejected" for tx in transactions),
        "total_fees_lamports": sum(
            tx["meta"].get("fee_charged_lamports", tx["meta"]["fee_lamports"])
            for tx in transactions
        ),
        "transactions": deepcopy(transactions),
    }
    block["block_hash"] = stable_hash(block)

    for transaction in block["transactions"]:
        transaction["block_id"] = block["block_id"]
        transaction["block_hash"] = block["block_hash"]

    return block


def get_required_account(accounts: dict[str, dict[str, Any]], pubkey: str) -> dict[str, Any]:
    account = accounts.get(pubkey)
    if account is None:
        raise ValueError(f"missing account: {pubkey}")
    return account


def ensure_account_state(
    accounts: dict[str, dict[str, Any]],
    pubkey: str,
    owner: str,
) -> dict[str, Any]:
    account = accounts.get(pubkey)
    if account is None:
        account = build_account_state(lamports=0, owner=owner, data=[])
        accounts[pubkey] = account
    return account


def record_account_activity(account: dict[str, Any], marker: int) -> None:
    account["data"].append(marker & 0xFF)


def fee_bps_for_pool(pool: dict[str, Any]) -> int:
    if pool["pool_type"] == POOL_TYPE_CONSTANT_PRODUCT:
        return CONSTANT_PRODUCT_SWAP_FEE_BPS
    if pool["pool_type"] == POOL_TYPE_STABLE_SWAP:
        return STABLE_SWAP_FEE_BPS
    return WEIGHTED_SWAP_FEE_BPS


def pool_output_for_exact_input(
    pool: dict[str, Any],
    source_reserve: int,
    destination_reserve: int,
    source_index: int,
    destination_index: int,
    net_input_amount: int,
) -> int:
    if net_input_amount <= 0 or source_reserve <= 0 or destination_reserve <= 0:
        return 0

    if pool["pool_type"] == POOL_TYPE_CONSTANT_PRODUCT:
        return (destination_reserve * net_input_amount) // (source_reserve + net_input_amount)

    if pool["pool_type"] == POOL_TYPE_STABLE_SWAP:
        amplification_factor = max(pool.get("amplification_factor") or 1, 1)
        numerator = destination_reserve * net_input_amount * amplification_factor
        denominator = source_reserve * amplification_factor + net_input_amount
        return min(destination_reserve, numerator // max(denominator, 1))

    weight_in = pool["normalized_weights_bps"][source_index] / 10_000
    weight_out = pool["normalized_weights_bps"][destination_index] / 10_000
    base_ratio = source_reserve / (source_reserve + net_input_amount)
    output = destination_reserve * (1 - (base_ratio ** (weight_in / max(weight_out, 1e-9))))
    return max(0, min(destination_reserve, int(output)))


def required_input_for_exact_output(
    pool: dict[str, Any],
    source_reserve: int,
    destination_reserve: int,
    source_index: int,
    destination_index: int,
    desired_output_amount: int,
    max_total_input_amount: int,
) -> tuple[int, int] | None:
    if desired_output_amount <= 0 or desired_output_amount >= destination_reserve:
        return None

    fee_bps = fee_bps_for_pool(pool)
    low = 1
    high = max_total_input_amount
    best_total_input = None
    best_net_input = None

    while low <= high:
        mid = (low + high) // 2
        fee_amount = (mid * fee_bps) // 10_000
        if fee_amount >= mid:
            fee_amount = max(mid - 1, 0)
        net_input_amount = mid - fee_amount
        output_amount = pool_output_for_exact_input(
            pool=pool,
            source_reserve=source_reserve,
            destination_reserve=destination_reserve,
            source_index=source_index,
            destination_index=destination_index,
            net_input_amount=net_input_amount,
        )
        if output_amount >= desired_output_amount:
            best_total_input = mid
            best_net_input = net_input_amount
            high = mid - 1
        else:
            low = mid + 1

    if best_total_input is None or best_net_input is None:
        return None
    return best_total_input, best_net_input


def estimate_market_quote_amount(
    side: str,
    order_type: str,
    base_amount: int,
    quote_amount_limit: int,
    limit_price: int,
) -> int:
    if base_amount <= 0:
        return 0

    if order_type == MARKET_ORDER_TYPE_MARKET or limit_price == 0:
        return quote_amount_limit

    price_based_quote_amount = max(1, (base_amount * limit_price) // MARKET_PRICE_SCALE)
    if side == MARKET_SIDE_BUY:
        return min(quote_amount_limit, price_based_quote_amount)
    return max(quote_amount_limit, price_based_quote_amount)


def refresh_runtime_views(blockchain_state: dict[str, Any]) -> None:
    accounts = blockchain_state["accounts"]

    for pool in blockchain_state["pools"].values():
        runtime_state = pool.setdefault("runtime_state", {})
        runtime_state.setdefault("swap_count", 0)
        runtime_state.setdefault("liquidity_add_count", 0)
        runtime_state["last_observed_reserves"] = [
            get_required_account(accounts, vault_account)["lamports"]
            for vault_account in pool["pool_vault_accounts"]
        ]
        runtime_state["lp_supply"] = get_required_account(accounts, pool["pool_lp_mint"])["lamports"]
        runtime_state["fee_vault_balance"] = get_required_account(accounts, pool["pool_fee_vault"])[
            "lamports"
        ]

    for market in blockchain_state["markets"].values():
        runtime_state = market.setdefault("runtime_state", {})
        runtime_state.setdefault("trade_count", 0)
        runtime_state.setdefault("base_volume", 0)
        runtime_state.setdefault("quote_volume", 0)
        runtime_state.setdefault("last_trade_price", None)
        runtime_state["base_vault_balance"] = get_required_account(
            accounts, market["base_vault_account"]
        )["lamports"]
        runtime_state["quote_vault_balance"] = get_required_account(
            accounts, market["quote_vault_account"]
        )["lamports"]


def build_blockchain_state(
    accounts: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
    players: dict[str, dict[str, Any]],
    validators: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Build the persistent simulation state for the blockchain.

    This is the missing layer between one-off block creation and a running chain. It stores the
    live account state, venue definitions, registered players and validators, the pending request
    queue, and the ordered block history.
    """
    genesis_hash = stable_hash(
        {
            "accounts": accounts,
            "pools": pools,
            "markets": markets,
            "players": players,
            "validators": validators or {},
        }
    )
    blockchain_state = {
        "chain_id": make_id("chain"),
        "genesis_hash": genesis_hash,
        "head_block_hash": genesis_hash,
        "head_slot": 0,
        "next_slot": 1,
        "current_epoch": 0,
        "epoch_schedule": {"slots_per_epoch": DEFAULT_SLOTS_PER_EPOCH},
        "accounts": deepcopy(accounts),
        "pools": deepcopy(pools),
        "markets": deepcopy(markets),
        "players": deepcopy(players),
        "validators": deepcopy(validators or {}),
        "leader_schedules": {},
        "pending_requests": [],
        "processed_request_ids": [],
        "blocks": [],
        "stats": {
            "block_count": 0,
            "processed_request_count": 0,
            "confirmed_transaction_count": 0,
            "rejected_transaction_count": 0,
            "total_fees_lamports": 0,
        },
    }
    refresh_runtime_views(blockchain_state)
    return blockchain_state


def register_validator(
    blockchain_state: dict[str, Any],
    validator_profile: dict[str, Any],
) -> dict[str, Any]:
    """
    Register a validator into the live chain state.

    This is the runtime registration path for growing the validator set after the chain has been
    initialized. The simulator keeps this as a direct state mutation for now rather than modeling
    validator registration as an on-chain transaction.
    """
    validator_id = validator_profile["validator_id"]
    if validator_id in blockchain_state["validators"]:
        raise ValueError(f"validator already registered: {validator_id}")

    for existing_validator in blockchain_state["validators"].values():
        if existing_validator["identity_account"] == validator_profile["identity_account"]:
            raise ValueError("validator identity account is already registered")
        if existing_validator["vote_account"] == validator_profile["vote_account"]:
            raise ValueError("validator vote account is already registered")

    identity_account = ensure_account_state(
        blockchain_state["accounts"],
        validator_profile["identity_account"],
        owner=SYSTEM_PROGRAM_ID,
    )
    vote_account = ensure_account_state(
        blockchain_state["accounts"],
        validator_profile["vote_account"],
        owner=VOTE_PROGRAM_ID,
    )
    if identity_account["owner"] != SYSTEM_PROGRAM_ID:
        raise ValueError("validator identity account must be a system account")
    if vote_account["owner"] != VOTE_PROGRAM_ID:
        raise ValueError("validator vote account must be a vote account")

    validator_copy = deepcopy(validator_profile)
    validator_copy["registered_at_slot"] = blockchain_state["head_slot"]
    blockchain_state["validators"][validator_id] = validator_copy
    blockchain_state["leader_schedules"].clear()
    return validator_copy


def register_player(
    blockchain_state: dict[str, Any],
    player_profile: dict[str, Any],
) -> dict[str, Any]:
    """
    Register a player into the live chain state.

    Players are simulation-side actors rather than consensus participants, but runtime
    registration is still useful because it lets the market population change over time instead
    of staying frozen in the initial sample set.
    """
    player_id = player_profile["player_id"]
    if player_id in blockchain_state["players"]:
        raise ValueError(f"player already registered: {player_id}")

    for existing_player in blockchain_state["players"].values():
        if existing_player["authority_account"] == player_profile["authority_account"]:
            raise ValueError("player authority account is already registered")
        existing_token_accounts = set(existing_player["token_accounts"].values())
        new_token_accounts = set(player_profile["token_accounts"].values())
        if existing_token_accounts & new_token_accounts:
            raise ValueError("player token account is already registered")

    authority_account = ensure_account_state(
        blockchain_state["accounts"],
        player_profile["authority_account"],
        owner=SYSTEM_PROGRAM_ID,
    )
    if authority_account["owner"] != SYSTEM_PROGRAM_ID:
        raise ValueError("player authority account must be a system account")

    for token_account_pubkey in player_profile["token_accounts"].values():
        token_account = ensure_account_state(
            blockchain_state["accounts"],
            token_account_pubkey,
            owner=TOKEN_PROGRAM_ID,
        )
        if token_account["owner"] != TOKEN_PROGRAM_ID:
            raise ValueError("player token accounts must be token-program accounts")

    player_copy = deepcopy(player_profile)
    player_copy["registered_at_slot"] = blockchain_state["head_slot"]
    player_copy.setdefault("submitted_request_count", 0)
    player_copy.setdefault("last_active_slot", None)
    blockchain_state["players"][player_id] = player_copy
    return player_copy


def set_player_status(
    blockchain_state: dict[str, Any],
    player_id: str,
    status: str,
) -> dict[str, Any]:
    """
    Update a registered player's lifecycle status.

    This is a non-destructive control switch:
    - `active`: the player may submit new requests
    - `inactive`: the player stays in the registry/history but is paused
    - `deregistered`: the player has left the active simulation population

    Example reasons:
    - a retail user becomes `inactive` overnight and trades again tomorrow
    - an arbitrage bot becomes `inactive` during maintenance
    - a bankrupt market maker or a merchant leaving the platform becomes `deregistered`

    That is different from deleting a player object entirely. Keeping the registry entry is
    usually better for analytics, history, and debugging.
    """
    if status not in {
        REGISTRY_STATUS_ACTIVE,
        REGISTRY_STATUS_INACTIVE,
        REGISTRY_STATUS_DEREGISTERED,
    }:
        raise ValueError("invalid player status")

    player = blockchain_state["players"].get(player_id)
    if player is None:
        raise ValueError(f"unknown player: {player_id}")

    if status == REGISTRY_STATUS_DEREGISTERED:
        pending_request_ids = [
            request_tx["request_id"]
            for request_tx in blockchain_state["pending_requests"]
            if request_tx["agent_id"] == player_id
        ]
        if pending_request_ids:
            raise ValueError("cannot deregister player while they still have pending requests")

    player["status"] = status
    player["status_updated_at_slot"] = blockchain_state["head_slot"]
    if status == REGISTRY_STATUS_DEREGISTERED:
        player["deregistered_at_slot"] = blockchain_state["head_slot"]
    return player


def deregister_player(
    blockchain_state: dict[str, Any],
    player_id: str,
) -> dict[str, Any]:
    """
    Deregister a player from the active simulation population.

    Deregistration is implemented as a status transition rather than hard deletion so historical
    requests, balances, and analytics still have a stable player reference.

    Typical examples are a player going bankrupt, a strategy being retired permanently, or a
    merchant leaving the simulated ecosystem.
    """
    return set_player_status(
        blockchain_state,
        player_id,
        REGISTRY_STATUS_DEREGISTERED,
    )


def estimate_validator_exit_epochs(
    blockchain_state: dict[str, Any],
    validator_id: str,
) -> int:
    """
    Estimate how many epochs validator exit should take in this simulator.

    Solana does not use a fixed "validator exits in N epochs" rule. The official staking docs
    describe warmup/cooldown as rate-limited at the network level, with at most 25% of total
    active stake activating or deactivating per epoch. That means deactivation can take several
    epochs depending on how much stake is moving.

    This simulator approximates that by using:
    `ceil(validator_active_stake / (total_active_stake * 25%))`, with a minimum of 1 epoch.
    It is a simplification, but it keeps the core Solana property that larger stake exits take
    longer and that exit delay is not a single fixed constant.
    """
    validator = blockchain_state["validators"].get(validator_id)
    if validator is None:
        raise ValueError(f"unknown validator: {validator_id}")

    total_active_stake = sum(
        existing_validator["activated_stake_lamports"]
        for existing_validator in blockchain_state["validators"].values()
        if existing_validator["status"] in {REGISTRY_STATUS_ACTIVE, REGISTRY_STATUS_EXITING}
    )
    if total_active_stake <= 0 or validator["activated_stake_lamports"] <= 0:
        return 1

    epoch_deactivation_capacity = max(
        int(total_active_stake * STAKE_WARMUP_COOLDOWN_RATE),
        1,
    )
    return max(
        1,
        math.ceil(validator["activated_stake_lamports"] / epoch_deactivation_capacity),
    )


def set_validator_status(
    blockchain_state: dict[str, Any],
    validator_id: str,
    status: str,
) -> dict[str, Any]:
    """
    Update a registered validator's lifecycle status.

    Validators use the same status pattern as players, but changing validator status also clears
    cached leader schedules because the eligible producer set may have changed.

    Example reasons:
    - a validator becomes `inactive` for maintenance or an operator outage
    - a validator enters `exiting` after requesting stake deactivation
    - a validator becomes `deregistered` after the simulated cooldown finishes
    """
    if status not in {
        REGISTRY_STATUS_ACTIVE,
        REGISTRY_STATUS_INACTIVE,
        REGISTRY_STATUS_EXITING,
        REGISTRY_STATUS_DEREGISTERED,
    }:
        raise ValueError("invalid validator status")

    validator = blockchain_state["validators"].get(validator_id)
    if validator is None:
        raise ValueError(f"unknown validator: {validator_id}")

    if status == REGISTRY_STATUS_DEREGISTERED and validator["deactivating_stake_lamports"] > 0:
        raise ValueError("validator cannot fully deregister while stake is still deactivating")

    validator["status"] = status
    validator["status_updated_at_slot"] = blockchain_state["head_slot"]
    if status == REGISTRY_STATUS_DEREGISTERED:
        validator["deregistered_at_slot"] = blockchain_state["head_slot"]
    blockchain_state["leader_schedules"].clear()
    return validator


def deregister_validator(
    blockchain_state: dict[str, Any],
    validator_id: str,
) -> dict[str, Any]:
    """
    Begin validator deregistration using a Solana-style delayed exit approximation.

    Solana stake deactivation is not an instant one-epoch action. The docs describe deactivation
    as epoch-boundary based and globally rate-limited, with at most 25% of total active stake
    activating or deactivating in one epoch. This simulator therefore puts the validator into an
    `exiting` state first and estimates an `effective_exit_epoch` from the current active stake.

    Typical examples are a validator operator permanently leaving the network, shutting down the
    business, or intentionally removing delegated stake from future leader rotation.
    """
    validator = blockchain_state["validators"].get(validator_id)
    if validator is None:
        raise ValueError(f"unknown validator: {validator_id}")
    if validator["status"] == REGISTRY_STATUS_DEREGISTERED:
        return validator

    exit_epochs = estimate_validator_exit_epochs(blockchain_state, validator_id)
    validator["deactivation_requested_epoch"] = blockchain_state["current_epoch"]
    validator["effective_exit_epoch"] = blockchain_state["current_epoch"] + exit_epochs
    validator["deactivating_stake_lamports"] = validator["activated_stake_lamports"]
    validator["status_updated_at_slot"] = blockchain_state["head_slot"]
    blockchain_state["leader_schedules"].clear()
    return set_validator_status(
        blockchain_state,
        validator_id,
        REGISTRY_STATUS_EXITING,
    )


def validator_is_schedulable_for_epoch(
    validator: dict[str, Any],
    epoch: int,
) -> bool:
    """Return True when a validator should still count for leader selection in an epoch."""
    if validator["is_delinquent"] or validator["activated_stake_lamports"] <= 0:
        return False
    if validator["status"] == REGISTRY_STATUS_ACTIVE:
        return True
    if validator["status"] == REGISTRY_STATUS_EXITING:
        effective_exit_epoch = validator.get("effective_exit_epoch")
        return effective_exit_epoch is None or epoch < effective_exit_epoch
    return False


def active_validators(
    blockchain_state: dict[str, Any],
    epoch: int | None = None,
) -> list[dict[str, Any]]:
    """Return validators eligible for leader selection in deterministic order."""
    if epoch is None:
        epoch = blockchain_state["current_epoch"]
    return sorted(
        [
            validator
            for validator in blockchain_state["validators"].values()
            if validator_is_schedulable_for_epoch(validator, epoch)
        ],
        key=lambda validator: validator["validator_id"],
    )


def pick_validator_by_stake(
    validators: list[dict[str, Any]],
    selection_value: int,
) -> str:
    """Pick one validator from a stake-weighted list using a deterministic integer."""
    total_active_stake = sum(validator["activated_stake_lamports"] for validator in validators)
    if total_active_stake <= 0:
        raise ValueError("leader selection requires positive active stake")

    cursor = selection_value % total_active_stake
    running_total = 0
    for validator in validators:
        running_total += validator["activated_stake_lamports"]
        if cursor < running_total:
            return validator["validator_id"]

    return validators[-1]["validator_id"]


def build_leader_schedule_for_epoch(
    blockchain_state: dict[str, Any],
    epoch: int,
) -> dict[str, Any]:
    """
    Build a simplified deterministic stake-weighted leader schedule for one epoch.

    This is intentionally lighter than Solana's real schedule generation, but it keeps the core
    property we need next: validators with more activated stake should be scheduled more often.
    """
    cached_schedule = blockchain_state["leader_schedules"].get(epoch)
    if cached_schedule is not None:
        return deepcopy(cached_schedule)

    eligible_validators = active_validators(blockchain_state, epoch=epoch)
    if not eligible_validators:
        raise ValueError("cannot build leader schedule without active validators")

    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    first_slot = epoch * slots_per_epoch + 1
    leaders_by_slot = {}
    validator_weights = {
        validator["validator_id"]: validator["activated_stake_lamports"]
        for validator in eligible_validators
    }

    for relative_slot in range(slots_per_epoch):
        slot = first_slot + relative_slot
        selection_value = int(
            stable_hash(
                {
                    "chain_id": blockchain_state["chain_id"],
                    "epoch": epoch,
                    "slot": slot,
                    "validator_weights": validator_weights,
                }
            ),
            16,
        )
        leaders_by_slot[slot] = pick_validator_by_stake(eligible_validators, selection_value)

    schedule = {
        "epoch": epoch,
        "first_slot": first_slot,
        "last_slot": first_slot + slots_per_epoch - 1,
        "slots_per_epoch": slots_per_epoch,
        "validator_weights": validator_weights,
        "leaders_by_slot": leaders_by_slot,
    }
    blockchain_state["leader_schedules"][epoch] = deepcopy(schedule)
    return schedule


def select_leader_for_slot(
    blockchain_state: dict[str, Any],
    slot: int,
) -> str:
    """Select the scheduled leader for a slot from the current epoch schedule."""
    if slot <= 0:
        raise ValueError("slot must be positive")

    epoch = (slot - 1) // blockchain_state["epoch_schedule"]["slots_per_epoch"]
    schedule = build_leader_schedule_for_epoch(blockchain_state, epoch)
    return schedule["leaders_by_slot"][slot]


def finalize_validator_epoch_transitions(blockchain_state: dict[str, Any]) -> None:
    """
    Finalize validator exits whose cooldown has completed.

    Exiting validators remain in the registry for history, but once the current epoch reaches
    their `effective_exit_epoch` they stop counting as active stake and move to `deregistered`.
    """
    for validator in blockchain_state["validators"].values():
        if validator["status"] != REGISTRY_STATUS_EXITING:
            continue
        effective_exit_epoch = validator.get("effective_exit_epoch")
        if effective_exit_epoch is None or blockchain_state["current_epoch"] < effective_exit_epoch:
            continue

        validator["withdrawable_stake_lamports"] += validator["deactivating_stake_lamports"]
        validator["activated_stake_lamports"] = 0
        validator["delegated_stake_lamports"] = 0
        validator["self_stake_lamports"] = 0
        validator["stake_lamports"] = 0
        validator["deactivating_stake_lamports"] = 0
        validator["deregistered_at_slot"] = blockchain_state["head_slot"]
        validator["status"] = REGISTRY_STATUS_DEREGISTERED
        validator["status_updated_at_slot"] = blockchain_state["head_slot"]

    blockchain_state["leader_schedules"].clear()


def submit_transaction_request(
    blockchain_state: dict[str, Any],
    request_tx: dict[str, Any],
) -> dict[str, Any]:
    """
    Submit a transaction request into the chain state's pending queue.

    This is the mempool-like entry point used by simulated players and agents before validators
    select requests for block production.
    """
    request_id = request_tx["request_id"]
    pending_request_ids = {pending_request["request_id"] for pending_request in blockchain_state["pending_requests"]}
    processed_request_ids = set(blockchain_state["processed_request_ids"])
    if request_id in pending_request_ids or request_id in processed_request_ids:
        raise ValueError(f"duplicate request_id: {request_id}")

    if blockchain_state["players"]:
        player = blockchain_state["players"].get(request_tx["agent_id"])
        if player is None:
            raise ValueError(f"unregistered player submitted request: {request_tx['agent_id']}")
        if player["status"] != REGISTRY_STATUS_ACTIVE:
            raise ValueError(f"non-active player submitted request: {request_tx['agent_id']}")

    request_copy = deepcopy(request_tx)
    blockchain_state["pending_requests"].append(request_copy)
    if request_copy["agent_id"] in blockchain_state["players"]:
        player = blockchain_state["players"][request_copy["agent_id"]]
        player["submitted_request_count"] += 1
    return request_copy


def verify_block_parent_link(blockchain_state: dict[str, Any], block: dict[str, Any]) -> bool:
    """Return True when a candidate block extends the current chain head."""
    return (
        block["parent_block_hash"] == blockchain_state["head_block_hash"]
        and block["slot"] == blockchain_state["next_slot"]
    )


def apply_system_transfer_instruction(
    accounts: dict[str, dict[str, Any]],
    instruction: dict[str, Any],
) -> None:
    payload = decode_system_transfer_data(instruction["data"])
    lamports = payload["lamports"]
    sender_account = get_required_account(accounts, instruction["accounts"][0]["pubkey"])
    recipient_account = ensure_account_state(
        accounts, instruction["accounts"][1]["pubkey"], owner=SYSTEM_PROGRAM_ID
    )
    if sender_account["lamports"] < lamports:
        raise ValueError("system transfer sender balance too low")
    sender_account["lamports"] -= lamports
    recipient_account["lamports"] += lamports
    record_account_activity(sender_account, 101)
    record_account_activity(recipient_account, 102)


def apply_pool_swap_instruction(
    accounts: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    players: dict[str, dict[str, Any]],
    request_tx: dict[str, Any],
    instruction: dict[str, Any],
) -> None:
    venue_id = request_tx["metadata"].get("venue_id")
    player_id = request_tx["metadata"].get("player_id")
    if venue_id is None or player_id is None:
        raise ValueError("pool swap is missing venue_id or player_id metadata")

    pool = pools[venue_id]
    player = players[player_id]
    payload = decode_pool_swap_data(instruction["data"])
    trader_source_account_pubkey = instruction["accounts"][1]["pubkey"]
    trader_destination_account_pubkey = instruction["accounts"][2]["pubkey"]

    source_symbol = None
    destination_symbol = None
    for token_symbol, token_account in player["token_accounts"].items():
        if token_account == trader_source_account_pubkey:
            source_symbol = token_symbol
        if token_account == trader_destination_account_pubkey:
            destination_symbol = token_symbol

    if source_symbol is None or destination_symbol is None:
        raise ValueError("could not map pool swap accounts back to player token symbols")

    source_index = pool["token_symbols"].index(source_symbol)
    destination_index = pool["token_symbols"].index(destination_symbol)
    source_vault_pubkey = pool["pool_vault_accounts"][source_index]
    destination_vault_pubkey = pool["pool_vault_accounts"][destination_index]

    trader_source_account = get_required_account(accounts, trader_source_account_pubkey)
    trader_destination_account = get_required_account(accounts, trader_destination_account_pubkey)
    source_vault_account = get_required_account(accounts, source_vault_pubkey)
    destination_vault_account = get_required_account(accounts, destination_vault_pubkey)
    fee_vault_account = get_required_account(accounts, pool["pool_fee_vault"])
    pool_state_account = get_required_account(accounts, pool["pool_state_account"])

    source_reserve = source_vault_account["lamports"]
    destination_reserve = destination_vault_account["lamports"]
    fee_bps = fee_bps_for_pool(pool)

    if payload["swap_mode"] == SWAP_MODE_EXACT_INPUT:
        total_input_amount = int(payload["amount"])
        if trader_source_account["lamports"] < total_input_amount:
            raise ValueError("pool swap source balance too low")
        fee_amount = (total_input_amount * fee_bps) // 10_000
        if fee_amount >= total_input_amount:
            fee_amount = max(total_input_amount - 1, 0)
        net_input_amount = total_input_amount - fee_amount
        output_amount = pool_output_for_exact_input(
            pool=pool,
            source_reserve=source_reserve,
            destination_reserve=destination_reserve,
            source_index=source_index,
            destination_index=destination_index,
            net_input_amount=net_input_amount,
        )
        if output_amount < int(payload["other_amount_threshold"]):
            raise ValueError("pool swap output did not satisfy slippage threshold")
    else:
        desired_output_amount = int(payload["amount"])
        required_input = required_input_for_exact_output(
            pool=pool,
            source_reserve=source_reserve,
            destination_reserve=destination_reserve,
            source_index=source_index,
            destination_index=destination_index,
            desired_output_amount=desired_output_amount,
            max_total_input_amount=int(payload["other_amount_threshold"]),
        )
        if required_input is None:
            raise ValueError("pool swap exact-output request exceeded max input threshold")
        total_input_amount, net_input_amount = required_input
        if trader_source_account["lamports"] < total_input_amount:
            raise ValueError("pool swap source balance too low")
        fee_amount = total_input_amount - net_input_amount
        output_amount = desired_output_amount

    if destination_vault_account["lamports"] < output_amount:
        raise ValueError("pool destination vault balance too low")

    trader_source_account["lamports"] -= total_input_amount
    source_vault_account["lamports"] += net_input_amount
    fee_vault_account["lamports"] += fee_amount
    destination_vault_account["lamports"] -= output_amount
    trader_destination_account["lamports"] += output_amount
    record_account_activity(pool_state_account, 111)
    pools[venue_id].setdefault("runtime_state", {}).setdefault("swap_count", 0)
    pools[venue_id]["runtime_state"]["swap_count"] += 1


def apply_pool_liquidity_add_instruction(
    accounts: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    request_tx: dict[str, Any],
    instruction: dict[str, Any],
) -> None:
    venue_id = request_tx["metadata"].get("venue_id")
    if venue_id is None:
        raise ValueError("pool liquidity add is missing venue_id metadata")

    pool = pools[venue_id]
    payload = decode_pool_liquidity_add_data(instruction["data"])
    token_a_amount = payload["max_token_a_amount"]
    token_b_amount = payload["max_token_b_amount"]
    min_lp_tokens_out = payload["min_lp_tokens_out"]

    trader_source_account_a = get_required_account(accounts, instruction["accounts"][1]["pubkey"])
    trader_source_account_b = get_required_account(accounts, instruction["accounts"][2]["pubkey"])
    pool_state_account = get_required_account(accounts, instruction["accounts"][3]["pubkey"])
    pool_vault_a = get_required_account(accounts, instruction["accounts"][4]["pubkey"])
    pool_vault_b = get_required_account(accounts, instruction["accounts"][5]["pubkey"])
    pool_lp_mint = get_required_account(accounts, instruction["accounts"][6]["pubkey"])
    trader_lp_receipt_account = ensure_account_state(
        accounts, instruction["accounts"][7]["pubkey"], owner=TOKEN_PROGRAM_ID
    )

    if trader_source_account_a["lamports"] < token_a_amount or trader_source_account_b["lamports"] < token_b_amount:
        raise ValueError("liquidity provider source balance too low")

    reserve_a = max(pool_vault_a["lamports"], 1)
    reserve_b = max(pool_vault_b["lamports"], 1)
    lp_supply = max(pool_lp_mint["lamports"], 1)
    minted_lp_tokens = min(
        (token_a_amount * lp_supply) // reserve_a,
        (token_b_amount * lp_supply) // reserve_b,
    )
    if minted_lp_tokens < min_lp_tokens_out:
        raise ValueError("liquidity add did not satisfy minimum LP output")

    trader_source_account_a["lamports"] -= token_a_amount
    trader_source_account_b["lamports"] -= token_b_amount
    pool_vault_a["lamports"] += token_a_amount
    pool_vault_b["lamports"] += token_b_amount
    pool_lp_mint["lamports"] += minted_lp_tokens
    trader_lp_receipt_account["lamports"] += minted_lp_tokens
    record_account_activity(pool_state_account, 112)
    pools[venue_id].setdefault("runtime_state", {}).setdefault("liquidity_add_count", 0)
    pools[venue_id]["runtime_state"]["liquidity_add_count"] += 1


def apply_market_trade_instruction(
    accounts: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
    request_tx: dict[str, Any],
    instruction: dict[str, Any],
) -> None:
    venue_id = request_tx["metadata"].get("venue_id")
    if venue_id is None:
        raise ValueError("market trade is missing venue_id metadata")

    market = markets[venue_id]
    payload = decode_market_swap_data(instruction["data"])
    base_amount = int(payload["base_amount"])
    quote_amount = estimate_market_quote_amount(
        side=str(payload["side"]),
        order_type=str(payload["order_type"]),
        base_amount=base_amount,
        quote_amount_limit=int(payload["quote_amount_limit"]),
        limit_price=int(payload["limit_price"]),
    )
    if quote_amount <= 0:
        raise ValueError("market trade quote amount must be positive")

    trader_base_account = get_required_account(accounts, instruction["accounts"][1]["pubkey"])
    trader_quote_account = get_required_account(accounts, instruction["accounts"][2]["pubkey"])
    open_orders_account = get_required_account(accounts, instruction["accounts"][3]["pubkey"])
    event_queue_account = get_required_account(accounts, instruction["accounts"][4]["pubkey"])
    market_state_account = get_required_account(accounts, instruction["accounts"][5]["pubkey"])
    bids_account = get_required_account(accounts, instruction["accounts"][6]["pubkey"])
    asks_account = get_required_account(accounts, instruction["accounts"][7]["pubkey"])
    base_vault_account = get_required_account(accounts, instruction["accounts"][8]["pubkey"])
    quote_vault_account = get_required_account(accounts, instruction["accounts"][9]["pubkey"])

    if payload["side"] == MARKET_SIDE_BUY:
        if trader_quote_account["lamports"] < quote_amount:
            raise ValueError("market buy quote balance too low")
        if base_vault_account["lamports"] < base_amount:
            raise ValueError("market buy base vault balance too low")
        trader_quote_account["lamports"] -= quote_amount
        quote_vault_account["lamports"] += quote_amount
        base_vault_account["lamports"] -= base_amount
        trader_base_account["lamports"] += base_amount
        record_account_activity(bids_account, 121)
    else:
        if trader_base_account["lamports"] < base_amount:
            raise ValueError("market sell base balance too low")
        if quote_vault_account["lamports"] < quote_amount:
            raise ValueError("market sell quote vault balance too low")
        trader_base_account["lamports"] -= base_amount
        base_vault_account["lamports"] += base_amount
        quote_vault_account["lamports"] -= quote_amount
        trader_quote_account["lamports"] += quote_amount
        record_account_activity(asks_account, 122)

    record_account_activity(open_orders_account, 123)
    record_account_activity(event_queue_account, 124)
    record_account_activity(market_state_account, 125)
    runtime_state = markets[venue_id].setdefault("runtime_state", {})
    runtime_state["trade_count"] = runtime_state.get("trade_count", 0) + 1
    runtime_state["base_volume"] = runtime_state.get("base_volume", 0) + base_amount
    runtime_state["quote_volume"] = runtime_state.get("quote_volume", 0) + quote_amount
    runtime_state["last_trade_price"] = (quote_amount * MARKET_PRICE_SCALE) // max(base_amount, 1)


def mark_transaction_rejected(
    transaction_record: dict[str, Any],
    error_code: str,
    details: dict[str, Any],
) -> None:
    transaction_record["status"] = "rejected"
    transaction_record["meta"]["err"] = {error_code: details}
    transaction_record["meta"]["log_messages"].append(f"state transition rejected: {error_code}")


def apply_transaction_to_state(
    blockchain_state: dict[str, Any],
    request_tx: dict[str, Any],
    transaction_record: dict[str, Any],
) -> dict[str, Any]:
    """
    Apply one materialized transaction to chain state.

    Transaction execution is modeled atomically: fees are charged first, but instruction-side
    state changes commit only if every instruction succeeds. If execution fails, the fee stays
    charged and the rest of the state is rolled back.
    """
    accounts = blockchain_state["accounts"]
    validators = blockchain_state["validators"]
    fee_payer = get_required_account(accounts, request_tx["fee_payer"])
    fee_lamports = transaction_record["meta"]["fee_lamports"]

    if fee_payer["lamports"] < fee_lamports:
        transaction_record["meta"]["fee_charged_lamports"] = 0
        mark_transaction_rejected(
            transaction_record,
            "insufficient_fee_balance",
            {
                "fee_payer": request_tx["fee_payer"],
                "fee_lamports": fee_lamports,
                "available_lamports": fee_payer["lamports"],
            },
        )
        refresh_runtime_views(blockchain_state)
        return transaction_record

    fee_payer["lamports"] -= fee_lamports
    transaction_record["meta"]["fee_charged_lamports"] = fee_lamports
    validator = validators.get(transaction_record["validator_id"])
    if validator is not None:
        validator["fees_earned_lamports"] += fee_lamports
    player = blockchain_state["players"].get(request_tx["agent_id"])
    if player is not None:
        player["last_active_slot"] = transaction_record["slot"]

    if transaction_record["status"] != "confirmed":
        transaction_record["meta"]["log_messages"].append(
            "state application skipped because transaction was already rejected"
        )
        refresh_runtime_views(blockchain_state)
        return transaction_record

    trial_accounts = deepcopy(accounts)
    trial_pools = deepcopy(blockchain_state["pools"])
    trial_markets = deepcopy(blockchain_state["markets"])

    try:
        for instruction in request_tx["instructions"]:
            if instruction["program_id"] == SYSTEM_PROGRAM_ID:
                apply_system_transfer_instruction(trial_accounts, instruction)
            elif instruction["program_id"] == AMM_SIM_PROGRAM_ID:
                if len(instruction["data"]) == struct.calcsize("<BQQ"):
                    apply_pool_swap_instruction(
                        trial_accounts,
                        trial_pools,
                        blockchain_state["players"],
                        request_tx,
                        instruction,
                    )
                elif len(instruction["data"]) == struct.calcsize("<QQQ"):
                    apply_pool_liquidity_add_instruction(
                        trial_accounts,
                        trial_pools,
                        request_tx,
                        instruction,
                    )
                else:
                    raise ValueError("unsupported AMM instruction payload shape")
            elif instruction["program_id"] == MARKET_SIM_PROGRAM_ID:
                apply_market_trade_instruction(
                    trial_accounts,
                    trial_markets,
                    request_tx,
                    instruction,
                )
            else:
                raise ValueError(f"unsupported program_id in state application: {instruction['program_id']}")
    except ValueError as exc:
        mark_transaction_rejected(
            transaction_record,
            "state_transition_failed",
            {"reason": str(exc)},
        )
        refresh_runtime_views(blockchain_state)
        return transaction_record

    blockchain_state["accounts"] = trial_accounts
    blockchain_state["pools"] = trial_pools
    blockchain_state["markets"] = trial_markets
    refresh_runtime_views(blockchain_state)
    transaction_record["meta"]["log_messages"].append("state transition applied")
    return transaction_record


def produce_block(
    blockchain_state: dict[str, Any],
    leader_id: str | None = None,
    max_transactions: int | None = None,
) -> dict[str, Any]:
    """
    Materialize a block candidate from the current pending request queue.

    This previews validator processing against a copy of the current chain state so transaction
    statuses reflect sequential execution before the block is actually appended.
    """
    if not blockchain_state["pending_requests"]:
        raise ValueError("no pending requests to include in a block")

    slot = blockchain_state["next_slot"]
    scheduled_leader_id = None
    if blockchain_state["validators"]:
        scheduled_leader_id = select_leader_for_slot(blockchain_state, slot)
        if leader_id is None:
            leader_id = scheduled_leader_id

    if leader_id is None:
        raise ValueError("leader_id is required when no validators are registered")
    if blockchain_state["validators"] and leader_id not in blockchain_state["validators"]:
        raise ValueError(f"unknown validator: {leader_id}")
    if blockchain_state["validators"]:
        leader = blockchain_state["validators"][leader_id]
        leader_epoch = (slot - 1) // blockchain_state["epoch_schedule"]["slots_per_epoch"]
        if not validator_is_schedulable_for_epoch(leader, leader_epoch):
            raise ValueError(f"validator is not eligible to produce block in slot {slot}: {leader_id}")

    if max_transactions is None:
        selected_requests = list(blockchain_state["pending_requests"])
    else:
        selected_requests = list(blockchain_state["pending_requests"][:max_transactions])
    if not selected_requests:
        raise ValueError("max_transactions selected zero requests")

    preview_state = deepcopy(blockchain_state)
    transactions = []
    for request_tx in selected_requests:
        transaction_record = materialize_transaction(request_tx, validator_id=leader_id, slot=slot)
        apply_transaction_to_state(preview_state, request_tx, transaction_record)
        transactions.append(transaction_record)

    block = create_block(
        slot=slot,
        leader_id=leader_id,
        parent_block_hash=blockchain_state["head_block_hash"],
        transactions=transactions,
    )
    block["included_request_ids"] = [request_tx["request_id"] for request_tx in selected_requests]
    block["scheduled_leader_id"] = scheduled_leader_id or leader_id
    block["leader_schedule_match"] = leader_id == (scheduled_leader_id or leader_id)
    return block


def append_block(
    blockchain_state: dict[str, Any],
    block: dict[str, Any],
) -> dict[str, Any]:
    """
    Append a produced block to the persistent chain state and commit its state transitions.
    """
    if not verify_block_parent_link(blockchain_state, block):
        raise ValueError("block does not extend the current chain head")

    pending_requests_by_id = {
        request_tx["request_id"]: request_tx for request_tx in blockchain_state["pending_requests"]
    }
    for transaction_record in block["transactions"]:
        request_id = transaction_record["request_id"]
        if request_id not in pending_requests_by_id:
            raise ValueError(f"block references unknown pending request: {request_id}")
        apply_transaction_to_state(
            blockchain_state,
            pending_requests_by_id[request_id],
            deepcopy(transaction_record),
        )

    included_request_ids = [transaction_record["request_id"] for transaction_record in block["transactions"]]
    included_request_id_set = set(included_request_ids)
    blockchain_state["pending_requests"] = [
        request_tx
        for request_tx in blockchain_state["pending_requests"]
        if request_tx["request_id"] not in included_request_id_set
    ]
    blockchain_state["processed_request_ids"].extend(included_request_ids)
    blockchain_state["blocks"].append(deepcopy(block))
    blockchain_state["head_block_hash"] = block["block_hash"]
    blockchain_state["head_slot"] = block["slot"]
    blockchain_state["next_slot"] = block["slot"] + 1
    blockchain_state["current_epoch"] = (max(block["slot"], 1) - 1) // blockchain_state["epoch_schedule"][
        "slots_per_epoch"
    ]
    finalize_validator_epoch_transitions(blockchain_state)
    blockchain_state["stats"]["block_count"] += 1
    blockchain_state["stats"]["processed_request_count"] += len(block["transactions"])
    blockchain_state["stats"]["confirmed_transaction_count"] += block["confirmed_transaction_count"]
    blockchain_state["stats"]["rejected_transaction_count"] += block["rejected_transaction_count"]
    blockchain_state["stats"]["total_fees_lamports"] += block["total_fees_lamports"]
    leader = blockchain_state["validators"].get(block["leader_id"])
    if leader is not None:
        leader["produced_block_count"] += 1
        leader["last_produced_slot"] = block["slot"]
    refresh_runtime_views(blockchain_state)
    return block


def summarize_blockchain_state(blockchain_state: dict[str, Any]) -> dict[str, Any]:
    """Return a compact JSON-friendly summary of the live chain state."""
    next_scheduled_leader = None
    if blockchain_state["validators"]:
        try:
            next_scheduled_leader = select_leader_for_slot(
                blockchain_state,
                blockchain_state["next_slot"],
            )
        except ValueError:
            next_scheduled_leader = None
    return {
        "chain_id": blockchain_state["chain_id"],
        "genesis_hash": blockchain_state["genesis_hash"],
        "head_block_hash": blockchain_state["head_block_hash"],
        "head_slot": blockchain_state["head_slot"],
        "next_slot": blockchain_state["next_slot"],
        "current_epoch": blockchain_state["current_epoch"],
        "slots_per_epoch": blockchain_state["epoch_schedule"]["slots_per_epoch"],
        "pending_request_count": len(blockchain_state["pending_requests"]),
        "block_count": len(blockchain_state["blocks"]),
        "active_player_count": sum(
            player["status"] == REGISTRY_STATUS_ACTIVE
            for player in blockchain_state["players"].values()
        ),
        "registered_player_count": len(blockchain_state["players"]),
        "active_validator_count": sum(
            validator_is_schedulable_for_epoch(validator, blockchain_state["current_epoch"])
            for validator in blockchain_state["validators"].values()
        ),
        "registered_validator_count": len(blockchain_state["validators"]),
        "player_ids": list(blockchain_state["players"].keys()),
        "validator_ids": list(blockchain_state["validators"].keys()),
        "next_scheduled_leader": next_scheduled_leader,
        "stats": deepcopy(blockchain_state["stats"]),
    }


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


def sample_validators() -> dict[str, dict[str, Any]]:
    """Build a small validator set for block production and later stake-based scheduling."""
    return {
        "validator_alpha": build_validator_profile(
            validator_id="validator_alpha",
            identity_account=make_address("validator_alpha_identity"),
            vote_account=make_address("validator_alpha_vote"),
            activated_stake_lamports=800_000 * LAMPORTS_PER_SOL,
            self_stake_lamports=50_000 * LAMPORTS_PER_SOL,
            commission_bps=500,
            delegator_count=120,
            metadata={"region": "eu-west", "role": "current_demo_leader"},
        ),
        "validator_beta": build_validator_profile(
            validator_id="validator_beta",
            identity_account=make_address("validator_beta_identity"),
            vote_account=make_address("validator_beta_vote"),
            activated_stake_lamports=500_000 * LAMPORTS_PER_SOL,
            self_stake_lamports=35_000 * LAMPORTS_PER_SOL,
            commission_bps=700,
            delegator_count=85,
            metadata={"region": "us-east"},
        ),
        "validator_gamma": build_validator_profile(
            validator_id="validator_gamma",
            identity_account=make_address("validator_gamma_identity"),
            vote_account=make_address("validator_gamma_vote"),
            activated_stake_lamports=300_000 * LAMPORTS_PER_SOL,
            self_stake_lamports=20_000 * LAMPORTS_PER_SOL,
            commission_bps=600,
            delegator_count=55,
            metadata={"region": "ap-southeast"},
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
        # Validator identity accounts are the operator wallets/nodes for each validator.
        make_address("validator_alpha_identity"): build_account_state(
            lamports=40 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("validator_beta_identity"): build_account_state(
            lamports=35 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        make_address("validator_gamma_identity"): build_account_state(
            lamports=30 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
        # Vote accounts are where stake is delegated in Solana's PoS model and where validator
        # voting state would later live for rewards and leader-selection logic.
        make_address("validator_alpha_vote"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=VOTE_PROGRAM_ID,
            data=[71, 1, 0, 0],
        ),
        make_address("validator_beta_vote"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=VOTE_PROGRAM_ID,
            data=[72, 1, 0, 0],
        ),
        make_address("validator_gamma_vote"): build_account_state(
            lamports=2 * LAMPORTS_PER_SOL,
            owner=VOTE_PROGRAM_ID,
            data=[73, 1, 0, 0],
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
    accounts: dict[str, dict[str, Any]],
    pools: dict[str, dict[str, Any]],
    markets: dict[str, dict[str, Any]],
    players: dict[str, dict[str, Any]],
    validators: dict[str, dict[str, Any]],
    leader_id: str | None = None,
) -> dict[str, Any]:
    blockchain_state = build_blockchain_state(
        accounts=accounts,
        pools=pools,
        markets=markets,
        players={},
    )
    for player in players.values():
        register_player(blockchain_state, player)
    for validator in validators.values():
        register_validator(blockchain_state, validator)
    for request_tx in requests:
        submit_transaction_request(blockchain_state, request_tx)
    block = produce_block(blockchain_state, leader_id=leader_id)
    append_block(blockchain_state, block)
    return block


def main() -> None:
    pools = sample_pools()
    markets = sample_markets()
    players = sample_players()
    validators = sample_validators()
    player_intents = sample_player_intents(players, pools, markets)
    accounts = sample_accounts()
    requests = sample_transaction_requests(player_intents, players, pools, markets)
    blockchain_state = build_blockchain_state(
        accounts=accounts,
        pools=pools,
        markets=markets,
        players={},
    )
    for player in players.values():
        register_player(blockchain_state, player)
    for validator in validators.values():
        register_validator(blockchain_state, validator)
    for request_tx in requests:
        submit_transaction_request(blockchain_state, request_tx)
    block = produce_block(blockchain_state)
    append_block(blockchain_state, block)

    print("POOLS")
    print(to_json(pools))
    print()
    print("MARKETS")
    print(to_json(markets))
    print()
    print("PLAYERS")
    print(to_json(players))
    print()
    print("VALIDATORS")
    print(to_json(blockchain_state["validators"]))
    print()
    print("PLAYER INTENTS")
    print(to_json(player_intents))
    print()
    print("INITIAL ACCOUNTS")
    print(to_json(accounts))
    print()
    print("TRANSACTION REQUESTS")
    print(to_json(requests))
    print()
    print("BLOCKCHAIN STATE SUMMARY")
    print(to_json(summarize_blockchain_state(blockchain_state)))
    print()
    print("CHAIN ACCOUNTS")
    print(to_json(blockchain_state["accounts"]))
    print()
    print("FINALIZED BLOCK")
    print(to_json(blockchain_state["blocks"][-1]))


if __name__ == "__main__":
    main()
