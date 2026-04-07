"""Transaction and instruction primitives for the simulator."""

import struct
from copy import deepcopy
from typing import Any

from .constants import (
    AMM_SIM_PROGRAM_ID,
    BLOCKHASH_BYTES,
    DEFAULT_INSTRUCTION_COMPUTE_UNIT_LIMIT,
    DEFAULT_LAMPORTS_PER_SIGNATURE,
    LEGACY_TRANSACTION_FORMAT,
    MARKET_ORDER_TYPE_LIMIT,
    MARKET_ORDER_TYPE_MARKET,
    MARKET_SIDE_BUY,
    MARKET_SIDE_SELL,
    MARKET_SIM_PROGRAM_ID,
    MAX_ACCOUNT_DATA_LEN,
    MAX_BUILTIN_ALLOCATION_COMPUTE_UNIT_LIMIT,
    MAX_COMPUTE_UNIT_LIMIT,
    MAX_INSTRUCTION_DATA_LEN,
    NON_MIGRATED_BUILTIN_PROGRAM_IDS,
    PACKET_DATA_SIZE,
    PUBKEY_BYTES,
    RENT_EXEMPT_RENT_EPOCH,
    SIGNATURE_BYTES,
    SWAP_MODE_EXACT_INPUT,
    SWAP_MODE_EXACT_OUTPUT,
    SYSTEM_PROGRAM_ID,
    VERSIONED_V0_TRANSACTION_FORMAT,
)
from .utils import (
    make_id,
    message_hash,
    now_ms,
    shortvec_length,
    simulate_signature_for_signer,
    stable_hash,
    transaction_hash,
)


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

    return list(
        struct.pack("<BBQQQ", side_flag, order_type_flag, base_amount, quote_amount_limit, limit_price)
    )


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


def estimate_request_serialized_size_bytes(request_tx: dict[str, Any]) -> int:
    """Estimate the serialized byte size of a request before it is materialized into a block."""
    if request_tx["message_format"] == LEGACY_TRANSACTION_FORMAT:
        transaction, _, _ = compile_legacy_transaction(request_tx)
        return estimate_legacy_transaction_size(transaction)

    transaction, _, _ = compile_v0_transaction(request_tx)
    return estimate_v0_transaction_size(transaction)


def build_request_scheduling_profile(request_tx: dict[str, Any]) -> dict[str, Any]:
    """
    Build request metadata used for mempool ordering and slot-capacity packing.

    The simulator keeps this intentionally simpler than Solana's full scheduler cost model:
    - estimated compute units act as the slot-capacity cost
    - compute-unit price and total estimated fee drive priority ordering
    """
    requested_compute_unit_limit = effective_compute_unit_limit(request_tx)
    estimated_compute_units = estimate_transaction_compute_units(request_tx["instructions"])
    compute_unit_price_micro_lamports = request_tx["compute_budget"][
        "compute_unit_price_micro_lamports"
    ]
    ordered_accounts = collect_transaction_accounts(
        fee_payer=request_tx["fee_payer"],
        instructions=request_tx["instructions"],
    )
    signature_count = sum(account["is_signer"] for account in ordered_accounts)
    serialized_size_bytes = estimate_request_serialized_size_bytes(request_tx)
    estimated_fee_lamports = estimate_fee_lamports(
        signature_count=signature_count,
        requested_compute_unit_limit=requested_compute_unit_limit,
        compute_unit_price_micro_lamports=compute_unit_price_micro_lamports,
    )
    priority_fee_lamports = estimated_fee_lamports - (
        signature_count * DEFAULT_LAMPORTS_PER_SIGNATURE
    )
    return {
        "signature_count": signature_count,
        "requested_compute_unit_limit": requested_compute_unit_limit,
        "estimated_compute_units": estimated_compute_units,
        "estimated_serialized_size_bytes": serialized_size_bytes,
        "compute_unit_price_micro_lamports": compute_unit_price_micro_lamports,
        "priority_fee_lamports": priority_fee_lamports,
        "estimated_fee_lamports": estimated_fee_lamports,
        "account_lock_count": len(ordered_accounts),
        "writable_account_lock_count": sum(account["is_writable"] for account in ordered_accounts),
        "account_locks": [account["pubkey"] for account in ordered_accounts],
        "writable_account_locks": [
            account["pubkey"] for account in ordered_accounts if account["is_writable"]
        ],
    }


def request_priority_sort_key(request_tx: dict[str, Any]) -> tuple[int, int, int, int, int]:
    """
    Return a deterministic sort key for pending-request inclusion priority.

    Higher fee pressure comes first. For equal fees, smaller compute estimates are favored so
    the slot can fit more work, and earlier submissions keep their place ahead of later ties.
    """
    scheduling = request_tx["scheduling"]
    return (
        -scheduling["compute_unit_price_micro_lamports"],
        -scheduling["priority_fee_lamports"],
        -scheduling["estimated_fee_lamports"],
        scheduling["estimated_compute_units"],
        request_tx["submission_sequence"],
    )


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

    return sorted(
        account_map.values(),
        key=lambda account: (account_permission_group(account), account["first_seen"]),
    )


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
    signer_pubkeys = [account["pubkey"] for account in ordered_accounts if account["is_signer"]]
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
