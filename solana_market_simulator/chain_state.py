"""Persistent blockchain state and runtime execution helpers.

This module owns the live chain state object plus the functions that mutate it:
- chain construction and timing config
- player and validator registration/status
- leader scheduling and skipped-slot logic
- mempool selection, transaction application, block production, and summaries
"""

import math
import struct
from copy import deepcopy
from typing import Any

from .constants import (
    AMM_SIM_PROGRAM_ID,
    CONSTANT_PRODUCT_SWAP_FEE_BPS,
    DEFAULT_BLOCK_ACCOUNT_LOCK_LIMIT,
    DEFAULT_BLOCK_COMPUTE_UNIT_LIMIT,
    DEFAULT_BLOCK_PACKET_BYTES_LIMIT,
    DEFAULT_BLOCK_WRITABLE_ACCOUNT_LOCK_LIMIT,
    DEFAULT_SLOTS_PER_EPOCH,
    MARKET_ORDER_TYPE_MARKET,
    MARKET_PRICE_SCALE,
    MARKET_SIDE_BUY,
    MARKET_SIDE_SELL,
    MARKET_SIM_PROGRAM_ID,
    MAX_PROCESSING_AGE,
    POOL_TYPE_CONSTANT_PRODUCT,
    POOL_TYPE_STABLE_SWAP,
    REGISTRY_STATUS_ACTIVE,
    REGISTRY_STATUS_DEREGISTERED,
    REGISTRY_STATUS_EXITING,
    REGISTRY_STATUS_INACTIVE,
    REFERENCE_MAINNET_SLOTS_PER_EPOCH,
    STABLE_SWAP_FEE_BPS,
    STAKE_WARMUP_COOLDOWN_RATE,
    SWAP_MODE_EXACT_INPUT,
    SYSTEM_PROGRAM_ID,
    TARGET_SLOT_DURATION_MS,
    TOKEN_PROGRAM_ID,
    VOTE_PROGRAM_ID,
    WEIGHTED_SWAP_FEE_BPS,
)
from .protocol import (
    build_account_state,
    build_request_scheduling_profile,
    create_block,
    decode_market_swap_data,
    decode_pool_liquidity_add_data,
    decode_pool_swap_data,
    decode_system_transfer_data,
    materialize_transaction,
    request_priority_sort_key,
)
from .utils import make_id, stable_hash


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
        "simulated_time_ms": 0,
        "current_epoch": 0,
        "epoch_schedule": {
            "slots_per_epoch": DEFAULT_SLOTS_PER_EPOCH,
            "target_slot_duration_ms": TARGET_SLOT_DURATION_MS,
            "reference_mainnet_slots_per_epoch": REFERENCE_MAINNET_SLOTS_PER_EPOCH,
        },
        "block_limits": {
            "max_compute_units": DEFAULT_BLOCK_COMPUTE_UNIT_LIMIT,
            "max_packet_bytes": DEFAULT_BLOCK_PACKET_BYTES_LIMIT,
            "max_account_locks": DEFAULT_BLOCK_ACCOUNT_LOCK_LIMIT,
            "max_writable_account_locks": DEFAULT_BLOCK_WRITABLE_ACCOUNT_LOCK_LIMIT,
        },
        "simulation_config": {
            "realistic_solana_timing": False,
            "skip_slot_probability_bps": 0,
        },
        "accounts": deepcopy(accounts),
        "pools": deepcopy(pools),
        "markets": deepcopy(markets),
        "players": deepcopy(players),
        "validators": deepcopy(validators or {}),
        "leader_schedules": {},
        "pending_requests": [],
        "processed_request_ids": [],
        "expired_request_ids": [],
        "submitted_request_archive": {},
        "request_archive": {},
        "next_request_submission_sequence": 0,
        "blocks": [],
        "skipped_slots": [],
        "verification_base_state": {
            "accounts": deepcopy(accounts),
            "pools": deepcopy(pools),
            "markets": deepcopy(markets),
            "players": deepcopy(players),
            "validators": deepcopy(validators or {}),
        },
        "stats": {
            "block_count": 0,
            "skipped_slot_count": 0,
            "processed_request_count": 0,
            "confirmed_transaction_count": 0,
            "rejected_transaction_count": 0,
            "expired_request_count": 0,
            "total_fees_lamports": 0,
        },
    }
    refresh_runtime_views(blockchain_state)
    return blockchain_state


def refresh_verification_base_state(blockchain_state: dict[str, Any]) -> None:
    """
    Refresh the replay base state used by chain verification before block production begins.

    Player and validator registration currently happen as direct simulation-state mutations rather
    than as on-chain transactions. To let `verify_chain()` replay the produced blocks later, we
    freeze a verification base state that mirrors the live runtime state just before the first
    block is appended.
    """
    if (
        blockchain_state["blocks"]
        or blockchain_state["pending_requests"]
        or blockchain_state["processed_request_ids"]
    ):
        return

    blockchain_state["verification_base_state"] = {
        "accounts": deepcopy(blockchain_state["accounts"]),
        "pools": deepcopy(blockchain_state["pools"]),
        "markets": deepcopy(blockchain_state["markets"]),
        "players": deepcopy(blockchain_state["players"]),
        "validators": deepcopy(blockchain_state["validators"]),
    }


def configure_simulation_timing(
    blockchain_state: dict[str, Any],
    realistic_solana_timing: bool = False,
    slots_per_epoch: int | None = None,
    target_slot_duration_ms: int | None = None,
    skip_slot_probability_bps: int | None = None,
) -> dict[str, Any]:
    """
    Configure logical slot and epoch timing without making the simulator sleep in real time.

    `realistic_solana_timing=True` switches the schedule to Solana-like reference timing:
    - target slot duration: 400ms
    - slots per epoch: 8192

    This remains optional because a full 8192-slot epoch is often too large for day-to-day local
    experiments. The default lightweight mode therefore stays smaller while preserving the same
    logical timing model.
    """
    if blockchain_state["blocks"] or blockchain_state["pending_requests"]:
        raise ValueError("simulation timing can only be configured before slots start processing")

    if realistic_solana_timing:
        blockchain_state["simulation_config"]["realistic_solana_timing"] = True
        blockchain_state["epoch_schedule"]["slots_per_epoch"] = REFERENCE_MAINNET_SLOTS_PER_EPOCH
        blockchain_state["epoch_schedule"]["target_slot_duration_ms"] = TARGET_SLOT_DURATION_MS
    else:
        blockchain_state["simulation_config"]["realistic_solana_timing"] = False

    if slots_per_epoch is not None:
        if slots_per_epoch <= 0:
            raise ValueError("slots_per_epoch must be positive")
        blockchain_state["epoch_schedule"]["slots_per_epoch"] = slots_per_epoch

    if target_slot_duration_ms is not None:
        if target_slot_duration_ms <= 0:
            raise ValueError("target_slot_duration_ms must be positive")
        blockchain_state["epoch_schedule"]["target_slot_duration_ms"] = target_slot_duration_ms

    if skip_slot_probability_bps is not None:
        if skip_slot_probability_bps < 0 or skip_slot_probability_bps > 10_000:
            raise ValueError("skip_slot_probability_bps must be between 0 and 10,000")
        blockchain_state["simulation_config"]["skip_slot_probability_bps"] = skip_slot_probability_bps

    blockchain_state["leader_schedules"].clear()
    refresh_verification_base_state(blockchain_state)
    return {
        "realistic_solana_timing": blockchain_state["simulation_config"]["realistic_solana_timing"],
        "slots_per_epoch": blockchain_state["epoch_schedule"]["slots_per_epoch"],
        "target_slot_duration_ms": blockchain_state["epoch_schedule"]["target_slot_duration_ms"],
        "skip_slot_probability_bps": blockchain_state["simulation_config"]["skip_slot_probability_bps"],
    }


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
    refresh_verification_base_state(blockchain_state)
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
    refresh_verification_base_state(blockchain_state)
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
    refresh_verification_base_state(blockchain_state)
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
    refresh_verification_base_state(blockchain_state)
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


def should_skip_slot(
    blockchain_state: dict[str, Any],
    slot: int,
    leader_id: str,
) -> bool:
    """
    Return True when the simulator should treat a slot as skipped instead of producing a block.

    The decision is deterministic so replay verification can reproduce it exactly. The skip rate
    is configured in basis points rather than by wall-clock randomness.
    """
    skip_slot_probability_bps = blockchain_state["simulation_config"]["skip_slot_probability_bps"]
    if skip_slot_probability_bps <= 0:
        return False

    sample = int(
        stable_hash(
            {
                "chain_id": blockchain_state["chain_id"],
                "slot": slot,
                "leader_id": leader_id,
                "skip_slot_probability_bps": skip_slot_probability_bps,
            }
        ),
        16,
    ) % 10_000
    return sample < skip_slot_probability_bps


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
    expired_request_ids = set(blockchain_state["expired_request_ids"])
    if request_id in pending_request_ids or request_id in processed_request_ids or request_id in expired_request_ids:
        raise ValueError(f"duplicate request_id: {request_id}")

    if blockchain_state["players"]:
        player = blockchain_state["players"].get(request_tx["agent_id"])
        if player is None:
            raise ValueError(f"unregistered player submitted request: {request_tx['agent_id']}")
        if player["status"] != REGISTRY_STATUS_ACTIVE:
            raise ValueError(f"non-active player submitted request: {request_tx['agent_id']}")

    request_copy = deepcopy(request_tx)
    request_copy["submitted_for_slot"] = blockchain_state["next_slot"]
    request_copy["expires_after_slot"] = request_copy["submitted_for_slot"] + MAX_PROCESSING_AGE
    request_copy["submission_sequence"] = blockchain_state["next_request_submission_sequence"]
    blockchain_state["next_request_submission_sequence"] += 1
    request_copy["scheduling"] = build_request_scheduling_profile(request_copy)
    blockchain_state["submitted_request_archive"][request_id] = deepcopy(request_copy)
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


def request_is_expired_for_slot(request_tx: dict[str, Any], slot: int) -> bool:
    """Return True when a pending request has aged past the recent-blockhash processing window."""
    return slot > int(request_tx["expires_after_slot"])


def expire_pending_requests_for_slot(
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    Drop pending requests that can no longer be processed because their blockhash age expired.

    This models time pressure in logical slot space rather than by sleeping in wall-clock time.
    """
    remaining_requests = []
    expired_requests = []
    for request_tx in blockchain_state["pending_requests"]:
        if request_is_expired_for_slot(request_tx, slot):
            expired_requests.append(request_tx)
        else:
            remaining_requests.append(request_tx)

    if expired_requests:
        blockchain_state["pending_requests"] = remaining_requests
        blockchain_state["expired_request_ids"].extend(
            request_tx["request_id"] for request_tx in expired_requests
        )
        blockchain_state["stats"]["expired_request_count"] += len(expired_requests)

    return expired_requests


def select_pending_requests_for_block(
    blockchain_state: dict[str, Any],
    max_transactions: int | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """
    Select the pending requests that fit into the slot's block packing budgets.

    Requests are considered in fee-priority order. Requests that do not fit stay pending for a
    later slot instead of being dropped immediately.
    """
    block_limits = blockchain_state["block_limits"]
    block_compute_unit_limit = block_limits["max_compute_units"]
    block_packet_bytes_limit = block_limits["max_packet_bytes"]
    block_account_lock_limit = block_limits["max_account_locks"]
    block_writable_account_lock_limit = block_limits["max_writable_account_locks"]
    selected_requests: list[dict[str, Any]] = []
    consumed_compute_units = 0
    consumed_packet_bytes = 0
    locked_accounts: set[str] = set()
    writable_locked_accounts: set[str] = set()

    for request_tx in sorted(blockchain_state["pending_requests"], key=request_priority_sort_key):
        scheduling = request_tx["scheduling"]
        estimated_compute_units = scheduling["estimated_compute_units"]
        estimated_packet_bytes = scheduling["estimated_serialized_size_bytes"]
        candidate_locked_accounts = locked_accounts | set(scheduling["account_locks"])
        candidate_writable_locked_accounts = writable_locked_accounts | set(
            scheduling["writable_account_locks"]
        )

        if estimated_compute_units > block_compute_unit_limit:
            continue
        if consumed_compute_units + estimated_compute_units > block_compute_unit_limit:
            continue
        if estimated_packet_bytes > block_packet_bytes_limit:
            continue
        if consumed_packet_bytes + estimated_packet_bytes > block_packet_bytes_limit:
            continue
        if len(candidate_locked_accounts) > block_account_lock_limit:
            continue
        if len(candidate_writable_locked_accounts) > block_writable_account_lock_limit:
            continue

        selected_requests.append(request_tx)
        consumed_compute_units += estimated_compute_units
        consumed_packet_bytes += estimated_packet_bytes
        locked_accounts = candidate_locked_accounts
        writable_locked_accounts = candidate_writable_locked_accounts

        if max_transactions is not None and len(selected_requests) >= max_transactions:
            break

    return selected_requests, {
        "compute_units_consumed": consumed_compute_units,
        "packet_bytes_consumed": consumed_packet_bytes,
        "account_lock_count": len(locked_accounts),
        "writable_account_lock_count": len(writable_locked_accounts),
    }


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
    runtime_state = pool.setdefault("runtime_state", {})
    runtime_state.setdefault("swap_count", 0)
    runtime_state["swap_count"] += 1


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
    runtime_state = pool.setdefault("runtime_state", {})
    runtime_state.setdefault("liquidity_add_count", 0)
    runtime_state["liquidity_add_count"] += 1


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
    runtime_state = market.setdefault("runtime_state", {})
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
    allow_empty: bool = False,
) -> dict[str, Any]:
    """
    Materialize a block candidate from the current pending request queue.

    This previews validator processing against a copy of the current chain state so transaction
    statuses reflect sequential execution before the block is actually appended.

    `allow_empty=True` is useful for the slot runner because Solana time still advances even
    when a slot has no user transactions to include.
    """
    slot = blockchain_state["next_slot"]
    expired_requests = expire_pending_requests_for_slot(blockchain_state, slot)
    if not blockchain_state["pending_requests"] and not allow_empty:
        raise ValueError("no pending requests to include in a block")

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

    if not blockchain_state["pending_requests"]:
        selected_requests = []
        packing_stats = {
            "compute_units_consumed": 0,
            "packet_bytes_consumed": 0,
            "account_lock_count": 0,
            "writable_account_lock_count": 0,
        }
    else:
        selected_requests, packing_stats = select_pending_requests_for_block(
            blockchain_state,
            max_transactions=max_transactions,
        )
    if not selected_requests and not allow_empty:
        raise ValueError("no pending requests fit into the current block compute budget")

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
    block["expired_request_count"] = len(expired_requests)
    block["max_transactions_limit"] = max_transactions
    block["compute_unit_limit"] = blockchain_state["block_limits"]["max_compute_units"]
    block["compute_units_consumed"] = packing_stats["compute_units_consumed"]
    block["compute_units_remaining"] = max(
        block["compute_unit_limit"] - block["compute_units_consumed"],
        0,
    )
    block["packet_bytes_limit"] = blockchain_state["block_limits"]["max_packet_bytes"]
    block["packet_bytes_consumed"] = packing_stats["packet_bytes_consumed"]
    block["packet_bytes_remaining"] = max(
        block["packet_bytes_limit"] - block["packet_bytes_consumed"],
        0,
    )
    block["account_lock_limit"] = blockchain_state["block_limits"]["max_account_locks"]
    block["account_lock_count"] = packing_stats["account_lock_count"]
    block["writable_account_lock_limit"] = blockchain_state["block_limits"][
        "max_writable_account_locks"
    ]
    block["writable_account_lock_count"] = packing_stats["writable_account_lock_count"]
    return block


def skip_slot(
    blockchain_state: dict[str, Any],
    leader_id: str | None = None,
    reason: str = "leader_missed_slot",
    expired_request_count: int | None = None,
) -> dict[str, Any]:
    """
    Advance one slot without appending a block.

    This is distinct from an empty block:
    - empty block: a block exists for the slot, but it contains zero transactions
    - skipped slot: no block exists for the slot at all

    Pending transactions remain queued, aside from any that expire because the slot advance
    pushed them past the recent-blockhash processing window.
    """
    slot = blockchain_state["next_slot"]
    if expired_request_count is None:
        expired_requests = expire_pending_requests_for_slot(blockchain_state, slot)
        expired_request_count = len(expired_requests)

    scheduled_leader_id = None
    if blockchain_state["validators"]:
        scheduled_leader_id = select_leader_for_slot(blockchain_state, slot)
        if leader_id is None:
            leader_id = scheduled_leader_id

    slot_record = {
        "slot": slot,
        "scheduled_leader_id": scheduled_leader_id,
        "leader_id": leader_id,
        "reason": reason,
        "expired_request_count": expired_request_count,
        "pending_request_count_after_skip": len(blockchain_state["pending_requests"]),
        "skipped_at_simulated_time_ms": slot * blockchain_state["epoch_schedule"]["target_slot_duration_ms"],
    }
    blockchain_state["skipped_slots"].append(slot_record)
    blockchain_state["head_slot"] = slot
    blockchain_state["next_slot"] = slot + 1
    blockchain_state["simulated_time_ms"] = (
        blockchain_state["head_slot"] * blockchain_state["epoch_schedule"]["target_slot_duration_ms"]
    )
    blockchain_state["current_epoch"] = (max(slot, 1) - 1) // blockchain_state["epoch_schedule"][
        "slots_per_epoch"
    ]
    finalize_validator_epoch_transitions(blockchain_state)
    blockchain_state["stats"]["skipped_slot_count"] += 1
    refresh_runtime_views(blockchain_state)
    return slot_record


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
        blockchain_state["request_archive"][request_id] = deepcopy(pending_requests_by_id[request_id])
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
    blockchain_state["simulated_time_ms"] = (
        blockchain_state["head_slot"] * blockchain_state["epoch_schedule"]["target_slot_duration_ms"]
    )
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
        "last_block_slot": blockchain_state["blocks"][-1]["slot"] if blockchain_state["blocks"] else 0,
        "next_slot": blockchain_state["next_slot"],
        "simulated_time_ms": blockchain_state["simulated_time_ms"],
        "current_epoch": blockchain_state["current_epoch"],
        "slots_per_epoch": blockchain_state["epoch_schedule"]["slots_per_epoch"],
        "target_slot_duration_ms": blockchain_state["epoch_schedule"]["target_slot_duration_ms"],
        "realistic_solana_timing": blockchain_state["simulation_config"]["realistic_solana_timing"],
        "skip_slot_probability_bps": blockchain_state["simulation_config"]["skip_slot_probability_bps"],
        "block_compute_unit_limit": blockchain_state["block_limits"]["max_compute_units"],
        "block_packet_bytes_limit": blockchain_state["block_limits"]["max_packet_bytes"],
        "block_account_lock_limit": blockchain_state["block_limits"]["max_account_locks"],
        "block_writable_account_lock_limit": blockchain_state["block_limits"]["max_writable_account_locks"],
        "pending_request_count": len(blockchain_state["pending_requests"]),
        "block_count": len(blockchain_state["blocks"]),
        "skipped_slot_count": len(blockchain_state["skipped_slots"]),
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


def summarize_block(
    block: dict[str, Any],
    slots_per_epoch: int,
) -> dict[str, Any]:
    """Return a compact summary for one produced block."""
    return {
        "slot": block["slot"],
        "epoch": (block["slot"] - 1) // slots_per_epoch,
        "leader_id": block["leader_id"],
        "scheduled_leader_id": block.get("scheduled_leader_id"),
        "leader_schedule_match": block.get("leader_schedule_match"),
        "transaction_count": block["transaction_count"],
        "confirmed_transaction_count": block["confirmed_transaction_count"],
        "rejected_transaction_count": block["rejected_transaction_count"],
        "expired_request_count": block.get("expired_request_count", 0),
        "compute_unit_limit": block.get("compute_unit_limit"),
        "compute_units_consumed": block.get("compute_units_consumed"),
        "compute_units_remaining": block.get("compute_units_remaining"),
        "packet_bytes_limit": block.get("packet_bytes_limit"),
        "packet_bytes_consumed": block.get("packet_bytes_consumed"),
        "packet_bytes_remaining": block.get("packet_bytes_remaining"),
        "account_lock_limit": block.get("account_lock_limit"),
        "account_lock_count": block.get("account_lock_count"),
        "writable_account_lock_limit": block.get("writable_account_lock_limit"),
        "writable_account_lock_count": block.get("writable_account_lock_count"),
        "total_fees_lamports": block["total_fees_lamports"],
        "included_request_ids": list(block.get("included_request_ids", [])),
    }


def summarize_blocks(
    blocks: list[dict[str, Any]],
    slots_per_epoch: int,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return compact summaries for produced blocks, optionally keeping only the most recent ones."""
    selected_blocks = blocks if limit is None else blocks[-limit:]
    return [summarize_block(block, slots_per_epoch=slots_per_epoch) for block in selected_blocks]


def summarize_skipped_slots(
    skipped_slots: list[dict[str, Any]],
    slots_per_epoch: int,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    """Return compact summaries for skipped slots, optionally keeping only the most recent ones."""
    selected_slots = skipped_slots if limit is None else skipped_slots[-limit:]
    return [
        {
            "slot": slot_record["slot"],
            "epoch": (slot_record["slot"] - 1) // slots_per_epoch,
            "leader_id": slot_record.get("leader_id"),
            "scheduled_leader_id": slot_record.get("scheduled_leader_id"),
            "reason": slot_record["reason"],
            "expired_request_count": slot_record["expired_request_count"],
            "pending_request_count_after_skip": slot_record["pending_request_count_after_skip"],
        }
        for slot_record in selected_slots
    ]
