"""Domain-level builders and intent compilation.

This module defines the higher-level market/pool/player/validator objects used by the
simulation layer and converts player intents into concrete transaction requests.
"""

from copy import deepcopy
from typing import Any

from .constants import (
    INTENT_TYPE_MARKET_TRADE,
    INTENT_TYPE_POOL_LIQUIDITY_ADD,
    INTENT_TYPE_POOL_SWAP,
    INTENT_TYPE_SYSTEM_TRANSFER,
    LEGACY_TRANSACTION_FORMAT,
    REGISTRY_STATUS_ACTIVE,
    VERSIONED_V0_TRANSACTION_FORMAT,
)
from .protocol import (
    build_address_lookup_table,
    build_market_swap_instruction,
    build_pool_liquidity_add_instruction,
    build_pool_swap_instruction,
    build_system_transfer_instruction,
    build_transaction_request,
)
from .utils import make_id


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
    policy_name: str | None = None,
    policy_config: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build a simulator-side player profile.

    A player profile lives above the on-chain layer. It describes who the actor is, which
    authority account they control, and which token accounts they typically use. Players do
    not directly become transactions; they generate intents, and those intents are later
    compiled into Solana-style transaction requests.

    `player_type` and `policy_name` are intentionally separate:
    - `player_type` says what broad economic role the actor plays
    - `policy_name` says which concrete decision rule that actor currently uses

    That separation matters because later you may want multiple market makers, routers, or LPs
    that all share the same player type but behave differently. The profile therefore stores a
    `policy_config` dictionary as well, so one policy implementation can be parameterized per
    player without changing the player type itself.
    """
    return {
        "player_id": player_id,
        "player_type": player_type,
        "authority_account": authority_account,
        "token_accounts": dict(token_accounts or {}),
        "default_message_format": default_message_format,
        "policy_name": policy_name,
        "policy_config": deepcopy(policy_config or {}),
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
            "player_policy_name": intent["metadata"].get("policy_name", player.get("policy_name")),
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
