"""Sample fixtures and demo-oriented helper flows.

This file provides the example pools, markets, accounts, players, validators, and a few
helper functions used by the demo runner to bootstrap a readable simulation scenario.
"""

from .constants import (
    ADDRESS_LOOKUP_TABLE_PROGRAM_ID,
    AMM_SIM_PROGRAM_ID,
    LAMPORTS_PER_SOL,
    MARKET_SIM_PROGRAM_ID,
    PLAYER_POLICY_ADAPTIVE_TWO_TOKEN_LP,
    PLAYER_POLICY_CROSS_VENUE_ARBITRAGE,
    PLAYER_POLICY_INVENTORY_MARKET_MAKER,
    PLAYER_POLICY_RETAIL_FLOW,
    PLAYER_POLICY_STABLE_BALANCE_ROUTER,
    PLAYER_POLICY_TARGET_WEIGHT_REBALANCER,
    PLAYER_TYPE_ARBITRAGEUR,
    PLAYER_TYPE_LIQUIDITY_PROVIDER,
    PLAYER_TYPE_MARKET_MAKER,
    PLAYER_TYPE_REBALANCER,
    PLAYER_TYPE_RETAIL_USER,
    PLAYER_TYPE_ROUTER,
    POOL_TYPE_CONSTANT_PRODUCT,
    POOL_TYPE_STABLE_SWAP,
    POOL_TYPE_WEIGHTED,
    SYSTEM_PROGRAM_ID,
    TOKEN_PROGRAM_ID,
    VERSIONED_V0_TRANSACTION_FORMAT,
    VOTE_PROGRAM_ID,
)
from .chain_state import (
    append_block,
    build_blockchain_state,
    produce_block,
    register_player,
    register_validator,
    submit_transaction_request,
)
from .domain import (
    build_market_definition,
    build_player_profile,
    build_pool_definition,
    build_validator_profile,
    compile_player_intents_to_requests,
)
from .policies import (
    generate_player_intents,
)
from .protocol import build_account_state
from .utils import make_address


def sample_pools() -> dict[str, dict[str, object]]:
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


def sample_markets() -> dict[str, dict[str, object]]:
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


def sample_players() -> dict[str, dict[str, object]]:
    """
    Build sample player profiles for the simulator.

    These are strategy-level actors, not transactions. They hold the accounts they control and
    later emit intents that get compiled into transaction requests.

    Each sample player is also assigned one concrete policy. That keeps the architecture general:
    the player type identifies the actor class, while the policy says how that individual player
    currently behaves.
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
            policy_name=PLAYER_POLICY_INVENTORY_MARKET_MAKER,
            policy_config={
                "evaluation_rule": {"every_slots": 2, "slot_offset": 0},
                "market_id": "sol_usdc_spot",
                "base_symbol": "SOL",
                "quote_symbol": "USDC",
                "target_base_weight_bps": 5_000,
                "inventory_band_bps": 900,
                "max_trade_quote_amount": 350_000_000,
                "quote_spread_bps": 40,
                "trade_priority_fee_micro_lamports": 9_000,
                "funding_rule": {"epoch_start_only": True},
                "liquidity_wallet": make_address("liquidity_pool"),
                "liquidity_wallet_target_lamports": 102 * LAMPORTS_PER_SOL,
                "liquidity_wallet_top_up_cap_lamports": 2 * LAMPORTS_PER_SOL,
                "authority_reserve_lamports": 18 * LAMPORTS_PER_SOL,
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
            policy_name=PLAYER_POLICY_ADAPTIVE_TWO_TOKEN_LP,
            policy_config={
                "evaluation_rule": {"every_slots": 8, "slot_offset": 0},
                "pool_id": "volatile_sol_usdc",
                "reference_market_id": "sol_usdc_spot",
                "lp_receipt_account": make_address("cp_lp_receipt_account"),
                "deposit_balance_share_bps": 700,
                "max_pool_share_bps": 3_500,
                "max_price_deviation_bps": 900,
                "lp_slippage_bps": 300,
                "priority_fee_micro_lamports": 8_000,
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
            policy_name=PLAYER_POLICY_RETAIL_FLOW,
            policy_config={
                "evaluation_rule": {"every_slots": 1, "slot_offset": 0},
                "payment_rule": {"every_slots": 4, "slot_offset": 0},
                "payment_lamports": 250_000_000,
                "merchant_account": make_address("merchant"),
                "authority_buffer_lamports": 2 * LAMPORTS_PER_SOL,
                "trade_rule": {"every_slots": 3, "slot_offset": 1},
                "market_id": "sol_usdc_spot",
                "comparison_pool_id": "volatile_sol_usdc",
                "base_symbol": "SOL",
                "quote_symbol": "USDC",
                "min_quote_buffer": 5_000_000_000,
                "max_buy_quote_amount": 120_000_000,
                "max_market_premium_vs_pool_bps": 300,
                "lookup_table_account": make_address("market_alt"),
                "trade_priority_fee_micro_lamports": 4_000,
            },
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
            policy_name=PLAYER_POLICY_CROSS_VENUE_ARBITRAGE,
            policy_config={
                "evaluation_rule": {"every_slots": 2, "slot_offset": 1},
                "pool_id": "volatile_sol_usdc",
                "market_id": "sol_usdc_spot",
                "base_symbol": "SOL",
                "quote_symbol": "USDC",
                "min_edge_bps": 100,
                "edge_full_size_bps": 300,
                "max_input_share_bps": 1_500,
                "min_input_amount": 50_000_000,
                "slippage_bps": 150,
                "base_priority_fee_micro_lamports": 8_000,
                "priority_fee_per_edge_bps": 25,
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
            policy_name=PLAYER_POLICY_STABLE_BALANCE_ROUTER,
            policy_config={
                "evaluation_rule": {"every_slots": 4, "slot_offset": 2},
                "pool_id": "stable_usdc_usdt",
                "target_usdc_weight_bps": 4_500,
                "balance_band_bps": 200,
                "max_output_amount": 120_000_000,
                "max_input_share_bps": 2_500,
                "slippage_bps": 80,
                "lookup_table_account": make_address("stable_pool_alt"),
                "priority_fee_micro_lamports": 5_000,
            },
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
            policy_name=PLAYER_POLICY_TARGET_WEIGHT_REBALANCER,
            policy_config={
                "evaluation_rule": {"every_slots": 6, "slot_offset": 4},
                "pool_id": "weighted_sol_jup_usdc",
                "target_weights_bps": {"SOL": 5_000, "JUP": 2_000, "USDC": 3_000},
                "weight_band_bps": 500,
                "max_trade_value_quote_amount": 180_000_000,
                "max_input_share_bps": 2_500,
                "slippage_bps": 200,
                "lookup_table_account": make_address("weighted_pool_alt"),
                "priority_fee_micro_lamports": 7_500,
            },
            metadata={"style": "portfolio_rebalance"},
        ),
    }


def sample_validators() -> dict[str, dict[str, object]]:
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


def sample_accounts() -> dict[str, dict[str, object]]:
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
        make_address("liquidity_provider"): build_account_state(
            lamports=30 * LAMPORTS_PER_SOL,
            owner=SYSTEM_PROGRAM_ID,
        ),
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
        AMM_SIM_PROGRAM_ID: build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner="BPFLoaderUpgradeable11111111111111111111111",
            executable=True,
        ),
        MARKET_SIM_PROGRAM_ID: build_account_state(
            lamports=5 * LAMPORTS_PER_SOL,
            owner="BPFLoaderUpgradeable11111111111111111111111",
            executable=True,
        ),
    }
    return accounts


def sample_player_intents(blockchain_state: dict[str, dict[str, object]]) -> list[dict[str, object]]:
    """
    Build sample high-level intents emitted by different player types.

    This keeps the main demo flow explicit:
    players -> player intents -> transaction requests -> executed transactions -> blocks
    """
    return generate_player_intents(blockchain_state, slot=blockchain_state["next_slot"])


def sample_transaction_requests(
    player_intents: list[dict[str, object]],
    players: dict[str, dict[str, object]],
    pools: dict[str, dict[str, object]],
    markets: dict[str, dict[str, object]],
) -> list[dict[str, object]]:
    return compile_player_intents_to_requests(player_intents, players, pools, markets)


def sample_block_from_requests(
    requests: list[dict[str, object]],
    accounts: dict[str, dict[str, object]],
    pools: dict[str, dict[str, object]],
    markets: dict[str, dict[str, object]],
    players: dict[str, dict[str, object]],
    validators: dict[str, dict[str, object]],
    leader_id: str | None = None,
) -> dict[str, object]:
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
