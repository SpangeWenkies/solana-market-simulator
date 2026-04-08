"""State-driven player policies and request generation."""

from copy import deepcopy
from typing import Any

from .chain_state import (
    fee_bps_for_pool,
    get_required_account,
    pool_output_for_exact_input,
    refresh_runtime_views,
    required_input_for_exact_output,
)
from .constants import (
    INTENT_TYPE_MARKET_TRADE,
    INTENT_TYPE_POOL_LIQUIDITY_ADD,
    INTENT_TYPE_POOL_SWAP,
    INTENT_TYPE_SYSTEM_TRANSFER,
    LEGACY_TRANSACTION_FORMAT,
    MARKET_ORDER_TYPE_LIMIT,
    MARKET_ORDER_TYPE_MARKET,
    MARKET_PRICE_SCALE,
    MARKET_SIDE_BUY,
    MARKET_SIDE_SELL,
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
    REGISTRY_STATUS_ACTIVE,
    SWAP_MODE_EXACT_INPUT,
    SWAP_MODE_EXACT_OUTPUT,
    VERSIONED_V0_TRANSACTION_FORMAT,
)
from .domain import build_player_intent, compile_player_intents_to_requests
from .utils import make_address


def slot_matches_rule(
    slot: int,
    slots_per_epoch: int,
    rule: dict[str, Any] | None,
) -> bool:
    """
    Return True when a slot satisfies a simple deterministic cadence rule.

    Policies use this helper in two places:
    - a top-level evaluation rule for deciding whether the policy should wake up this slot
    - sub-rules inside the policy for optional actions such as payments, LP deposits, or
      inventory funding

    Keeping cadence as data rather than hard-coded `if slot % n == ...` logic makes it easy to
    attach different schedules to later policies or to different players using the same policy.
    """
    if slot <= 0:
        raise ValueError("slot must be positive")
    if rule is None:
        return True

    slot_index = slot - 1
    if rule.get("epoch_start_only"):
        return slot_index % slots_per_epoch == 0

    every_slots = int(rule.get("every_slots", 1))
    slot_offset = int(rule.get("slot_offset", 0))
    if every_slots <= 0:
        raise ValueError("policy rule every_slots must be positive")
    if slot_offset < 0 or slot_offset >= every_slots:
        raise ValueError("policy rule slot_offset must be within the cadence interval")
    return slot_index % every_slots == slot_offset


def resolve_player_policy_name(player: dict[str, Any]) -> str | None:
    """Resolve the concrete policy assigned to a player, falling back from player type."""
    if player.get("policy_name") is not None:
        return str(player["policy_name"])

    return DEFAULT_PLAYER_POLICY_BY_TYPE.get(player["player_type"])


def player_policy_is_due(
    player: dict[str, Any],
    slot: int,
    slots_per_epoch: int,
) -> bool:
    """
    Return True when a player's configured policy should be evaluated in a slot.

    This is intentionally policy-level rather than intent-level. The earlier design scheduled
    individual hard-coded intents. The new design schedules policy evaluation and lets the
    policy decide which intents, if any, make sense from current state.
    """
    policy_config = player.get("policy_config") or {}
    return slot_matches_rule(slot, slots_per_epoch, policy_config.get("evaluation_rule"))


def player_authority_balance(
    accounts: dict[str, dict[str, Any]],
    player: dict[str, Any],
) -> int:
    """Return the lamport balance of the player's authority wallet."""
    return get_required_account(accounts, player["authority_account"])["lamports"]


def player_token_balance(
    accounts: dict[str, dict[str, Any]],
    player: dict[str, Any],
    token_symbol: str,
) -> int:
    """
    Return a player's token-account balance for one symbol.

    Policies stay readable when they can ask for `player_token_balance(..., "USDC")` instead of
    repeatedly resolving token-account pubkeys by hand.
    """
    token_account_pubkey = player["token_accounts"].get(token_symbol)
    if token_account_pubkey is None:
        return 0
    return get_required_account(accounts, token_account_pubkey)["lamports"]


def pool_reserve_for_symbol(
    blockchain_state: dict[str, Any],
    pool_id: str,
    token_symbol: str,
) -> int:
    """Return the current reserve balance for one token inside a pool."""
    pool = blockchain_state["pools"][pool_id]
    token_index = pool["token_symbols"].index(token_symbol)
    vault_pubkey = pool["pool_vault_accounts"][token_index]
    return get_required_account(blockchain_state["accounts"], vault_pubkey)["lamports"]


def estimate_market_reference_price_scaled(
    blockchain_state: dict[str, Any],
    market_id: str,
) -> int:
    """
    Estimate the current base/quote price for a market.

    The simulator does not have a full orderbook matching engine yet, so this is an
    approximation:
    - if the market has traded recently, use `runtime_state["last_trade_price"]`
    - otherwise infer a rough price from the quote/base vault balances
    """
    market = blockchain_state["markets"][market_id]
    runtime_state = market.get("runtime_state", {})
    last_trade_price = runtime_state.get("last_trade_price")
    if last_trade_price is not None and last_trade_price > 0:
        return int(last_trade_price)

    base_vault_balance = get_required_account(
        blockchain_state["accounts"],
        market["base_vault_account"],
    )["lamports"]
    quote_vault_balance = get_required_account(
        blockchain_state["accounts"],
        market["quote_vault_account"],
    )["lamports"]
    if base_vault_balance <= 0:
        return MARKET_PRICE_SCALE
    return max(1, (quote_vault_balance * MARKET_PRICE_SCALE) // base_vault_balance)


def estimate_pool_spot_price_scaled(
    blockchain_state: dict[str, Any],
    pool_id: str,
    base_symbol: str,
    quote_symbol: str,
) -> int:
    """
    Estimate the instantaneous pool price of one unit of `base_symbol` in `quote_symbol`.

    This is a curve-aware simulator approximation:
    - constant-product and stable pools use the current reserve ratio
    - weighted pools also divide by the token weights so the price reflects the target basket

    It is good enough for policy decisions such as "is the pool cheaper than the market?" even
    though it is not a full swap simulation by itself.
    """
    pool = blockchain_state["pools"][pool_id]
    base_index = pool["token_symbols"].index(base_symbol)
    quote_index = pool["token_symbols"].index(quote_symbol)
    base_reserve = pool_reserve_for_symbol(blockchain_state, pool_id, base_symbol)
    quote_reserve = pool_reserve_for_symbol(blockchain_state, pool_id, quote_symbol)
    if base_reserve <= 0:
        return MARKET_PRICE_SCALE

    if pool["pool_type"] in {POOL_TYPE_CONSTANT_PRODUCT, POOL_TYPE_STABLE_SWAP}:
        return max(1, (quote_reserve * MARKET_PRICE_SCALE) // base_reserve)

    base_weight_bps = pool["normalized_weights_bps"][base_index]
    quote_weight_bps = pool["normalized_weights_bps"][quote_index]
    weighted_quote = quote_reserve * max(base_weight_bps, 1)
    weighted_base = base_reserve * max(quote_weight_bps, 1)
    return max(1, (weighted_quote * MARKET_PRICE_SCALE) // max(weighted_base, 1))


def estimate_token_price_in_usdc_scaled(
    blockchain_state: dict[str, Any],
    token_symbol: str,
) -> int:
    """
    Estimate a token's value in USDC terms for higher-level player policies.

    These prices are not oracle-grade and should not be treated as canonical truth. They are
    policy inputs used for decisions like inventory balancing or portfolio reweighting.
    """
    if token_symbol in {"USDC", "USDT"}:
        return MARKET_PRICE_SCALE
    if token_symbol == "SOL":
        candidate_prices = [
            estimate_market_reference_price_scaled(blockchain_state, "sol_usdc_spot"),
            estimate_pool_spot_price_scaled(
                blockchain_state,
                "volatile_sol_usdc",
                base_symbol="SOL",
                quote_symbol="USDC",
            ),
            estimate_pool_spot_price_scaled(
                blockchain_state,
                "weighted_sol_jup_usdc",
                base_symbol="SOL",
                quote_symbol="USDC",
            ),
        ]
        return sum(candidate_prices) // max(len(candidate_prices), 1)
    if token_symbol == "JUP":
        return estimate_pool_spot_price_scaled(
            blockchain_state,
            "weighted_sol_jup_usdc",
            base_symbol="JUP",
            quote_symbol="USDC",
        )
    return MARKET_PRICE_SCALE


def estimate_pool_swap_output_exact_input(
    blockchain_state: dict[str, Any],
    pool_id: str,
    source_symbol: str,
    destination_symbol: str,
    total_input_amount: int,
) -> int:
    """
    Estimate the output side of an exact-input pool swap using current reserves.

    Policies use this before creating a swap so they can set a reasonable slippage threshold
    instead of using a fixed magic number.
    """
    if total_input_amount <= 0:
        return 0

    pool = blockchain_state["pools"][pool_id]
    source_index = pool["token_symbols"].index(source_symbol)
    destination_index = pool["token_symbols"].index(destination_symbol)
    source_reserve = pool_reserve_for_symbol(blockchain_state, pool_id, source_symbol)
    destination_reserve = pool_reserve_for_symbol(blockchain_state, pool_id, destination_symbol)
    fee_bps = fee_bps_for_pool(pool)
    fee_amount = (total_input_amount * fee_bps) // 10_000
    if fee_amount >= total_input_amount:
        fee_amount = max(total_input_amount - 1, 0)
    net_input_amount = total_input_amount - fee_amount
    return pool_output_for_exact_input(
        pool=pool,
        source_reserve=source_reserve,
        destination_reserve=destination_reserve,
        source_index=source_index,
        destination_index=destination_index,
        net_input_amount=net_input_amount,
    )


def estimate_pool_swap_input_for_exact_output(
    blockchain_state: dict[str, Any],
    pool_id: str,
    source_symbol: str,
    destination_symbol: str,
    desired_output_amount: int,
    max_total_input_amount: int,
) -> int | None:
    """
    Estimate the total input needed for an exact-output pool swap.

    Returning `None` means the desired output cannot be achieved under the current reserves and
    the supplied max-input ceiling.
    """
    if desired_output_amount <= 0 or max_total_input_amount <= 0:
        return None

    pool = blockchain_state["pools"][pool_id]
    source_index = pool["token_symbols"].index(source_symbol)
    destination_index = pool["token_symbols"].index(destination_symbol)
    source_reserve = pool_reserve_for_symbol(blockchain_state, pool_id, source_symbol)
    destination_reserve = pool_reserve_for_symbol(blockchain_state, pool_id, destination_symbol)
    required_input = required_input_for_exact_output(
        pool=pool,
        source_reserve=source_reserve,
        destination_reserve=destination_reserve,
        source_index=source_index,
        destination_index=destination_index,
        desired_output_amount=desired_output_amount,
        max_total_input_amount=max_total_input_amount,
    )
    if required_input is None:
        return None
    return required_input[0]


def build_portfolio_value_by_symbol_usdc(
    blockchain_state: dict[str, Any],
    player: dict[str, Any],
) -> dict[str, int]:
    """
    Value a player's token balances in USDC terms.

    The rebalancer and market-maker policies both reason about portfolio composition, so this
    helper turns the raw token-account balances into a comparable value map.
    """
    values = {}
    accounts = blockchain_state["accounts"]
    for token_symbol in player["token_accounts"]:
        balance = player_token_balance(accounts, player, token_symbol)
        price_scaled = estimate_token_price_in_usdc_scaled(blockchain_state, token_symbol)
        values[token_symbol] = (balance * price_scaled) // MARKET_PRICE_SCALE
    return values


def generate_inventory_market_maker_policy(
    player: dict[str, Any],
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    State-driven market-maker policy based on inventory balance.

    This is deliberately one market-maker policy, not the market-maker policy. A later player of
    the same `player_type` could use a different policy name such as a spread-capturing maker, a
    passive quoting maker, or a cross-venue hedging maker. The architecture here keeps those
    concerns separate.

    Current behavior:
    - optionally tops up a shared liquidity wallet when that system wallet falls below a target
    - estimates a SOL/USDC reference price from current market state
    - values the player's SOL and USDC inventory in the same USDC-denominated scale
    - compares the actual SOL weight to a target band
    - buys SOL on the market when underweight and sells SOL when overweight

    The important modeling idea is that the policy reacts to live balances and prices rather than
    emitting the same hard-coded trade every slot.
    """
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    if not player_policy_is_due(player, slot, slots_per_epoch):
        return []

    accounts = blockchain_state["accounts"]
    config = player.get("policy_config") or {}
    policy_name = resolve_player_policy_name(player)
    intents: list[dict[str, Any]] = []

    funding_rule = config.get("funding_rule")
    liquidity_wallet = config.get("liquidity_wallet")
    if (
        liquidity_wallet is not None
        and slot_matches_rule(slot, slots_per_epoch, funding_rule)
    ):
        liquidity_target_lamports = int(config.get("liquidity_wallet_target_lamports", 0))
        liquidity_top_up_cap_lamports = int(config.get("liquidity_wallet_top_up_cap_lamports", 0))
        authority_reserve_lamports = int(config.get("authority_reserve_lamports", 0))
        current_liquidity_balance = get_required_account(accounts, liquidity_wallet)["lamports"]
        authority_balance = player_authority_balance(accounts, player)
        top_up_capacity = max(authority_balance - authority_reserve_lamports, 0)
        top_up_amount = min(
            liquidity_top_up_cap_lamports,
            max(liquidity_target_lamports - current_liquidity_balance, 0),
            top_up_capacity,
        )
        if top_up_amount > 0:
            intents.append(
                build_player_intent(
                    player_id=player["player_id"],
                    intent_type=INTENT_TYPE_SYSTEM_TRANSFER,
                    parameters={
                        "recipient": liquidity_wallet,
                        "lamports": top_up_amount,
                    },
                    execution_preferences={
                        "message_format": LEGACY_TRANSACTION_FORMAT,
                        "compute_unit_price_micro_lamports": int(
                            config.get("funding_priority_fee_micro_lamports", 5_000)
                        ),
                    },
                    metadata={
                        "policy_name": policy_name,
                        "intent_label": "fund_liquidity_pool",
                        "policy_reason": "shared_liquidity_wallet_below_target",
                    },
                )
            )

    market_id = str(config.get("market_id", "sol_usdc_spot"))
    quote_symbol = str(config.get("quote_symbol", "USDC"))
    base_symbol = str(config.get("base_symbol", "SOL"))
    reference_price = estimate_market_reference_price_scaled(blockchain_state, market_id)
    base_balance = player_token_balance(accounts, player, base_symbol)
    quote_balance = player_token_balance(accounts, player, quote_symbol)
    base_value_quote = (base_balance * reference_price) // MARKET_PRICE_SCALE
    total_value_quote = base_value_quote + quote_balance
    if total_value_quote <= 0:
        return intents

    target_base_weight_bps = int(config.get("target_base_weight_bps", 5_000))
    inventory_band_bps = int(config.get("inventory_band_bps", 1_000))
    max_trade_quote_amount = int(config.get("max_trade_quote_amount", 400_000_000))
    quote_spread_bps = int(config.get("quote_spread_bps", 30))
    actual_base_weight_bps = (base_value_quote * 10_000) // max(total_value_quote, 1)

    if actual_base_weight_bps < target_base_weight_bps - inventory_band_bps:
        quote_budget = min(
            max_trade_quote_amount,
            max((target_base_weight_bps * total_value_quote) // 10_000 - base_value_quote, 0),
            quote_balance,
        )
        base_amount = (quote_budget * MARKET_PRICE_SCALE) // max(reference_price, 1)
        quote_amount_limit = quote_budget
        limit_price = max(1, (reference_price * (10_000 + quote_spread_bps)) // 10_000)
        if base_amount > 0 and quote_amount_limit > 0:
            intents.append(
                build_player_intent(
                    player_id=player["player_id"],
                    intent_type=INTENT_TYPE_MARKET_TRADE,
                    venue_type="market",
                    venue_id=market_id,
                    parameters={
                        "side": MARKET_SIDE_BUY,
                        "order_type": MARKET_ORDER_TYPE_LIMIT,
                        "base_amount": base_amount,
                        "quote_amount_limit": quote_amount_limit,
                        "limit_price": limit_price,
                    },
                    execution_preferences={
                        "message_format": LEGACY_TRANSACTION_FORMAT,
                        "compute_unit_price_micro_lamports": int(
                            config.get("trade_priority_fee_micro_lamports", 9_000)
                        ),
                    },
                    metadata={
                        "policy_name": policy_name,
                        "intent_label": "market_maker_inventory_buy",
                        "policy_reason": "base_inventory_underweight",
                    },
                )
            )
    elif actual_base_weight_bps > target_base_weight_bps + inventory_band_bps:
        target_base_value_quote = (target_base_weight_bps * total_value_quote) // 10_000
        excess_base_value_quote = max(base_value_quote - target_base_value_quote, 0)
        trade_value_quote = min(max_trade_quote_amount, excess_base_value_quote)
        base_amount = min(
            base_balance,
            (trade_value_quote * MARKET_PRICE_SCALE) // max(reference_price, 1),
        )
        limit_price = max(1, (reference_price * (10_000 - quote_spread_bps)) // 10_000)
        quote_amount_limit = max(1, (base_amount * limit_price) // MARKET_PRICE_SCALE)
        if base_amount > 0 and quote_amount_limit > 0:
            intents.append(
                build_player_intent(
                    player_id=player["player_id"],
                    intent_type=INTENT_TYPE_MARKET_TRADE,
                    venue_type="market",
                    venue_id=market_id,
                    parameters={
                        "side": MARKET_SIDE_SELL,
                        "order_type": MARKET_ORDER_TYPE_LIMIT,
                        "base_amount": base_amount,
                        "quote_amount_limit": quote_amount_limit,
                        "limit_price": limit_price,
                    },
                    execution_preferences={
                        "message_format": LEGACY_TRANSACTION_FORMAT,
                        "compute_unit_price_micro_lamports": int(
                            config.get("trade_priority_fee_micro_lamports", 9_000)
                        ),
                    },
                    metadata={
                        "policy_name": policy_name,
                        "intent_label": "market_maker_inventory_sell",
                        "policy_reason": "base_inventory_overweight",
                    },
                )
            )

    return intents


def generate_adaptive_two_token_lp_policy(
    player: dict[str, Any],
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    State-driven liquidity-provider policy for a two-token AMM pool.

    This is one LP policy, not the only LP policy. Later you may want range-order LPs,
    volatility-sensitive LPs, or fee-harvesting LPs. For now the policy is intentionally simple
    but still state-aware:
    - it wakes up on a configurable cadence
    - it checks the player's current LP share so it does not keep adding forever
    - it looks at the current pool price and optionally refuses to add if the pool is too far
      away from the external market reference
    - it sizes deposits using the pool's current reserve ratio instead of fixed token amounts
    """
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    if not player_policy_is_due(player, slot, slots_per_epoch):
        return []

    accounts = blockchain_state["accounts"]
    config = player.get("policy_config") or {}
    policy_name = resolve_player_policy_name(player)
    pool_id = str(config.get("pool_id", "volatile_sol_usdc"))
    pool = blockchain_state["pools"][pool_id]
    if len(pool["token_symbols"]) != 2:
        return []

    base_symbol = pool["token_symbols"][0]
    quote_symbol = pool["token_symbols"][1]
    reserve_base = pool_reserve_for_symbol(blockchain_state, pool_id, base_symbol)
    reserve_quote = pool_reserve_for_symbol(blockchain_state, pool_id, quote_symbol)
    if reserve_base <= 0 or reserve_quote <= 0:
        return []

    pool_price = estimate_pool_spot_price_scaled(
        blockchain_state,
        pool_id,
        base_symbol=base_symbol,
        quote_symbol=quote_symbol,
    )
    reference_market_id = config.get("reference_market_id")
    if reference_market_id is not None:
        reference_price = estimate_market_reference_price_scaled(
            blockchain_state,
            str(reference_market_id),
        )
        price_deviation_bps = abs(pool_price - reference_price) * 10_000 // max(reference_price, 1)
        if price_deviation_bps > int(config.get("max_price_deviation_bps", 500)):
            return []

    lp_receipt_account = str(config.get("lp_receipt_account", ""))
    player_lp_tokens = get_required_account(accounts, lp_receipt_account)["lamports"]
    lp_supply = max(get_required_account(accounts, pool["pool_lp_mint"])["lamports"], 1)
    current_pool_share_bps = (player_lp_tokens * 10_000) // lp_supply
    if current_pool_share_bps >= int(config.get("max_pool_share_bps", 4_000)):
        return []

    available_base = player_token_balance(accounts, player, base_symbol)
    available_quote = player_token_balance(accounts, player, quote_symbol)
    spend_share_bps = int(config.get("deposit_balance_share_bps", 800))
    proposed_base = (available_base * spend_share_bps) // 10_000
    proposed_quote = (available_quote * spend_share_bps) // 10_000
    deposit_base = min(
        proposed_base,
        (proposed_quote * MARKET_PRICE_SCALE) // max(pool_price, 1),
    )
    deposit_quote = min(
        proposed_quote,
        (deposit_base * pool_price) // MARKET_PRICE_SCALE,
    )
    if deposit_base <= 0 or deposit_quote <= 0:
        return []

    expected_lp_tokens = min(
        (deposit_base * lp_supply) // max(reserve_base, 1),
        (deposit_quote * lp_supply) // max(reserve_quote, 1),
    )
    if expected_lp_tokens <= 0:
        return []

    min_lp_tokens_out = max(
        1,
        (expected_lp_tokens * (10_000 - int(config.get("lp_slippage_bps", 300)))) // 10_000,
    )
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_LIQUIDITY_ADD,
            venue_type="pool",
            venue_id=pool_id,
            parameters={
                "max_token_amounts": [deposit_base, deposit_quote],
                "min_lp_tokens_out": min_lp_tokens_out,
                "lp_receipt_account": lp_receipt_account,
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": int(
                    config.get("priority_fee_micro_lamports", 8_000)
                ),
            },
            metadata={
                "policy_name": policy_name,
                "intent_label": "adaptive_pool_liquidity_add",
                "policy_reason": "pool_share_below_target_and_pool_price_within_band",
            },
        )
    ]


def generate_retail_flow_policy(
    player: dict[str, Any],
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    State-driven retail-user policy mixing payments with occasional market participation.

    This is only one retail policy. Another retail player later might be momentum-driven,
    DCA-driven, payment-only, or highly fee-sensitive. The point here is to keep the retail
    behavior configurable and separate from the generic `retail_user` type.

    Current behavior:
    - makes merchant payments on its own cadence if the wallet has enough spare SOL balance
    - occasionally buys SOL on the market using spare USDC
    - skips the market buy if the orderbook venue looks materially worse than the pool venue
    """
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    if not player_policy_is_due(player, slot, slots_per_epoch):
        return []

    accounts = blockchain_state["accounts"]
    config = player.get("policy_config") or {}
    policy_name = resolve_player_policy_name(player)
    intents: list[dict[str, Any]] = []

    if slot_matches_rule(slot, slots_per_epoch, config.get("payment_rule")):
        payment_lamports = int(config.get("payment_lamports", 0))
        authority_buffer_lamports = int(config.get("authority_buffer_lamports", 0))
        if (
            payment_lamports > 0
            and player_authority_balance(accounts, player) >= payment_lamports + authority_buffer_lamports
        ):
            intents.append(
                build_player_intent(
                    player_id=player["player_id"],
                    intent_type=INTENT_TYPE_SYSTEM_TRANSFER,
                    parameters={
                        "recipient": str(config.get("merchant_account", make_address("merchant"))),
                        "lamports": payment_lamports,
                    },
                    execution_preferences={
                        "message_format": LEGACY_TRANSACTION_FORMAT,
                        "compute_unit_price_micro_lamports": int(
                            config.get("payment_priority_fee_micro_lamports", 0)
                        ),
                    },
                    metadata={
                        "policy_name": policy_name,
                        "intent_label": "merchant_payment",
                        "policy_reason": "retail_consumption_flow",
                    },
                )
            )

    if slot_matches_rule(slot, slots_per_epoch, config.get("trade_rule")):
        market_id = str(config.get("market_id", "sol_usdc_spot"))
        comparison_pool_id = str(config.get("comparison_pool_id", "volatile_sol_usdc"))
        quote_symbol = str(config.get("quote_symbol", "USDC"))
        base_symbol = str(config.get("base_symbol", "SOL"))
        quote_balance = player_token_balance(accounts, player, quote_symbol)
        min_quote_buffer = int(config.get("min_quote_buffer", 0))
        if quote_balance > min_quote_buffer:
            market_price = estimate_market_reference_price_scaled(blockchain_state, market_id)
            comparison_pool_price = estimate_pool_spot_price_scaled(
                blockchain_state,
                comparison_pool_id,
                base_symbol=base_symbol,
                quote_symbol=quote_symbol,
            )
            market_premium_bps = (
                (market_price - comparison_pool_price) * 10_000 // max(comparison_pool_price, 1)
            )
            if market_premium_bps <= int(config.get("max_market_premium_vs_pool_bps", 150)):
                quote_budget = min(
                    int(config.get("max_buy_quote_amount", 120_000_000)),
                    quote_balance - min_quote_buffer,
                )
                base_amount = (quote_budget * MARKET_PRICE_SCALE) // max(market_price, 1)
                if base_amount > 0 and quote_budget > 0:
                    intents.append(
                        build_player_intent(
                            player_id=player["player_id"],
                            intent_type=INTENT_TYPE_MARKET_TRADE,
                            venue_type="market",
                            venue_id=market_id,
                            parameters={
                                "side": MARKET_SIDE_BUY,
                                "order_type": MARKET_ORDER_TYPE_MARKET,
                                "base_amount": base_amount,
                                "quote_amount_limit": quote_budget,
                                "limit_price": 0,
                            },
                            execution_preferences={
                                "message_format": VERSIONED_V0_TRANSACTION_FORMAT,
                                "lookup_table_account": str(
                                    config.get("lookup_table_account", make_address("market_alt"))
                                ),
                                "compute_unit_price_micro_lamports": int(
                                    config.get("trade_priority_fee_micro_lamports", 4_000)
                                ),
                            },
                            metadata={
                                "policy_name": policy_name,
                                "intent_label": "retail_market_buy",
                                "policy_reason": "retail_portfolio_accumulation",
                            },
                        )
                    )

    return intents


def generate_cross_venue_arbitrage_policy(
    player: dict[str, Any],
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    State-driven arbitrage policy comparing a pool against the spot market.

    This is one arbitrage policy, not the only possible one. It does not yet reason about
    network-local views, pending queue depth, or fork risk; it only reacts to the current chain
    state. Later arbitrage policies can become more latency-aware without changing the player
    type itself.

    Current behavior:
    - compares the volatile SOL/USDC pool price to the SOL/USDC market price
    - only trades if the spread exceeds fees, slippage tolerance, and a minimum edge threshold
    - sizes the trade as a share of the available balance, increasing with the edge
    - raises priority fee as the opportunity gets larger
    """
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    if not player_policy_is_due(player, slot, slots_per_epoch):
        return []

    accounts = blockchain_state["accounts"]
    config = player.get("policy_config") or {}
    policy_name = resolve_player_policy_name(player)
    pool_id = str(config.get("pool_id", "volatile_sol_usdc"))
    market_id = str(config.get("market_id", "sol_usdc_spot"))
    base_symbol = str(config.get("base_symbol", "SOL"))
    quote_symbol = str(config.get("quote_symbol", "USDC"))
    market_price = estimate_market_reference_price_scaled(blockchain_state, market_id)
    pool_price = estimate_pool_spot_price_scaled(
        blockchain_state,
        pool_id,
        base_symbol=base_symbol,
        quote_symbol=quote_symbol,
    )
    edge_bps = abs(pool_price - market_price) * 10_000 // max(market_price, 1)
    min_edge_bps = int(config.get("min_edge_bps", 80))
    if edge_bps < min_edge_bps:
        return []

    edge_full_size_bps = max(int(config.get("edge_full_size_bps", 250)), 1)
    edge_utilization_bps = min(edge_bps, edge_full_size_bps)
    max_input_share_bps = int(config.get("max_input_share_bps", 2_000))
    slippage_bps = int(config.get("slippage_bps", 150))

    if pool_price < market_price:
        available_input = player_token_balance(accounts, player, quote_symbol)
        max_input_amount = (available_input * max_input_share_bps) // 10_000
        input_amount = max(
            int(config.get("min_input_amount", 1)),
            (max_input_amount * edge_utilization_bps) // edge_full_size_bps,
        )
        estimated_output = estimate_pool_swap_output_exact_input(
            blockchain_state,
            pool_id,
            source_symbol=quote_symbol,
            destination_symbol=base_symbol,
            total_input_amount=input_amount,
        )
        if input_amount <= 0 or estimated_output <= 0:
            return []
        source_symbol = quote_symbol
        destination_symbol = base_symbol
    else:
        available_input = player_token_balance(accounts, player, base_symbol)
        max_input_amount = (available_input * max_input_share_bps) // 10_000
        input_amount = max(
            int(config.get("min_input_amount", 1)),
            (max_input_amount * edge_utilization_bps) // edge_full_size_bps,
        )
        estimated_output = estimate_pool_swap_output_exact_input(
            blockchain_state,
            pool_id,
            source_symbol=base_symbol,
            destination_symbol=quote_symbol,
            total_input_amount=input_amount,
        )
        if input_amount <= 0 or estimated_output <= 0:
            return []
        source_symbol = base_symbol
        destination_symbol = quote_symbol

    other_amount_threshold = max(1, (estimated_output * (10_000 - slippage_bps)) // 10_000)
    priority_fee = int(config.get("base_priority_fee_micro_lamports", 8_000)) + (
        edge_bps * int(config.get("priority_fee_per_edge_bps", 20))
    )
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_SWAP,
            venue_type="pool",
            venue_id=pool_id,
            parameters={
                "source_symbol": source_symbol,
                "destination_symbol": destination_symbol,
                "swap_mode": SWAP_MODE_EXACT_INPUT,
                "amount": input_amount,
                "other_amount_threshold": other_amount_threshold,
            },
            execution_preferences={
                "message_format": LEGACY_TRANSACTION_FORMAT,
                "compute_unit_price_micro_lamports": priority_fee,
            },
            metadata={
                "policy_name": policy_name,
                "intent_label": "cross_venue_arbitrage",
                "policy_reason": "pool_market_price_dislocation",
            },
        )
    ]


def generate_stable_balance_router_policy(
    player: dict[str, Any],
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    State-driven router policy that rebalances stablecoin inventory through a stable pool.

    This policy models a router as a portfolio balancer for now:
    - it tracks the player's USDC and USDT balances
    - it compares the current split to a target balance split
    - when the imbalance exceeds a band, it requests an exact-output swap to fill the deficit

    Later router policies can become more path-search driven across many venues, but exact-output
    balancing is a clean first policy because routers often care about delivering a target output
    amount.
    """
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    if not player_policy_is_due(player, slot, slots_per_epoch):
        return []

    accounts = blockchain_state["accounts"]
    config = player.get("policy_config") or {}
    policy_name = resolve_player_policy_name(player)
    pool_id = str(config.get("pool_id", "stable_usdc_usdt"))
    usdc_balance = player_token_balance(accounts, player, "USDC")
    usdt_balance = player_token_balance(accounts, player, "USDT")
    total_balance = usdc_balance + usdt_balance
    if total_balance <= 0:
        return []

    target_usdc_weight_bps = int(config.get("target_usdc_weight_bps", 5_000))
    target_usdc_balance = (total_balance * target_usdc_weight_bps) // 10_000
    band_bps = int(config.get("balance_band_bps", 500))
    current_usdc_weight_bps = (usdc_balance * 10_000) // total_balance
    if abs(current_usdc_weight_bps - target_usdc_weight_bps) <= band_bps:
        return []

    if current_usdc_weight_bps > target_usdc_weight_bps:
        source_symbol = "USDC"
        destination_symbol = "USDT"
        destination_deficit = max((total_balance - target_usdc_balance) - usdt_balance, 0)
        available_source = usdc_balance
    else:
        source_symbol = "USDT"
        destination_symbol = "USDC"
        destination_deficit = max(target_usdc_balance - usdc_balance, 0)
        available_source = usdt_balance

    desired_output_amount = min(
        int(config.get("max_output_amount", 150_000_000)),
        destination_deficit,
    )
    max_total_input_amount = min(
        available_source,
        (available_source * int(config.get("max_input_share_bps", 3_000))) // 10_000,
    )
    required_input_amount = estimate_pool_swap_input_for_exact_output(
        blockchain_state,
        pool_id,
        source_symbol=source_symbol,
        destination_symbol=destination_symbol,
        desired_output_amount=desired_output_amount,
        max_total_input_amount=max_total_input_amount,
    )
    if desired_output_amount <= 0 or required_input_amount is None:
        return []

    max_input_with_slippage = max(
        required_input_amount,
        (required_input_amount * (10_000 + int(config.get("slippage_bps", 80)))) // 10_000,
    )
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_SWAP,
            venue_type="pool",
            venue_id=pool_id,
            parameters={
                "source_symbol": source_symbol,
                "destination_symbol": destination_symbol,
                "swap_mode": SWAP_MODE_EXACT_OUTPUT,
                "amount": desired_output_amount,
                "other_amount_threshold": max_input_with_slippage,
            },
            execution_preferences={
                "message_format": VERSIONED_V0_TRANSACTION_FORMAT,
                "lookup_table_account": str(
                    config.get("lookup_table_account", make_address("stable_pool_alt"))
                ),
                "compute_unit_price_micro_lamports": int(
                    config.get("priority_fee_micro_lamports", 5_000)
                ),
            },
            metadata={
                "policy_name": policy_name,
                "intent_label": "stable_balance_route",
                "policy_reason": "stable_inventory_drift_outside_band",
            },
        )
    ]


def generate_target_weight_rebalancer_policy(
    player: dict[str, Any],
    blockchain_state: dict[str, Any],
    slot: int,
) -> list[dict[str, Any]]:
    """
    State-driven portfolio rebalancing policy for a weighted multi-token pool.

    This is one rebalancer policy, not the only one. The current version:
    - values the player's token balances in USDC terms
    - compares current weights against either configured target weights or the pool weights
    - identifies the most overweight and most underweight assets
    - trades from the overweight asset into the underweight asset through the weighted pool

    The policy intentionally uses a single direct swap rather than many small child orders so the
    simulator still stays readable while moving from fixed templates to state-driven behavior.
    """
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    if not player_policy_is_due(player, slot, slots_per_epoch):
        return []

    accounts = blockchain_state["accounts"]
    config = player.get("policy_config") or {}
    policy_name = resolve_player_policy_name(player)
    pool_id = str(config.get("pool_id", "weighted_sol_jup_usdc"))
    pool = blockchain_state["pools"][pool_id]
    portfolio_values = build_portfolio_value_by_symbol_usdc(blockchain_state, player)
    total_value = sum(portfolio_values.values())
    if total_value <= 0:
        return []

    target_weights_bps = config.get("target_weights_bps")
    if target_weights_bps is None:
        target_weights_bps = {
            token_symbol: pool["normalized_weights_bps"][index]
            for index, token_symbol in enumerate(pool["token_symbols"])
        }
    weight_band_bps = int(config.get("weight_band_bps", 600))

    deviations = []
    for token_symbol, target_weight_bps in target_weights_bps.items():
        current_value = portfolio_values.get(token_symbol, 0)
        current_weight_bps = (current_value * 10_000) // total_value
        deviations.append(
            {
                "token_symbol": token_symbol,
                "current_value": current_value,
                "target_value": (total_value * int(target_weight_bps)) // 10_000,
                "weight_delta_bps": current_weight_bps - int(target_weight_bps),
            }
        )

    overweight = max(deviations, key=lambda item: item["weight_delta_bps"])
    underweight = min(deviations, key=lambda item: item["weight_delta_bps"])
    if (
        overweight["weight_delta_bps"] <= weight_band_bps
        or underweight["weight_delta_bps"] >= -weight_band_bps
    ):
        return []

    source_symbol = str(overweight["token_symbol"])
    destination_symbol = str(underweight["token_symbol"])
    source_price = estimate_token_price_in_usdc_scaled(blockchain_state, source_symbol)
    source_balance = player_token_balance(accounts, player, source_symbol)
    excess_value = max(overweight["current_value"] - overweight["target_value"], 0)
    deficit_value = max(underweight["target_value"] - underweight["current_value"], 0)
    trade_value_quote = min(
        int(config.get("max_trade_value_quote_amount", 250_000_000)),
        excess_value,
        deficit_value,
    )
    max_input_amount = (source_balance * int(config.get("max_input_share_bps", 2_500))) // 10_000
    input_amount = min(
        max_input_amount,
        (trade_value_quote * MARKET_PRICE_SCALE) // max(source_price, 1),
    )
    estimated_output = estimate_pool_swap_output_exact_input(
        blockchain_state,
        pool_id,
        source_symbol=source_symbol,
        destination_symbol=destination_symbol,
        total_input_amount=input_amount,
    )
    if input_amount <= 0 or estimated_output <= 0:
        return []

    other_amount_threshold = max(
        1,
        (estimated_output * (10_000 - int(config.get("slippage_bps", 200)))) // 10_000,
    )
    return [
        build_player_intent(
            player_id=player["player_id"],
            intent_type=INTENT_TYPE_POOL_SWAP,
            venue_type="pool",
            venue_id=pool_id,
            parameters={
                "source_symbol": source_symbol,
                "destination_symbol": destination_symbol,
                "swap_mode": SWAP_MODE_EXACT_INPUT,
                "amount": input_amount,
                "other_amount_threshold": other_amount_threshold,
            },
            execution_preferences={
                "message_format": VERSIONED_V0_TRANSACTION_FORMAT,
                "lookup_table_account": str(
                    config.get("lookup_table_account", make_address("weighted_pool_alt"))
                ),
                "compute_unit_price_micro_lamports": int(
                    config.get("priority_fee_micro_lamports", 7_500)
                ),
            },
            metadata={
                "policy_name": policy_name,
                "intent_label": "target_weight_rebalance",
                "policy_reason": "portfolio_weights_outside_target_band",
            },
        )
    ]


PLAYER_POLICY_GENERATORS = {
    PLAYER_POLICY_INVENTORY_MARKET_MAKER: generate_inventory_market_maker_policy,
    PLAYER_POLICY_ADAPTIVE_TWO_TOKEN_LP: generate_adaptive_two_token_lp_policy,
    PLAYER_POLICY_RETAIL_FLOW: generate_retail_flow_policy,
    PLAYER_POLICY_CROSS_VENUE_ARBITRAGE: generate_cross_venue_arbitrage_policy,
    PLAYER_POLICY_STABLE_BALANCE_ROUTER: generate_stable_balance_router_policy,
    PLAYER_POLICY_TARGET_WEIGHT_REBALANCER: generate_target_weight_rebalancer_policy,
}

PLAYER_POLICY_PLAYER_TYPES = {
    PLAYER_POLICY_INVENTORY_MARKET_MAKER: PLAYER_TYPE_MARKET_MAKER,
    PLAYER_POLICY_ADAPTIVE_TWO_TOKEN_LP: PLAYER_TYPE_LIQUIDITY_PROVIDER,
    PLAYER_POLICY_RETAIL_FLOW: PLAYER_TYPE_RETAIL_USER,
    PLAYER_POLICY_CROSS_VENUE_ARBITRAGE: PLAYER_TYPE_ARBITRAGEUR,
    PLAYER_POLICY_STABLE_BALANCE_ROUTER: PLAYER_TYPE_ROUTER,
    PLAYER_POLICY_TARGET_WEIGHT_REBALANCER: PLAYER_TYPE_REBALANCER,
}

DEFAULT_PLAYER_POLICY_BY_TYPE = {
    PLAYER_TYPE_MARKET_MAKER: PLAYER_POLICY_INVENTORY_MARKET_MAKER,
    PLAYER_TYPE_LIQUIDITY_PROVIDER: PLAYER_POLICY_ADAPTIVE_TWO_TOKEN_LP,
    PLAYER_TYPE_RETAIL_USER: PLAYER_POLICY_RETAIL_FLOW,
    PLAYER_TYPE_ARBITRAGEUR: PLAYER_POLICY_CROSS_VENUE_ARBITRAGE,
    PLAYER_TYPE_ROUTER: PLAYER_POLICY_STABLE_BALANCE_ROUTER,
    PLAYER_TYPE_REBALANCER: PLAYER_POLICY_TARGET_WEIGHT_REBALANCER,
}


def generate_player_intents(
    blockchain_state: dict[str, Any],
    slot: int | None = None,
) -> list[dict[str, Any]]:
    """
    Generate player intents by evaluating each active player's configured policy.

    This is now a policy registry rather than a hard-coded player-type switch. The important
    generalization is:
    - player type describes the actor class
    - policy name describes the decision rule

    That means later you can have multiple market makers or routers with different behaviors
    without adding more player types.
    """
    target_slot = blockchain_state["next_slot"] if slot is None else slot
    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    refresh_runtime_views(blockchain_state)
    intents: list[dict[str, Any]] = []
    for player in blockchain_state["players"].values():
        if player["status"] != REGISTRY_STATUS_ACTIVE:
            continue
        if not player_policy_is_due(player, target_slot, slots_per_epoch):
            continue

        policy_name = resolve_player_policy_name(player)
        if policy_name is None:
            continue
        expected_player_type = PLAYER_POLICY_PLAYER_TYPES.get(policy_name)
        if expected_player_type is not None and expected_player_type != player["player_type"]:
            raise ValueError(
                f"player {player['player_id']} uses policy {policy_name} for the wrong player_type"
            )
        generator = PLAYER_POLICY_GENERATORS.get(policy_name)
        if generator is None:
            continue
        intents.extend(generator(player, blockchain_state, target_slot))
    return intents


def generate_slot_transaction_requests(
    blockchain_state: dict[str, Any],
    slot: int | None = None,
) -> list[dict[str, Any]]:
    """
    Generate fresh transaction requests for the chain's next slot.

    Player policies are now state-driven, but still deterministic and single-policy-per-player.
    This function evaluates the active players for the next slot, annotates the resulting intents
    with scheduling metadata, and compiles them into concrete transaction requests.
    """
    target_slot = blockchain_state["next_slot"] if slot is None else slot
    if target_slot != blockchain_state["next_slot"]:
        raise ValueError("slot request generation must target the chain's next slot")

    if not any(player["status"] == REGISTRY_STATUS_ACTIVE for player in blockchain_state["players"].values()):
        return []

    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    target_epoch = (target_slot - 1) // slots_per_epoch
    intents = generate_player_intents(blockchain_state, slot=target_slot)
    scheduled_intents = []
    for intent in intents:
        intent_copy = deepcopy(intent)
        intent_copy["metadata"] = {
            **intent_copy["metadata"],
            "scheduled_slot": target_slot,
            "scheduled_epoch": target_epoch,
        }
        scheduled_intents.append(intent_copy)

    return compile_player_intents_to_requests(
        scheduled_intents,
        blockchain_state["players"],
        blockchain_state["pools"],
        blockchain_state["markets"],
    )
