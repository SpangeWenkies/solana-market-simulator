"""Application entry point for the simulator demo."""

from .constants import DEFAULT_SLOTS_PER_EPOCH
from .chain_state import (
    build_blockchain_state,
    register_player,
    register_validator,
    summarize_blockchain_state,
    summarize_blocks,
    summarize_skipped_slots,
)
from .samples import (
    sample_accounts,
    sample_markets,
    sample_player_intents,
    sample_players,
    sample_pools,
    sample_validators,
)
from .simulation import run_simulation
from .utils import to_json
from .verification import verify_chain


def main() -> None:
    pools = sample_pools()
    markets = sample_markets()
    accounts = sample_accounts()
    players = sample_players()
    validators = sample_validators()
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
    base_player_intents = sample_player_intents(blockchain_state)
    simulation_result = run_simulation(
        blockchain_state,
        num_slots=DEFAULT_SLOTS_PER_EPOCH * 2,
    )
    verification_report = verify_chain(blockchain_state)

    print("POOLS")
    print(to_json(pools))
    print()
    print("MARKETS")
    print(to_json(markets))
    print()
    print("REGISTERED PLAYERS")
    print(to_json(blockchain_state["players"]))
    print()
    print("REGISTERED VALIDATORS")
    print(to_json(blockchain_state["validators"]))
    print()
    print("BASE PLAYER INTENTS")
    print(to_json(base_player_intents))
    print()
    print("SIMULATION RESULT")
    print(to_json(simulation_result))
    print()
    print("BLOCKCHAIN STATE SUMMARY")
    print(to_json(summarize_blockchain_state(blockchain_state)))
    print()
    print("CHAIN VERIFICATION")
    print(to_json(verification_report))
    print()
    print("RECENT BLOCKS")
    print(
        to_json(
            summarize_blocks(
                blockchain_state["blocks"],
                slots_per_epoch=blockchain_state["epoch_schedule"]["slots_per_epoch"],
                limit=10,
            )
        )
    )
    print()
    print("RECENT SKIPPED SLOTS")
    print(
        to_json(
            summarize_skipped_slots(
                blockchain_state["skipped_slots"],
                slots_per_epoch=blockchain_state["epoch_schedule"]["slots_per_epoch"],
                limit=10,
            )
        )
    )
