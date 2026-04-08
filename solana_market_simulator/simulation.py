"""Simulation-loop orchestration."""

from typing import Any

from .chain_state import (
    append_block,
    produce_block,
    select_leader_for_slot,
    should_skip_slot,
    skip_slot,
    submit_transaction_request,
    summarize_blocks,
    summarize_skipped_slots,
)
from .policies import generate_slot_transaction_requests


def run_simulation(
    blockchain_state: dict[str, Any],
    num_slots: int,
    max_transactions_per_block: int | None = None,
) -> dict[str, Any]:
    """
    Run the blockchain forward for many slots and epochs.

    This is the missing step between one-shot block demos and a continuously advancing chain.
    Each slot:
    - active players evaluate their configured policies against the current state
    - those intents are compiled into transaction requests and submitted to the pending queue
    - the scheduled validator produces a block, even if it ends up empty
    - append_block commits the slot, updates epoch state, and applies validator exit transitions

    The policies are deterministic for reproducibility, but they are no longer fixed templates:
    they react to current balances, pool prices, market prices, and prior simulation outcomes.
    """
    if num_slots <= 0:
        raise ValueError("num_slots must be positive")

    produced_blocks = []
    skipped_slots = []
    generated_request_count = 0
    slots_with_new_requests = 0

    for _ in range(num_slots):
        slot = blockchain_state["next_slot"]
        slot_requests = generate_slot_transaction_requests(blockchain_state, slot=slot)
        generated_request_count += len(slot_requests)
        if slot_requests:
            slots_with_new_requests += 1
        for request_tx in slot_requests:
            submit_transaction_request(blockchain_state, request_tx)

        scheduled_leader_id = (
            select_leader_for_slot(blockchain_state, slot) if blockchain_state["validators"] else None
        )
        if scheduled_leader_id is not None and should_skip_slot(blockchain_state, slot, scheduled_leader_id):
            skipped_slots.append(skip_slot(blockchain_state, leader_id=scheduled_leader_id))
            continue

        block = produce_block(
            blockchain_state,
            leader_id=scheduled_leader_id,
            max_transactions=max_transactions_per_block,
            allow_empty=True,
        )
        append_block(blockchain_state, block)
        produced_blocks.append(block)

    slots_per_epoch = blockchain_state["epoch_schedule"]["slots_per_epoch"]
    epochs_touched = sorted({(block["slot"] - 1) // slots_per_epoch for block in produced_blocks})
    epochs_touched.extend(
        (slot_record["slot"] - 1) // slots_per_epoch
        for slot_record in skipped_slots
    )
    epochs_touched = sorted(set(epochs_touched))
    return {
        "start_slot": blockchain_state["head_slot"] - num_slots + 1,
        "end_slot": blockchain_state["head_slot"],
        "slot_count": num_slots,
        "produced_block_count": len(produced_blocks),
        "skipped_slot_count": len(skipped_slots),
        "epochs_touched": epochs_touched,
        "simulated_time_ms": blockchain_state["simulated_time_ms"],
        "generated_request_count": generated_request_count,
        "slots_with_new_requests": slots_with_new_requests,
        "empty_block_count": sum(block["transaction_count"] == 0 for block in produced_blocks),
        "expired_request_count": sum(block.get("expired_request_count", 0) for block in produced_blocks),
        "confirmed_transaction_count": sum(
            block["confirmed_transaction_count"] for block in produced_blocks
        ),
        "rejected_transaction_count": sum(
            block["rejected_transaction_count"] for block in produced_blocks
        ),
        "total_fees_lamports": sum(block["total_fees_lamports"] for block in produced_blocks),
        "recent_blocks": summarize_blocks(
            produced_blocks,
            slots_per_epoch=slots_per_epoch,
            limit=min(10, len(produced_blocks)),
        ),
        "recent_skipped_slots": summarize_skipped_slots(
            skipped_slots,
            slots_per_epoch=slots_per_epoch,
            limit=min(10, len(skipped_slots)),
        ),
    }
