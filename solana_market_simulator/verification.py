"""Replay-based chain verification helpers."""

from copy import deepcopy
from typing import Any

from .chain_state import (
    append_block,
    apply_transaction_to_state,
    build_blockchain_state,
    expire_pending_requests_for_slot,
    refresh_runtime_views,
    select_leader_for_slot,
    select_pending_requests_for_block,
    skip_slot,
    submit_transaction_request,
    validator_is_schedulable_for_epoch,
    verify_block_parent_link,
)
from .protocol import materialize_transaction
from .utils import stable_hash


def normalized_transaction_for_verification(
    transaction_record: dict[str, Any],
) -> dict[str, Any]:
    """Return a transaction record with runtime-only fields removed for deterministic comparison."""
    normalized = deepcopy(transaction_record)
    normalized["included_at_ms"] = None
    normalized["block_id"] = None
    normalized["block_hash"] = None
    return normalized


def block_hash_payload(block: dict[str, Any]) -> dict[str, Any]:
    """
    Rebuild the exact payload that `create_block()` hashes before block id/hash backfills.

    `create_block()` computes the block hash while transaction records still have `block_id=None`
    and `block_hash=None`, then fills those references in afterward.
    """
    transactions = []
    for transaction_record in block["transactions"]:
        transaction_payload = deepcopy(transaction_record)
        transaction_payload["block_id"] = None
        transaction_payload["block_hash"] = None
        transactions.append(transaction_payload)

    return {
        "block_id": block["block_id"],
        "slot": block["slot"],
        "leader_id": block["leader_id"],
        "created_at_ms": block["created_at_ms"],
        "parent_block_hash": block["parent_block_hash"],
        "transaction_count": block["transaction_count"],
        "confirmed_transaction_count": block["confirmed_transaction_count"],
        "rejected_transaction_count": block["rejected_transaction_count"],
        "total_fees_lamports": block["total_fees_lamports"],
        "transactions": transactions,
    }


def verify_skipped_slot(
    blockchain_state: dict[str, Any],
    slot_record: dict[str, Any],
) -> dict[str, Any]:
    """Verify one skipped-slot record against the replay state's current slot and leader schedule."""
    errors: list[str] = []
    slot = slot_record["slot"]
    if slot != blockchain_state["next_slot"]:
        errors.append("skipped slot does not match the replay state's next slot")

    expired_requests = expire_pending_requests_for_slot(blockchain_state, slot)
    scheduled_leader_id = None
    if blockchain_state["validators"]:
        try:
            scheduled_leader_id = select_leader_for_slot(blockchain_state, slot)
        except ValueError as exc:
            errors.append(f"leader schedule could not be built for skipped slot: {exc}")
        else:
            if slot_record.get("scheduled_leader_id") != scheduled_leader_id:
                errors.append("skipped slot scheduled_leader_id does not match the leader schedule")

    if slot_record.get("reason") != "leader_missed_slot":
        errors.append("skipped slot reason is not supported by the current verifier")
    if slot_record.get("expired_request_count") != len(expired_requests):
        errors.append("skipped slot expired_request_count does not match replayed expiry count")
    if slot_record.get("pending_request_count_after_skip") != len(blockchain_state["pending_requests"]):
        errors.append("skipped slot pending_request_count_after_skip does not match replayed queue size")
    expected_time_ms = slot * blockchain_state["epoch_schedule"]["target_slot_duration_ms"]
    if slot_record.get("skipped_at_simulated_time_ms") != expected_time_ms:
        errors.append("skipped slot simulated time does not match the slot timing model")

    expected_leader_id = scheduled_leader_id if blockchain_state["validators"] else None
    if slot_record.get("leader_id") != expected_leader_id:
        errors.append("skipped slot leader_id does not match the skipped leader for that slot")

    return {
        "ok": not errors,
        "slot": slot,
        "leader_id": slot_record.get("leader_id"),
        "scheduled_leader_id": scheduled_leader_id,
        "error_count": len(errors),
        "errors": errors,
    }


def verify_block(
    blockchain_state: dict[str, Any],
    block: dict[str, Any],
) -> dict[str, Any]:
    """
    Verify one block against the current pre-block chain state.

    This checks both structure and replay semantics:
    - parent link and slot continuity
    - stake-scheduled leader consistency
    - transaction counts, fee totals, and block hash
    - deterministic re-materialization of each transaction from its archived request
    - sequential state-transition results inside the block
    """
    errors: list[str] = []
    expired_requests = expire_pending_requests_for_slot(blockchain_state, block["slot"])
    expected_selected_requests, expected_packing_stats = select_pending_requests_for_block(
        blockchain_state,
        max_transactions=block.get("max_transactions_limit"),
    )
    expected_selected_request_ids = [
        request_tx["request_id"] for request_tx in expected_selected_requests
    ]

    if not verify_block_parent_link(blockchain_state, block):
        errors.append("block does not extend the current chain head")

    if block["transaction_count"] != len(block["transactions"]):
        errors.append("block transaction_count does not match transactions length")
    if block["confirmed_transaction_count"] != sum(
        transaction["status"] == "confirmed" for transaction in block["transactions"]
    ):
        errors.append("block confirmed_transaction_count is inconsistent")
    if block["rejected_transaction_count"] != sum(
        transaction["status"] == "rejected" for transaction in block["transactions"]
    ):
        errors.append("block rejected_transaction_count is inconsistent")
    if block["total_fees_lamports"] != sum(
        transaction["meta"].get("fee_charged_lamports", transaction["meta"]["fee_lamports"])
        for transaction in block["transactions"]
    ):
        errors.append("block total_fees_lamports is inconsistent")

    expected_included_request_ids = [transaction["request_id"] for transaction in block["transactions"]]
    if block.get("included_request_ids", expected_included_request_ids) != expected_included_request_ids:
        errors.append("block included_request_ids do not match transaction request ids")
    if expected_included_request_ids != expected_selected_request_ids:
        errors.append("block included requests do not match fee-priority packing for the slot")
    if block.get("expired_request_count", 0) != len(expired_requests):
        errors.append("block expired_request_count does not match replayed expiry count")
    if block.get("compute_unit_limit") != blockchain_state["block_limits"]["max_compute_units"]:
        errors.append("block compute_unit_limit does not match the chain's configured limit")
    if block.get("compute_units_consumed") != expected_packing_stats["compute_units_consumed"]:
        errors.append("block compute_units_consumed does not match replayed request packing")
    expected_compute_units_remaining = max(
        blockchain_state["block_limits"]["max_compute_units"] - expected_packing_stats["compute_units_consumed"],
        0,
    )
    if block.get("compute_units_remaining") != expected_compute_units_remaining:
        errors.append("block compute_units_remaining does not match replayed request packing")
    if block.get("packet_bytes_limit") != blockchain_state["block_limits"]["max_packet_bytes"]:
        errors.append("block packet_bytes_limit does not match the chain's configured limit")
    if block.get("packet_bytes_consumed") != expected_packing_stats["packet_bytes_consumed"]:
        errors.append("block packet_bytes_consumed does not match replayed request packing")
    expected_packet_bytes_remaining = max(
        blockchain_state["block_limits"]["max_packet_bytes"] - expected_packing_stats["packet_bytes_consumed"],
        0,
    )
    if block.get("packet_bytes_remaining") != expected_packet_bytes_remaining:
        errors.append("block packet_bytes_remaining does not match replayed request packing")
    if block.get("account_lock_limit") != blockchain_state["block_limits"]["max_account_locks"]:
        errors.append("block account_lock_limit does not match the chain's configured limit")
    if block.get("account_lock_count") != expected_packing_stats["account_lock_count"]:
        errors.append("block account_lock_count does not match replayed request packing")
    if block.get("writable_account_lock_limit") != blockchain_state["block_limits"]["max_writable_account_locks"]:
        errors.append("block writable_account_lock_limit does not match the chain's configured limit")
    if block.get("writable_account_lock_count") != expected_packing_stats["writable_account_lock_count"]:
        errors.append("block writable_account_lock_count does not match replayed request packing")

    expected_block_hash = stable_hash(block_hash_payload(block))
    if block["block_hash"] != expected_block_hash:
        errors.append("block_hash does not match the block contents")

    scheduled_leader_id = None
    if blockchain_state["validators"]:
        try:
            scheduled_leader_id = select_leader_for_slot(blockchain_state, block["slot"])
        except ValueError as exc:
            errors.append(f"leader schedule could not be built: {exc}")
        else:
            if block.get("scheduled_leader_id") != scheduled_leader_id:
                errors.append("scheduled_leader_id does not match the leader schedule")
            expected_schedule_match = block["leader_id"] == scheduled_leader_id
            if block.get("leader_schedule_match") != expected_schedule_match:
                errors.append("leader_schedule_match is inconsistent with the scheduled leader")
            leader = blockchain_state["validators"].get(block["leader_id"])
            if leader is None:
                errors.append("block leader_id is not a registered validator")
            else:
                epoch = (block["slot"] - 1) // blockchain_state["epoch_schedule"]["slots_per_epoch"]
                if not validator_is_schedulable_for_epoch(leader, epoch):
                    errors.append("block leader is not schedulable for the block epoch")

    pending_requests_by_id = {
        request_tx["request_id"]: request_tx for request_tx in blockchain_state["pending_requests"]
    }
    preview_state = deepcopy(blockchain_state)
    expected_transactions = []
    for transaction_record in block["transactions"]:
        if transaction_record["block_id"] != block["block_id"]:
            errors.append(f"transaction {transaction_record['request_id']} block_id mismatch")
        if transaction_record["block_hash"] != block["block_hash"]:
            errors.append(f"transaction {transaction_record['request_id']} block_hash mismatch")

        request_tx = pending_requests_by_id.get(transaction_record["request_id"])
        if request_tx is None:
            errors.append(f"missing pending request for transaction {transaction_record['request_id']}")
            continue

        expected_transaction = materialize_transaction(
            request_tx,
            validator_id=block["leader_id"],
            slot=block["slot"],
        )
        apply_transaction_to_state(preview_state, request_tx, expected_transaction)
        expected_transactions.append(expected_transaction)

        if normalized_transaction_for_verification(expected_transaction) != normalized_transaction_for_verification(
            transaction_record
        ):
            errors.append(
                f"transaction replay mismatch for request {transaction_record['request_id']}"
            )

    if len(expected_transactions) != len(block["transactions"]):
        errors.append("could not replay every transaction in the block")

    return {
        "ok": not errors,
        "slot": block["slot"],
        "leader_id": block["leader_id"],
        "scheduled_leader_id": scheduled_leader_id,
        "transaction_count": block["transaction_count"],
        "error_count": len(errors),
        "errors": errors,
    }


def build_chain_verification_replay_state(
    blockchain_state: dict[str, Any],
) -> dict[str, Any]:
    """
    Build a fresh replay state from the stored verification base state.

    The replay state uses the current chain's `chain_id` and `genesis_hash` so stake-weighted
    leader selection and parent-link verification match the original run.
    """
    base_state = blockchain_state["verification_base_state"]
    replay_state = build_blockchain_state(
        accounts=base_state["accounts"],
        pools=base_state["pools"],
        markets=base_state["markets"],
        players=base_state["players"],
        validators=base_state["validators"],
    )
    replay_state["chain_id"] = blockchain_state["chain_id"]
    replay_state["genesis_hash"] = blockchain_state["genesis_hash"]
    replay_state["head_block_hash"] = blockchain_state["genesis_hash"]
    replay_state["epoch_schedule"] = deepcopy(blockchain_state["epoch_schedule"])
    replay_state["block_limits"] = deepcopy(blockchain_state["block_limits"])
    replay_state["simulation_config"] = deepcopy(blockchain_state["simulation_config"])
    replay_state["verification_base_state"] = deepcopy(base_state)
    refresh_runtime_views(replay_state)
    return replay_state


def verify_chain(
    blockchain_state: dict[str, Any],
) -> dict[str, Any]:
    """
    Verify the full chain by replaying blocks from the stored verification base state.

    This is stronger than checking parent links alone: it re-submits archived requests at their
    original slot, re-runs block verification, appends each verified block to a replay state, and
    then compares the final replayed accounts, venues, registries, and chain stats to the live
    chain state.
    """
    errors: list[str] = []
    replay_state = build_chain_verification_replay_state(blockchain_state)
    archived_requests = sorted(
        blockchain_state["submitted_request_archive"].values(),
        key=lambda request_tx: (
            request_tx.get("submitted_for_slot", 0),
            request_tx.get("submission_sequence", 0),
        ),
    )
    archived_requests_by_slot: dict[int, list[dict[str, Any]]] = {}
    for request_tx in archived_requests:
        archived_requests_by_slot.setdefault(request_tx["submitted_for_slot"], []).append(request_tx)

    block_reports = []
    skipped_slots_by_slot = {
        slot_record["slot"]: slot_record for slot_record in blockchain_state["skipped_slots"]
    }
    blocks_by_slot = {block["slot"]: block for block in blockchain_state["blocks"]}
    skip_reports = []

    for slot in range(1, blockchain_state["head_slot"] + 1):
        for request_tx in archived_requests_by_slot.get(slot, []):
            submit_transaction_request(replay_state, request_tx)

        if slot in skipped_slots_by_slot:
            slot_record = skipped_slots_by_slot[slot]
            skip_report = verify_skipped_slot(replay_state, slot_record)
            skip_reports.append(skip_report)
            if not skip_report["ok"]:
                errors.extend(
                    f"slot {slot}: {error_message}" for error_message in skip_report["errors"]
                )
                continue

            skip_slot(
                replay_state,
                leader_id=slot_record.get("leader_id"),
                reason=slot_record["reason"],
                expired_request_count=slot_record["expired_request_count"],
            )
            continue

        block = blocks_by_slot.get(slot)
        if block is None:
            errors.append(f"slot {slot}: neither block nor skipped-slot record exists")
            continue

        block_report = verify_block(replay_state, block)
        block_reports.append(block_report)
        if not block_report["ok"]:
            errors.extend(
                f"slot {block['slot']}: {error_message}" for error_message in block_report["errors"]
            )
            continue

        append_block(replay_state, block)

    comparable_keys = [
        "head_block_hash",
        "head_slot",
        "next_slot",
        "simulated_time_ms",
        "current_epoch",
        "epoch_schedule",
        "block_limits",
        "simulation_config",
        "stats",
        "processed_request_ids",
        "expired_request_ids",
        "request_archive",
        "submitted_request_archive",
        "next_request_submission_sequence",
        "skipped_slots",
        "accounts",
        "pools",
        "markets",
        "players",
        "validators",
    ]
    live_state_matches = True
    for key in comparable_keys:
        if replay_state[key] != blockchain_state[key]:
            live_state_matches = False
            errors.append(f"replayed state does not match live state for key: {key}")

    return {
        "ok": not errors,
        "verified_block_count": sum(report["ok"] for report in block_reports),
        "verified_skipped_slot_count": sum(report["ok"] for report in skip_reports),
        "block_count": len(blockchain_state["blocks"]),
        "skipped_slot_count": len(blockchain_state["skipped_slots"]),
        "error_count": len(errors),
        "errors": errors,
        "live_state_matches": live_state_matches,
        "replayed_head_slot": replay_state["head_slot"],
        "replayed_current_epoch": replay_state["current_epoch"],
        "block_reports": block_reports[-10:],
    }
