# Solana Market Simulator

I built this project to understand what happens when a blockchain market is treated as a system that can be stressed, measured and challenged, instead of as a black box. The goal is not only to simulate transactions, but to study how validators, traders, liquidity providers and other actors behave when there is congestion, changing liquidity, participant failure or a market shock.

What I find most interesting about the project is the risk side of it. I wanted a way to explore questions such as: what gets included and what gets left in the queue, how capacity limits shape outcomes, what happens when a validator misses slots, how different types of players react to price dislocations, and how a network behaves when it is exposed to unusual or adversarial conditions. That is why the project is designed as a full market and network simulation rather than only a pricing model.

At its current stage, the simulator already combines market behaviour, network behaviour and replay verification. It is meant to be a practical environment for thinking about operational risk, market risk, congestion, incentives and resilience.

## What the simulator already does

- Builds a persistent blockchain state with accounts, pools, markets, players, validators, pending requests, blocks and skipped slots
- Supports both liquidity pool activity and market style trading
- Models different player types such as market makers, liquidity providers, retail users, arbitrageurs, routers and rebalancers
- Uses state driven player policies instead of fixed scripted actions
- Compiles player intent into Solana-like transaction requests
- Produces blocks over many slots and epochs instead of only one isolated block
- Uses a simplified stake weighted leader schedule for validators
- Models validator registration, deregistration and delayed exit
- Applies slot pressure logically through compute budgets, packet size limits, account lock limits and request expiry
- Distinguishes between empty blocks and skipped slots
- Replays the chain from archived requests and checks whether the resulting state matches the live chain state

## Why I think this project is interesting

For me, the value of this project is that it forces a structured way of thinking about uncertainty and system behaviour. A market can look stable until traffic increases, incentives change or one participant starts acting differently. By making the system explicit, I can test what happens when assumptions break.

That is why this repository is not only about blockchain mechanics. It is also about scenario analysis. It gives me a place to introduce stress, change participant behaviour, inspect bottlenecks, verify outcomes and reason about where controls or safeguards matter. I see it as a way to practice analytical thinking in a setting where market dynamics, process discipline and technical design all matter at the same time.

## How the program works today

The current program follows a simple chain of events. Players observe the current state and generate intent. Those intents are compiled into transaction requests. Requests enter a pending queue. A scheduled validator selects which requests fit into the slot. A block is produced or the slot is skipped. State changes are applied. At the end, the chain can be replayed and checked.

The files are organised around that flow.

- main.py is the thin entry point that starts the demo run
- solana_market_simulator/app.py assembles the sample world, runs the simulation and prints the summaries
- solana_market_simulator/constants.py contains the shared simulator and protocol constants
- solana_market_simulator/utils.py contains generic helpers such as hashing, ids, JSON formatting and small encoding helpers
- solana_market_simulator/protocol.py contains the low level Solana-like primitives: accounts, instructions, transaction requests, compilation, sizing and block assembly
- solana_market_simulator/domain.py defines the higher level objects such as pools, markets, players, validators and player intent, and it compiles intent into transaction requests
- solana_market_simulator/policies.py contains the state driven logic for each player type and the functions that generate fresh requests for the next slot
- solana_market_simulator/chain_state.py contains the live blockchain state and the functions that mutate it, including registration, leader scheduling, block production, execution and summaries
- solana_market_simulator/simulation.py runs the chain forward over many slots and epochs
- solana_market_simulator/verification.py replays the chain and checks whether the reconstructed state matches the real state
- solana_market_simulator/samples.py contains the sample accounts, players, validators, markets, pools and demo helper flows used to bootstrap the simulation

Some key functions in the current architecture are:

- build_blockchain_state, which creates the persistent simulation state
- register_player and register_validator, which add participants to the live system
- generate_player_intents and generate_slot_transaction_requests, which turn current conditions into new activity
- produce_block and append_block, which move pending requests into the chain and apply their effects
- run_simulation, which advances the blockchain over many slots and epochs
- verify_chain, which replays the archived requests and checks whether the final state is internally consistent

The current design is intentionally deterministic where possible. That makes the simulator easier to inspect, compare and verify. If something unexpected happens, I want to be able to replay it and understand why.

## What I want to add next

- Node level simulation, including separate node views, chain conflicts and consensus between nodes
- A richer proof of stake model with explicit stake accounts instead of only validator level stake summaries
- Proof of history style timing and ordering logic
- Scenario testing for shocks, attacks, congestion events and liquidity stress
- More statistics and reporting to analyse throughput, queue pressure, transaction composition and abnormal patterns
- Network aware player behaviour, for example bots reacting to queue depth, skipped slots or recent validator misses
- State driven validator behaviour, for example maintenance, changing reliability or profitability based exit decisions
- Better scheduling realism, including per account contention and more detailed parallel execution constraints
- Visual reporting so the behaviour of the system is easier to inspect over time

## Current focus

Right now the project is already useful as a small but complete simulation environment. It has a persistent chain, participant behaviour, slot level capacity constraints and replay verification. The next step is to make the environment richer under stress: more scenarios, more network realism and better measurement of what happens when assumptions fail.
