# solana-market-simulator
Simulate solana blockchain through players -> intent -> requests -> validation -> blocks

This is a project to learn what it takes to be a blockchain network and to evaluate what types of behaviour changes what in the market.

Aims/todos:
- ~~create players (players, accounts, markets, intents partially done?)~~
- ~~create chain that stores subsequent blocks~~
- create proof of stake algorithm
- create proof of history algorithm (maybe this is the same as verifying the chain is valid)
- ~~create a way to add new transactions to the chain (partially done?)~~
- ~~create a way to verify the chain is valid~~
- create a way to resolve conflicts between chains
- create a way to register nodes in the network
- create a way to reach consensus between nodes
- ~~build a persistent simulation state / blockchain state for PoS, PoH, consensus to act on~~
- replace fixed sample generators with state-driven ones so they react to pool prices, inventory, spreads, and validator conditions instead of emitting hard-coded intents (intent generators and slot scheduling exist; state-driven behavior is still open)
- ~~create liquidity pools and a way to swap between them (done?)~~
- create a random transaction request loop to test the blockchain
- create transaction data using benford's law to simulate real-world transactions
- create statistics such as total number of transactions, total value of transactions, average transaction value, etc. to analyze the blockchain data and see if it follows expected patterns.
- create a way to visualize the blockchain data, such as a graph or dashboard, to make it easier to understand and analyze the data.
- create a way to simulate different scenarios, such as a sudden increase in transactions, a network attack, or a change in the proof of stake algorithm, to see how the blockchain would react and adapt to these changes.
- implement the stateless architecture of solana, where each node only needs to store a small portion of the blockchain data and can quickly verify transactions without needing to download the entire chain.
- implement the schedular cost model of solana, where the cost of executing a transaction is based on the computational resources it requires, rather than a fixed fee. This can help to prevent spam and ensure that the network is used efficiently. it is equal to the signature cost + write lock cost + data bytes cost + programs execution cost + loaded accounts data size cost, not included is the runtime compute unit metering, which is a separate mechanism that limits the total amount of computational resources that can be used in a single transaction.
- add per-account contention and lane-style scheduling so conflicting transactions block each other while independent ones can run in parallel more like Solana's banking stage.
- create statistics such as the distribution of transaction values, the distribution of transaction fees, the distribution of transaction types, etc. to analyze the blockchain data and see if it follows expected patterns and to identify any anomalies or outliers in the data.
- create statistics such as total security budget, total security budget spent, average security budget per transaction, etc. to analyze the security of the blockchain and see if it is being used effectively to protect the network from attacks and malicious actors.
- create a ui dashboard for everything.
- optionally create players using smart contracts that can be executed on the blockchain to automate certain processes and create new functionalities. This can include things like decentralized finance (DeFi) applications, non-fungible tokens (NFTs), and other types of decentralized applications (dApps).
- think of when a player or validator would register and when he would become inactive or deregister (status lifecycle and examples exist; dynamic entry/exit rules are still open)

Already done and worth keeping visible:
- ~~add runtime registration and deregistration for players and validators~~
- ~~add a simplified stake-weighted leader schedule with delayed validator exit~~
- ~~run the chain over many slots and epochs~~
- ~~model Solana-like time pressure logically with slot budgets, fee-priority packing, and request expiry instead of making the simulator sleep in real time~~
- ~~add optional realistic Solana timing mode and distinguish empty blocks from skipped slots~~
- ~~add a block packet-bytes budget and separate banking-stage-style lock limits on slot packing~~
