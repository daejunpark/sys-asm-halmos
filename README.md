# Continuous Formal Verification of Pectra System Contracts with Halmos

👉 _**Check out our [post] for more insights.**_

[post]: https://a16zcrypto.com/posts/article/formal-verification-of-pectra-system-contracts-with-halmos/

#

The [Pectra] hardfork, scheduled to ship in early 2025, introduces several enhancements in user experience and validator operations. Some of these improvements require system contracts that implement on-chain logic. Specifically:

- [EIP-2935] proposes storing the last 8192 block hashes in a system contract to support stateless execution. This contract uses a ring buffer for efficient block hash storage.

- [EIP-7002] introduces a mechanism allowing validators to initiate exits and withdrawals directly via their execution layer withdrawal credentials, with withdrawal requests stored in a dedicated system contract. A queue is used here to manage withdrawal requests.

- [EIP-7251] proposes increasing the max effective balance for validators, allowing larger validators to consolidate operations. These consolidation requests are managed by a separate system contract using a queue.

These system contracts are written entirely in [assembly][geas] for gas efficiency. Although relatively small and manageable, these [assembly implementations][sys-asm] make it no longer trivial to ensure that they fully comply with the functionality specified in the EIP specs. For this reason, rigorous analysis is needed to get a higher confidence in the functional correctness of these system contracts. In fact, it’s the primary focus of [Ethereum Foundation’s RFP for the Pectra system contracts bytecode audit][Pectra audit RFP]. Ensuring the accuracy of these contracts is critical to the security of the Pectra upgrade.

[Pectra]: <https://eips.ethereum.org/EIPS/eip-7600>
[EIP-2935]: <https://eips.ethereum.org/EIPS/eip-2935>
[EIP-7002]: <https://eips.ethereum.org/EIPS/eip-7002>
[EIP-7251]: <https://eips.ethereum.org/EIPS/eip-7251>
[geas]: <https://github.com/fjl/geas>
[sys-asm]: <https://github.com/lightclient/sys-asm>
[Pectra audit RFP]: <https://github.com/ethereum/requests-for-proposals/blob/master/open-rfps/pectra-system-contracts-audit.md>


## Formal Verification using Halmos

We used halmos to formally verify the functional correctness of these contracts. We specifically focused on whether the bytecode aligns with the spec, rather than evaluating the security of the spec itself against potential abuse or malicious use. This separation of concerns allows auditors and the community to review the spec without worrying about low-level bytecode implementation details.

[Halmos], a symbolic execution tool for EVM bytecode, is particularly well-suited for this type of verification task. It allows for symbolically executing the system contracts bytecode to examine all possible behaviors of the bytecode and ensure they conform to the spec. Since the contracts are relatively small and their logic is not complicated, this verification process is quite straightforward and does not require much effort, taking only a couple of days to complete.

In halmos, verification properties are written in Solidity test interfaces, also referred to as "halmos tests." We developed halmos tests that:
- Setup arbitrary symbolic storage for a system contract.
- Call the contract with arbitrary symbolic calldata and a symbolic caller address.
- Assert correctness properties on both the return data and the updated storage values, to confirm compliance with the EIP specs.

Symbolic storage represents any possible contract state resulting from any sequence of transactions since deployment. Similarly, symbolic calldata and a symbolic caller address represent an arbitrary transaction. Verification under these conditions allows us to establish correctness guarantees for the entire lifetime of the contract.

**Note on Completeness:** Halmos performs _bounded_ symbolic execution, meaning that loops are executed only up to a specified number of iterations, and calldata sizes are constrained by set constants. Therefore, it is essential to provide sufficiently large loop bounds and a comprehensive range of calldata sizes to cover all unique execution paths. Provided that the contract does not contain paths that depend on calldata sizes beyond those considered, these halmos tests should achieve sufficient completeness in verification.

[Halmos]: <https://github.com/a16z/halmos>


## Verification Properties

### EIP-2935: Ring Buffer for Storing Block Hashes

The EIP-2935 system contract stores a ring buffer of size 8192, occupying storage slots 0 through 8191, with all other slots remaining empty.

In a block at height `8192*k + i` (for some `k` and `i`), the ring buffer stores the last 8192 block hashes. Specifically, block hashes from heights `8192*(k-1) + i` through `8192*(k-1) + 8191`, followed by `8192*k` through `8192*k + (i-1)`, are stored in slots `i` through `8191`, and then wrap around to slots 0 through `i-1`. Note that the hash of the current block is not available at this point.

The system contract provides two operations: `get()` and `set()`.

- The `get(x)` operation reads storage at slot `x % 8192` if `x` is within the valid range `[8192*(k-1) + i, 8192*k + i-1]` (inclusive); otherwise, it reverts.

- The `set(x)` operation updates storage slot `i-1` with the given value `x`, where `x` must be `blockhash(8192*k + i-1)`. The set() operation is restricted to be called by only the system address and is expected to be executed at the beginning of block processing.

```
     Slot    Data                                        New data after `set` operation

       0     blockhash(8192* k    +  0   )               <unchanged>
       1     blockhash(8192* k    +  1   )               <unchanged>
      ...    ...                                         ...
      i-2    blockhash(8192* k    + i-2  )               <unchanged>
      i-1    blockhash(8192*(k-1) + i-1  )   == set ==>  blockhash(8192*k + i-1)
       i     blockhash(8192*(k-1) +  i   )               <unchanged>
      ...    ...                                         ...
     8190    blockhash(8192*(k-1) + 8190 )               <unchanged>
     8191    blockhash(8192*(k-1) + 8191 )               <unchanged>
     8192    0                                           <unchanged>
      ...    ...                                         ...
  2^256-1    0                                           <unchanged>
```

#### Halmos Test Properties:

We created [halmos tests](test/EIP2935.t.sol) to confirm the correct behavior of both operations.

For the get() operation, halmos tests verify that it:
- Checks for valid input range, reverting if not valid.
- Retrieves data from the ring buffer at the specified index if the input is valid.
- Leaves the storage unaltered after execution.

```solidity
  // get() operation
  if (caller != SYSTEM_ADDRESS) {
      if (data.length == 32) {
          uint input = uint(bytes32(data));
          // valid input range: [block.number - HISTORY_SERVE_WINDOW, block.number - 1] (inclusive)
          if (input <= block.number - 1 && block.number - input <= HISTORY_SERVE_WINDOW) {
              assertTrue(success);
              assertEq(bytes32(retdata), vm.load(HISTORY_STORAGE_ADDRESS, bytes32(input % HISTORY_SERVE_WINDOW)));
          } else {
              // ensure revert for any input outside the valid range
              assertFalse(success);
          }
      } else {
          // ensure revert if calldata length is not 32 bytes
          assertFalse(success);
      }

      // ensure no storage updates
      assertEq(newState.anySlotValue, initState.anySlotValue);
```

For the set() operation, halmos tests verify that it:
- Updates the correct storage slot while keeping all other slots unchanged.
- Never revert under any circumstances.

```solidity
  // set() operation
  } else {
      // ensure set() operation never reverts
      assertTrue(success);

      // ensure the storage value at `block.number-1 % HISTORY_SERVE_WINDOW` is set to calldata[0:32]
      bytes32 input = bytes32(data); // implicit zero-padding if data.length < 32
      assertEq(input, vm.load(HISTORY_STORAGE_ADDRESS, bytes32((block.number - 1) % HISTORY_SERVE_WINDOW)));

      // ensure no storage updates other than the set slot
      if (anySlot != (block.number - 1) % HISTORY_SERVE_WINDOW) {
          assertEq(newState.anySlotValue, initState.anySlotValue);
      }
  }
```

#### Completeness:

The properties mentioned above have been verified under the following conditions:

- Contract state:
  - Arbitrary storage values, potentially including garbage values.
  - Arbitrary contract balance, up to `2**96` wei (over 70 billion ether).

- Block configuration:
  - Arbitrary block number greater than 0.
  - Arbitrary values for block timestamp, base fee, miner’s address, randomness beacon, and chain id.

- Transaction:
  - Arbitrary caller address with balance up to `2**96` wei.
  - Arbitrary callvalue.
  - Arbitrary calldata with specific sizes of 0, 1, 2, 31, 32, 33, and 1024.

The genesis block (`block.number == 0`) is excluded from verification, as its behavior is not fully specified in the current EIP spec. Since the genesis block has already been processed in the Ethereum chain, omitting this edge case does not compromise the completeness of verification. Additionally, the upper limit on balances does not impact completeness, as `2**96` wei (more than 70 billion ether) far exceeds the current total Ether supply.

The selected calldata sizes were chosen based on branching conditions in the code related to `data.length == 32`. Provided that no additional code paths depend on calldata sizes not considered, (as confirmed by manual inspection of the bytecode implementation), this bounded verification ensures a sufficient correctness guarantee.

The full halmos tests for EIP-2935 can be found [here](test/EIP2935.t.sol).


### EIP-7002: Withdrawal Requests Queue

The EIP-7002 system contract maintains a queue for withdrawal requests in the storage, where each queue element occupies 76 bytes, spread across three storage slots. Each element aligns with storage slot boundaries and is not packed.

When an element is removed, the head pointer of the queue advances, but the storage slots of removed elements are not cleared. Both head and tail pointers keep advancing until the queue is emptied, at which point both reset to index 0, without clearing any storage slots.

The contract’s storage layout is as follows. Note that removed queue elements may leave behind “garbage” values, as their storage slots remain uncleared:

```
  Slot                  Data

  0                     excess requests (from previous blocks)
  1                     request count (for the current block)
  2                     queue head index h
  3                     queue tail index t
  ...                   (garbage values for removed elements)
  4 + 3* h              queue element h   (1/3)
  4 + 3* h    + 1       queue element h   (2/3)
  4 + 3* h    + 2       queue element h   (3/3)
  4 + 3*(h+1)           queue element h+1 (1/3)
  4 + 3*(h+1) + 1       queue element h+1 (2/3)
  4 + 3*(h+1) + 2       queue element h+1 (3/3)
  ...                   ...
  4 + 3*(t-1)           queue element t-1 (1/3)
  4 + 3*(t-1) + 1       queue element t-1 (2/3)
  4 + 3*(t-1) + 2       queue element t-1 (3/3)
  4 + 3* t              (potentially garbage values)
  ...                   (potentially garbage values)
```

The system contract provides two main operations:

- User operation: Adds a withdrawal request to the queue and charges a fee. The fee is dynamically calculated based on the queue size, increasing exponentially as the queue grows. The user operation verifies that the provided funds cover the fee, with no refunds given for excess funds.

- System operation: Removes (and returns) as many queued requests as possible, up to a set limit (currently 16).

The fee calculation employs an approximation of `e^x`, called `fake_exponential()`, which is based on an iterative method, and has been used in other EIPs such as [EIP-4844 Proto-Danksharding][EIP-4844].

[EIP-4844]: <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-4844.md>


#### Halmos Test Properties:

We developed [halmos tests](test/EIP7002.t.sol) to verify the correct behavior of both operations.

For the user operation, halmos tests ensure that it:
- Inserts a new element into the queue with accurate encoding and zero-padding as required.
- Moves the tail pointer to the next index of the queue, and increments the internal counter.
- Checks that the fund is sufficient for the fee, reverting only if it’s not.
- Doesn’t alter the other existing queue elements.

```solidity
  // add_withdrawal_request() operation
  } else if (data.length == INPUT_SIZE) {
      if (success) {
          // ensure count has increased
          assertEq(newState.count, initState.count + 1);

          // ensure new queue element
          assertEq(newState.queueTailIndex, initState.queueTailIndex + 1);
          uint256 queueTailSlot = WITHDRAWAL_REQUEST_QUEUE_STORAGE_OFFSET + initState.queueTailIndex * SLOTS_PER_ITEM;
          bytes memory queueItem = _getQueueItem(queueTailSlot);
          assertEq(queueItem, bytes.concat(bytes32(uint256(uint160(caller))), data, bytes8(0)));
          // ensure no dirty bits for source address, and zero padding at the end
          assertEq(bytes12(this.slice(queueItem, 0, 12)), bytes12(0));
          assertEq(bytes8(this.slice(queueItem, 88, 96)), bytes8(0));

          // ensure sufficient fee
          assertGe(value, _getFee());

          // ensure no storage updates other than count, queue tail index, or the new queue item
          if (
              anySlot != WITHDRAWAL_REQUEST_COUNT_STORAGE_SLOT &&                     // count
              anySlot != WITHDRAWAL_REQUEST_QUEUE_TAIL_STORAGE_SLOT &&                // queue tail index
              (anySlot < queueTailSlot || anySlot >= queueTailSlot + SLOTS_PER_ITEM)  // new queue item
          ) {
              // NOTE: excess is not updated // TODO: figure out why
              assertEq(newState.anySlotValue, initState.anySlotValue);
          }

          // ensure empty return data
          assertEq(retdata.length, 0);
      } else {
          // NOTE: the contract immediately reverts when excess == EXCESS_INHIBITOR
          if (initState.excess != EXCESS_INHIBITOR) {
              // ensure that the failure is only due to insufficient fee
              assertLt(value, _getFee());
          }
      }
```

For the system operation, halmos tests ensure that it:
- Removes the correct number of elements from the queue, updating the head and tail pointers.
- Returns the removed elements with accurate encoding, especially the amount field in big-endian format.
- Updates correctly the excess value, and resets the internal counter.
- Doesn’t alter any remaining queue elements.
- Never revert under any circumstances.

```solidity
  assertTrue(success);

  // ensure excess update
  if (initState.excess != EXCESS_INHIBITOR) {
      assertEq(newState.excess, subcap(initState.excess + initState.count, TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK));
  } else {
      // at the fork block
      assertEq(newState.excess, subcap(                   initState.count, TARGET_WITHDRAWAL_REQUESTS_PER_BLOCK));
  }

  // ensure count reset
  assertEq(newState.count, 0);

  uint256 oldQueueSize = sub(initState.queueTailIndex, initState.queueHeadIndex);
  uint256 newQueueSize = sub(newState.queueTailIndex, newState.queueHeadIndex);
  uint256 numDequeued = sub(oldQueueSize, newQueueSize);

  // ensure queue pointer updates
  if (oldQueueSize <= MAX_WITHDRAWAL_REQUESTS_PER_BLOCK) {
      assertEq(newState.queueHeadIndex, 0);
      assertEq(newState.queueTailIndex, 0);
  } else {
      assertEq(newState.queueTailIndex, initState.queueTailIndex);
  }

  // ensure max withdrawals per block
  assertLe(numDequeued, MAX_WITHDRAWAL_REQUESTS_PER_BLOCK);

  // ensure retdata size
  assertEq(retdata.length, RECORD_SIZE * numDequeued);

  // check retdata
  for (uint256 i = 0; i < numDequeued; i++) {
      // TODO: to avoid slowdown as iteration progresses. use push/pop feature once available.
      if (svm.createBool("check-retdata")) {
          uint256 queueCurrSlot = WITHDRAWAL_REQUEST_QUEUE_STORAGE_OFFSET + (initState.queueHeadIndex + i) * SLOTS_PER_ITEM;
          bytes memory queueCurrItem = _getQueueItem(queueCurrSlot);

          uint256 retOffset = RECORD_SIZE * i;
          // check source address
          assertEq(_getSource(queueCurrItem), address(uint160(bytes20(this.slice(retdata, retOffset + 0, retOffset + 20)))));

          // check validator pubkey
          assertEq(_getPubkey(queueCurrItem), this.slice(retdata, retOffset + 20, retOffset + 68));

          // ensure big-endian amount
          assertEq(_getAmountBE(queueCurrItem), bytes8(this.slice(retdata, retOffset + 68, retOffset + RECORD_SIZE)));

          // NOTE: the else branch will continue with further iterations
          return;
      }
  }

  // ensure no storage update other than excess, count, and queue head/tail indexes
  // NOTE: "removed" queue elements are not reset to zero in storage, so they remain unchanged
  if (anySlot >= WITHDRAWAL_REQUEST_QUEUE_STORAGE_OFFSET) {
      assertEq(newState.anySlotValue, initState.anySlotValue);
  }
```

For the approximated exponentiation function, `fake_exponential()`, halmos tests ensure its consistency with the pseudocode provided in the EIP spec. For these tests, we translated the Python pseudocode into Solidity with minimal syntax adjustments, using it as a reference for comparison. Note that, however, verifying the correctness of the iterative method itself (such as convergence guarantees or approximation error bounds) is beyond the scope of this verification. As mentioned earlier, our objective here is to verify the conformance with the EIP spec, rather than the analysis of EIP spec itself.

```solidity
  // pseudocode from https://eips.ethereum.org/EIPS/eip-7002
  // NOTE: the purpose of this is to ensure that the geas implementation matches the pseudocode math, rather than verifying the math itself
  function _fake_exponential(uint256 factor, uint256 numerator, uint256 denominator) internal pure returns (uint256) {
      unchecked {
          uint256 i = 1;
          uint256 output = 0;
          uint256 numerator_accum = factor * denominator;
          while (numerator_accum > 0) {
              output += numerator_accum;
              numerator_accum = (numerator_accum * numerator) / (denominator * i);
              i += 1;
          }
          return output / denominator;
      }
  }
```

For contract invariants, halmos tests verify that the following invariant holds indefinitely through inductive proof:
- The head index is always less than or equal to the tail index.

This invariant, once verified independently, is used for verifying other properties.

```solidity
    function setUp() public {
        ...
        // assume the contract invariants before executing any transaction
        vm.assume(initState.queueHeadIndex <= initState.queueTailIndex);
    }

    function check_invariant(address caller, uint256 value, bytes memory data) public {
        ...

        // call the contract and capture the new contract state
        (, , State memory newState) = _callContract(caller, value, data);

        // ensure the contract invariants still hold after the transaction
        assertLe(newState.queueHeadIndex, newState.queueTailIndex);
    }
```


#### Completeness:

The properties mentioned above have been verified under the following conditions:

- Contract state:
  - Arbitrary storage values, potentially including garbage values, with these additional constraints:
    - The request counter (at slot 1) is less than `2**64`.
    - The tail index (at slot 3) is less than `2**64`.
  - Arbitrary contract balance, up to `2**96` wei (over 70 billion ether).

- Block configuration:
  - Arbitrary values for block number, timestamp, base fee, miner’s address, randomness beacon, and chain id.

- Transaction:
  - Arbitrary caller address with balance up to `2**96` wei.
  - Arbitrary callvalue.
  - Arbitrary calldata with specific sizes of 0, 1, 2, 32, 56, 64, and 1024.
  - Bounded loop iterations up to 16.

The upper bound on the request counter and tail index is used to prevent counterexamples involving arithmetic overflow when these values are incremented. Although overflow is theoretically possible, it is practically infeasible due to the excessive number of requests required. Consequently, the bytecode implementation does not include overflow protection, based on the assumption that this scenario is unrealistic. While not explicitly mentioned in the EIP spec, excluding overflow behavior is reasonable based on this implicit practical assumption.

The main loop in `fake_exponential()` is unbounded, but current halmos tests verify only up to 16 iterations in bounded symbolic execution, resulting in a weaker correctness guarantee. However, given that the loop body is simple and lacks branching, we believe that additional iterations are unlikely to introduce new behaviors, allowing this bounded verification to provide a reasonably high level of confidence.

Similar to the EIP-2935 tests, the selected calldata sizes were chosen based on branching conditions in the code related to `data.length == 56`. Provided that no additional code paths depend on calldata sizes not considered, (as confirmed by manual inspection of the bytecode implementation), this bounded verification ensures a sufficient correctness guarantee. Additionally, the upper limit on balances does not impact completeness, as `2**96` wei (more than 70 billion ether) far exceeds the current total Ether supply.

The full halmos tests for EIP-7002 can be found [here](test/EIP7002.t.sol).


### EIP-7251: Consolidation Requests Queue

The EIP-7251 system contract closely mirrors the EIP-7002 contract, except that the queue stores consolidation requests instead of withdrawal requests. Other than that, the two contracts employ the same logic for queue operations, including the storage structure, pointer management, and method of processing requests.


#### Halmos Test Properties:

For the verification of the EIP-7251 contract, we leveraged the existing properties developed for the EIP-7002 system contract. Adjustments were made to account for the differences in queue element size and encoding specific to consolidation requests. These properties inherit the same level of verification completeness.

The full halmos tests for EIP-7251 can be found [here](test/EIP7251.t.sol).


## Findings from Verification Process

The halmos tests revealed an [subtle off-by-one discrepancy] in the EIP-2935 system contract implementation. Specifically, when `get()` is called with an input of `block.number - HISTORY_SERVE_WINDOW - 1`, which falls outside the valid range, the expected behavior is for it to revert. However, in the current implementation, it returns the blockhash of `block.number - 1` instead of reverting. This issue went unnoticed in previous tests, where the expected values in assertions didn't fully align with the specification. This finding highlights the complementary value of formal verification, which offers a unique perspective for examining the target contract beyond what traditional testing or fuzzing provides.

[subtle off-by-one discrepancy]: <https://github.com/lightclient/sys-asm/issues/34>


## Conclusion

The functional correctness of the new system contracts introduced in EIPs 2935, 7002, and 7251, for the Pectra hardfork, has been formally verified. Focusing on bytecode compliance to specification, the verification process with halmos proved both straightforward and efficient, taking only a few days. Given the critical role of system contracts, this approach shows potential for efficiently verifying similar contracts in future hardforks, offering an additional layer of confidence with minimal effort.
