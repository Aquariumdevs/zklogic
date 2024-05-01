import { fieldArray, Wallet, transitionProgram, MyPublicOutputs, hashInputs, MerkleWitness4 } from './transition.js';
import { Field, Gadgets, MerkleMap, MerkleMapWitness, verify, Poseidon, VerificationKey, MerkleTree } from 'o1js';

// Helper function to generate a random Field value
function randomField(): Field {
  return new Field(Math.floor(Math.random() * Number.MAX_SAFE_INTEGER));
}

// Function to simulate a Merkle path
function simulateMerklePaths(leaf1: Field, leaf2: Field, depth: number = 128): fieldArray {
  let path = [leaf1];
  const right = leaf2;

    for (let i = 0; i < 128; i += 2) {

      const left = path[i];
      let right = Field("60"); // Simulating a paired node
      if(i == 0) {
        right = leaf2;
      }
      path.push(right);
      const hash = Poseidon.hash([left, right]);
      path.push(hash);
    }
 
  // The last hash is the root
  return new fieldArray({ array: path });
}

function simulateMerklePath(leaf: Field, depth: number = 128): fieldArray {
  let path = [leaf];
  //let currentLevel = [leaf];

  //while (currentLevel.length > 1) {
    //let nextLevel = [];
    for (let i = 0; i < 128; i += 2) {

      const left = path[i];
      const right = new Field("60");  // Simulating a paired node
      path.push(right);
      const hash = Poseidon.hash([left, right]);
      path.push(hash);
    }

  // The last hash is the root
  return new fieldArray({ array: path });
}

// Random initialization tester function
async function testRandomInitialization() {
  // Create a random balance and initial block hash
  const balance = Field(0);
  
  // Initialize the wallet with random balance
  const wallet = new Wallet(balance);
  wallet.balance = Field(0);

  // Assign random values to other necessary fields
  const blsPublicKeyPart1 = randomField();
  const blsPublicKeyPart2 = randomField();

  wallet.pkHash = randomField(); 
  wallet.address = randomField(); 

  const stateHash = Poseidon.hash([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balance, wallet.inTxsRootNew, wallet.outTxsRoot]);
  const messageHash = Poseidon.hash([wallet.address, wallet.pkHash, blsPublicKeyPart1, blsPublicKeyPart2, stateHash]);
  console.log(`message hash: ${messageHash.toString()}`);

  // Prepare Merkle paths
  const msgInclusionPath = simulateMerklePath(messageHash);

  const initialBlockHash = msgInclusionPath.array[msgInclusionPath.array.length - 1];
  wallet.blockHash = initialBlockHash; // Set the initial block hash as the leaf of the Merkle path

  const myPublicOutputs = new MyPublicOutputs({
    Leaf: initialBlockHash, // The initial block hash is the leaf
    Root: msgInclusionPath.array[msgInclusionPath.array.length - 1] // The last element is the root
  });

  // Call the initialize state and prove method
    const result = await wallet.initializeStateAndProve(
      blsPublicKeyPart1,
      blsPublicKeyPart2,
      msgInclusionPath,
      //inclusionPath,
      myPublicOutputs
    );
    //console.log('Initialization test result:', result);

    const isValid = await verify(result.toJSON(), verificationKey);
    console.log('ok', isValid);

    return wallet;
}

async function testDeriveDestination(wallet: Wallet) {
  
  const stateHashPrev = Poseidon.hash([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balanceNew, wallet.inTxsRootNew, wallet.outTxsRoot]);
  
  const pkSaltHash = randomField();
  const messageHash = wallet.deriveDestination( pkSaltHash );

  const inclusionPath = wallet.path;
  const myPublicOutputs = new MyPublicOutputs({
    Leaf: stateHashPrev, // The initial block hash is the leaf
    Root: inclusionPath.array[inclusionPath.array.length - 1] // The last element is the root
  });

  const msgInclusionPath = simulateMerklePaths(messageHash, myPublicOutputs.Root);
  
  wallet.blockHash = msgInclusionPath.array[msgInclusionPath.array.length - 1] // The last element is the root

  // Call the function that wraps the zk-program call
  const result = await wallet.proveStateAfterDestinationDerivation(
    pkSaltHash,
    msgInclusionPath,//prev
    msgInclusionPath,
    myPublicOutputs
  );

  //console.log('Destination derivation proof result:', result);

  const isValid = await verify(result.toJSON(), verificationKey);
  console.log('ok', isValid);
}

async function testBurnToStealth(wallet: Wallet) {
  // Store a snapshot of the current state before making changes

  
  const stateHashPrev = Poseidon.hash([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balanceNew, wallet.inTxsRootNew, wallet.outTxsRoot]);
  
  const amount = Field("10");
  const messageHash = wallet.increaseStealthFunds( amount );

  // Prepare Merkle paths

  const inclusionPath = wallet.path;
  const myPublicOutputs = new MyPublicOutputs({
    Leaf: stateHashPrev, // The initial block hash is the leaf
    Root: inclusionPath.array[inclusionPath.array.length - 1] // The last element is the root
  });

  const msgInclusionPath = simulateMerklePaths(messageHash, myPublicOutputs.Root);
  
  wallet.blockHash = msgInclusionPath.array[msgInclusionPath.array.length - 1] // The last element is the root

  // Call the function that wraps the zk-program call
  const result = await wallet.proveFundsBurning(
    amount,
    msgInclusionPath,//prev
    msgInclusionPath,
    myPublicOutputs
  );

  //console.log('Destination derivation proof result:', result);/**/

  const isValid = await verify(result.toJSON(), verificationKey);
  console.log('ok', isValid);
}

async function testSendTx(wallet: Wallet) {
  // Store a snapshot of the current state before making changes

  
  const stateHashPrev = Poseidon.hash([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balanceNew, wallet.inTxsRootNew, wallet.outTxsRoot]);
  
  const destination = wallet.Destinations[0];
  const amount = Field("5");
  const salt = wallet.destinationsRoot; //this should be changed

  const messageHash = wallet.constructNewTx(destination, amount, salt);

  // Prepare Merkle paths

  const inclusionPath = wallet.path;
  const myPublicOutputs = new MyPublicOutputs({
    Leaf: stateHashPrev, // The initial block hash is the leaf
    Root: inclusionPath.array[inclusionPath.array.length - 1] // The last element is the root
  });

  const msgInclusionPath = simulateMerklePaths(messageHash, myPublicOutputs.Root);
  wallet.blockHash = msgInclusionPath.array[msgInclusionPath.array.length - 1] // The last element is the root

  // Call the function that wraps the zk-program call
  const result = await wallet.proveStateAfterSending(
    salt,
    msgInclusionPath,//prev
    msgInclusionPath,
    myPublicOutputs
  );

  //console.log('State proof (sendtx) result:', result);/**/

  const isValid = await verify(result.toJSON(), verificationKey);
  console.log('ok', isValid);

  const proofInclusionPath = simulateMerklePaths(wallet.blockHash, salt);
  const blockHash = proofInclusionPath.array[proofInclusionPath.array.length - 1] // The last element is the root

  // Call the function that wraps the zk-program call
  const result2 = await wallet.proveTxAfterSending(
    blockHash,
    salt,
    proofInclusionPath,//prev
    myPublicOutputs
  );

  //console.log('Tx proof (sendtx) result:', result2);

  const isValid2 = await verify(result2.toJSON(), verificationKey);
  console.log('ok', isValid2);
}

async function testAbsorbTx(wallet: Wallet) {
  // Random initialization values for testing
  const amount = Field("5");
  const salt = wallet.destinationsRoot; //this should be changed

  const transactionDestination = wallet.Destinations[0];
  const transactionBalance = wallet.balance.sub(wallet.balanceNew); 
  console.log('transactionBalance of absorbing transaction:', transactionBalance.toString());

  // Simulate storing the previous state before the transaction
  const stateHashPrev = Poseidon.hash([
    wallet.pkHash,
    wallet.address,
    wallet.destinationsRoot,
    wallet.balanceNew,
    wallet.inTxsRootNew,
    wallet.outTxsRoot
  ]);

  // Call the absorbNewTx function
  if(!wallet.absorbNewTx(transactionDestination, amount, salt, wallet.newTxProof)) {
    return;
  }

  const newStateHash = wallet.stateHashNew;
  const messageHash = Poseidon.hash([wallet.address, wallet.stateHashNew]);
/*
  console.log('New state hash after absorbing transaction:', newStateHash.toString());
  console.log('wallet.blockHash:', wallet.blockHash.toString());
  console.log('wallet.prevStateProof.publicOutput.Leaf:', wallet.prevStateProof.publicOutput.Leaf.toString());
  console.log('wallet.prevStateProof.publicOutput.Root:', wallet.prevStateProof.publicOutput.Root.toString());
*/
  const myPublicOutputs = new MyPublicOutputs({
    Leaf: stateHashPrev, // Using the initial state hash as the leaf
    Root: wallet.blockHash // The last element is the root
  });

  // For verification purposes, simulate the transaction inclusion proof
  const inclusionPath = simulateMerklePaths(wallet.blockHash, messageHash);
  wallet.blockHash = inclusionPath.array[inclusionPath.array.length - 1] // The last element is the root

  console.log('wallet.blockHash:', wallet.blockHash.toString());
  console.log('messageHash:', messageHash.toString());

  // Call the function that wraps the zk-program call for verifying the new state
  const result = await wallet.proveStateAfterAbsorbing(
    transactionDestination,
    transactionBalance,
    salt,
    inclusionPath, // Using the same path for simplicity
    inclusionPath, // New path after the transaction is absorbed
    wallet.oldStateSnapshot!.newTxProof,
    myPublicOutputs
  );

  //console.log('Transaction absorption proof result:', result);

  const isValid = await verify(result.toJSON(), verificationKey);
  console.log('ok', isValid);
}


console.log('compiling zkprogram...');
console.time('compile');

// Run the function to check, load or create the verification key
  let verificationKey: VerificationKey; // Declare the variable to store the verification key

    const compiled = await transitionProgram.compile();
    verificationKey = compiled.verificationKey;
console.timeEnd('compile');

console.log('testing init...');
console.time('init');
const wal = await testRandomInitialization();
console.timeEnd('init');
console.log('finished init...');

console.log('testing derive...');
console.time('derive');
await testDeriveDestination(wal);
console.timeEnd('derive');
console.log('finished derive...');

console.log('testing BurnToStealth...');
console.time('BurnToStealth');
await testBurnToStealth(wal);
console.timeEnd('BurnToStealth');
console.log('finished BurnToStealth...');

console.log('testing send...');
console.time('send');
await testSendTx(wal);
console.timeEnd('send');
console.log('finished send...');

console.log('testing receive...');
console.time('receive');
await testAbsorbTx(wal);
console.timeEnd('receive');
console.log('finished receive...');

console.log('testing BurnToStealth...');
console.time('BurnToStealth');
await testBurnToStealth(wal);
console.timeEnd('BurnToStealth');
console.log('finished BurnToStealth...');

console.log('testing derive...');
console.time('derive');
await testDeriveDestination(wal);
console.timeEnd('derive');
console.log('finished derive...');

console.log('testing send...');
console.time('send');
await testSendTx(wal);
console.timeEnd('send');
console.log('finished send...');

console.log('testing receive...');
console.time('receive');
await testAbsorbTx(wal);
console.timeEnd('receive');
console.log('finished receive...');

console.log('testing BurnToStealth...');
console.time('BurnToStealth');
await testBurnToStealth(wal);
console.timeEnd('BurnToStealth');
console.log('finished BurnToStealth...');

