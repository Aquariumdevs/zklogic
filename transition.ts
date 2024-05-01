import { Struct, VerificationKey, verify, Hash, Poseidon, Field, MerkleTree, MerkleWitness, MerkleMap, MerkleMapWitness, Proof, SelfProof, Bool, Bytes, Gadgets, ZkProgram } from 'o1js';

export { fieldArray, transitionProgram, Wallet, MyPublicOutputs, hashInputs, MerkleWitness4};

class MyPublicOutputs extends Struct({
  Leaf: Field,
  Root: Field,
}) {}

class hashInputs extends Struct({
  Left: Field,
  Right: Field,
}) {}

class fieldArray extends Struct({
  array: [Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field],
}) {}


class MerkleWitness4 extends MerkleWitness(4) {}

class Wallet {
  pkHash: Field;
  address: Field;

  balance: Field;
  balanceNew: Field;

  inTxHash: Field
  inTxs: MerkleMap;
  inTxsRootPrev: Field;
  inTxsRootNew: Field;
  key: Field;
  proofNotExists: MerkleMapWitness;
  proofExists: MerkleMapWitness;

  outTxs: MerkleTree;
  outTxsRoot: Field;
  outTx: Field;
  outTxNotExists: MerkleWitness4;
  outTxExists: MerkleWitness4;

  Fee: Field;

  Destinations: Array<Field>; // Array to store multiple destinations
  destinations: MerkleTree;
  destinationNew: Field;
  destinationsRoot: Field;
  destinationExists: MerkleWitness4;
  destinationNotExists: MerkleWitness4;

  //inclusionmerklePath: fieldArray,

  blockHash: Field;

  stateHashPrev: Field;
  stateHashNew: Field;

  //myPublicOutputs: MyPublicOutputs,

  prevStateProof: Proof<Field, MyPublicOutputs>;
  newStateProof: Proof<Field, MyPublicOutputs>;
  newTxProof: Proof<Field, MyPublicOutputs>;

  path: fieldArray;

  // New additional variables
  oldStateSnapshot: Wallet | null; // Snapshot of the wallet's state before changes
  currentProofs: Array<Proof<any, any>>; // Array to store proofs after each transaction or state change

  constructor(balance: Field) {
    this.balance = balance;
    this.balanceNew = balance;
    this.inTxs = new MerkleMap();
    this.outTxs = new MerkleTree(4);
    this.inTxsRootNew = this.inTxs.getRoot();
    this.inTxsRootPrev = this.inTxs.getRoot();
    this.outTxsRoot = this.outTxs.getRoot();
    this.Destinations = []; // Initialize the destinations array
    this.destinations = new MerkleTree(4);
    this.destinationsRoot = this.destinations.getRoot();

    this.oldStateSnapshot = null;
    this.currentProofs = [];

  }

  clone(): Wallet {
    const snapshot = new Wallet(this.balance);

    // Clone field values
    snapshot.pkHash = this.pkHash;
    snapshot.address = this.address;
    snapshot.balance = this.balance;
    snapshot.balanceNew = this.balanceNew;
    snapshot.inTxHash = this.inTxHash;
    snapshot.inTxsRootPrev = this.inTxsRootPrev;
    snapshot.inTxsRootNew = this.inTxsRootNew;
    snapshot.outTxsRoot = this.outTxsRoot;
    snapshot.key = this.key;
    snapshot.Fee = this.Fee;
    snapshot.destinationNew = this.destinationNew;
    snapshot.destinationsRoot = this.destinationsRoot;
    snapshot.stateHashPrev = this.stateHashPrev;
    snapshot.stateHashNew = this.stateHashNew;
    snapshot.blockHash = this.blockHash;

    // Proof and witness fields are not cloned, handling them requires specific methods or they must be reassigned manually
    snapshot.proofNotExists = this.proofNotExists;
    snapshot.proofExists = this.proofExists;
    snapshot.outTxNotExists = this.outTxNotExists;
    snapshot.outTxExists = this.outTxExists;
    snapshot.destinationExists = this.destinationExists;
    snapshot.destinationNotExists = this.destinationNotExists;

    snapshot.prevStateProof = this.prevStateProof;
    snapshot.newStateProof = this.newStateProof;
    snapshot.newTxProof = this.newTxProof;

    // Note: Merkle trees and maps are referenced, not cloned deeply
    snapshot.inTxs = this.inTxs;
    snapshot.outTxs = this.outTxs;
    snapshot.destinations = this.destinations;
    snapshot.Destinations = this.Destinations;

    return snapshot;
  }

  // Utility method to restore state from a snapshot
  restoreFromSnapshot(snapshot: Wallet) {
    Object.assign(this, snapshot);
  }

  async initializeStateAndProve(
    blsPublicKeyPart1: Field,
    blsPublicKeyPart2: Field,
    msgInclusionMerklePath: fieldArray, // Message inclusion Merkle path for proving the transaction message
    myPublicOutputs: MyPublicOutputs // Outputs for the proof
  ) {

    this.path = msgInclusionMerklePath;
    // Capture the current state before any transaction
    const sourceAddress = this.address;
    const publicKey = this.pkHash; // public key is stored as pkHash
    const destinationsRoot = this.destinationsRoot;
    const balance = Field(0);
    const InputRoot = this.inTxsRootNew;
    const outputRoot = this.outTxsRoot;

    this.stateHashNew = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, balance, InputRoot, outputRoot]);

    const stateHash = this.stateHashNew; // Current state hash
    const blockHash = this.blockHash; // Current block hash 

    const operationType = Field("3");

    console.log('Initializing state and starting proof computation.');

    console.log(`Operation type set for the proof: ${operationType.toString()}`);
    console.log(`destinationsRoot hash: ${destinationsRoot.toString()}`);
    console.log(`InputRoot hash: ${InputRoot.toString()}`);
    console.log(`Public key hash: ${publicKey.toString()}`);
    console.log(`Current state hash: ${stateHash.toString()}`);
    console.log(`Current block hash: ${blockHash.toString()}`);

    // Log detailed Merkle path information
    //console.log('Message Inclusion Merkle Path:', msgInclusionMerklePath.array.map(x => x.toString()));
    //console.log('State Inclusion Merkle Path:', inclusionMerklePath.array.map(x => x.toString()));

    console.log('Calling zkProgram to prove base state construction...');


    const result = await transitionProgram.proveBaseStateConstruction(
      operationType,
      msgInclusionMerklePath,
      //inclusionMerklePath,
      sourceAddress,
      publicKey,
      blsPublicKeyPart1, // These should be initialized as part of the wallet state
      blsPublicKeyPart2,
      stateHash,
      blockHash,
      myPublicOutputs
    );
 
    this.newStateProof = result;

    //console.log('Base state proof result:', result);
    console.log('Proof process completed.');

    return result;
  }

async proveStateAfterDestinationDerivation(pkSaltHash: Field, previnclusionmerklePath: fieldArray, inclusionmerklePath: fieldArray, myPublicOutputs: MyPublicOutputs) {
  this.path = inclusionmerklePath;
  // Setup the necessary inputs
  const sourceAddress = this.address;
  const publicKey = this.pkHash; // public key is the hash of the public key
  const balance = this.balance; // Current balance which remains unchanged
  const previousOutputRoot = this.oldStateSnapshot!.outTxsRoot; // Previous output root from the snapshot
  const newOutputRoot = this.outTxsRoot; // New output root after adding the destination
  const previousDestinationRoot = this.oldStateSnapshot!.destinationsRoot; // Previous destinations root
  const newDestination = this.destinationNew; // New destination being added
  const newDestinationRoot = this.destinationsRoot; // Calculate new destination root
  const destinationExists = this.destinationExists; // Proof of destination existence
  const destinationNotExists = this.destinationNotExists; // Proof of destination non-existence
  const InputRoot = this.inTxsRootNew;
  const blockHash = this.blockHash; // Current block hash

        const stateHashOld = Poseidon.hash([publicKey, sourceAddress, previousDestinationRoot, balance, InputRoot, previousOutputRoot]);

    console.log(`Previous state hash: ${myPublicOutputs.Leaf.toString()}`);
    console.log(`Previous state hash recompute: ${stateHashOld.toString()}`);

  const result = await transitionProgram.proveStateAfterAddingDest(
    Field(3), //operation codes
    this.prevStateProof,
    previnclusionmerklePath,
    inclusionmerklePath,
    sourceAddress,
    publicKey,
    balance,
    previousOutputRoot,
    newOutputRoot,
    InputRoot, 
    previousDestinationRoot,
    newDestination,
    newDestinationRoot,
    destinationExists,
    destinationNotExists,
    pkSaltHash,
    blockHash,
    myPublicOutputs
  );

  this.newStateProof = result;

  //console.log('Proof of adding destination result:', result);
  return result;
}


  // Method to setup and call the zk-program function
  async proveStateAfterSending(transactionSalt: Field, previnclusionmerklePath: fieldArray, inclusionmerklePath: fieldArray, myPublicOutputs: MyPublicOutputs) {
    this.path = inclusionmerklePath;
    // Setup the necessary inputs
    const sourceAddress = this.address;
    const publicKey = this.pkHash; // public key is the hash of the public key
    const previousBalance = this.balance;
    const newBalance = this.balanceNew;
    const balanceSent = this.balance.sub(this.balanceNew); 
    const transactionDestination = this.destinationNew;
    const transactionHash = hashTx(transactionDestination, balanceSent, transactionSalt); 

    const result = await transitionProgram.proveStateAfterSending(
      Field("3"),
      this.prevStateProof,
      previnclusionmerklePath,
      inclusionmerklePath,
      sourceAddress,
      publicKey,
      previousBalance,
      newBalance,
      balanceSent,
      transactionDestination,
      transactionSalt,
      this.destinationsRoot,
      this.inTxsRootNew, 
      this.oldStateSnapshot!.outTxsRoot, 
      this.outTxsRoot, 
      this.outTxNotExists,
      this.outTxExists,
      this.inTxsRootPrev, 
      transactionHash,
      this.blockHash, 
      myPublicOutputs
    );

    this.newStateProof = result; 

    //console.log('Proof result:', result);
    return result;
  }

// Method to call the zk-program function for proving funds burning
async proveFundsBurning(amount: Field, prevInclusionMerklePath: fieldArray, msgInclusionMerklePath: fieldArray, myPublicOutputs: MyPublicOutputs) {
  this.path = msgInclusionMerklePath;
  const sourceAddress = this.address;
  const publicKey = this.pkHash; // public key is the hash of the public key
  const previousBalance = this.balance; // Previous balance before burning
  const newBalance = this.balanceNew; // New balance after burning

  const result = await transitionProgram.proveFundsBurning(
    Field("3"), // operation type for states
    this.newStateProof,
    prevInclusionMerklePath,
    msgInclusionMerklePath,
    sourceAddress,
    publicKey,
    previousBalance,
    amount,
    newBalance,
    this.inTxsRootNew, // New root hash of the input transactions Merkle tree after burning
    this.destinationsRoot, // Root hash of the destinations Merkle tree, unchanged here
    this.proofNotExists, // Proof of not inclusion for the burning transaction
    this.proofExists, // Proof of inclusion for the burning transaction
    this.outTxsRoot, // this represents the previous output root, unchanged in burning
    this.outTxsRoot, // New output root, unchanged as it's a burning operation
    this.blockHash, 
    this.stateHashNew, // State hash of the account after burning
    myPublicOutputs
  );

  this.newStateProof = result;

  //console.log('Funds burning proof result:', result);
  return result;
}

async proveStateAfterAbsorbing(transactionDestination: Field, transactionBalance: Field, transactionSalt: Field, previnclusionmerklePath: fieldArray, inclusionmerklePath: fieldArray, transactionProof: SelfProof<Field, MyPublicOutputs>, myPublicOutputs: MyPublicOutputs) {
  // Setup the necessary inputs

  this.path = inclusionmerklePath;

  const sourceAddress = this.address;
  const publicKey = this.pkHash; // public key is the hash of the public key
  const previousBalance = this.balance;

  const newBalance = this.balanceNew;

  const previousInputRoot = this.inTxsRootPrev;
  const newInputRoot = this.inTxsRootNew;

  const destinationsRoot = this.destinationsRoot;

  // The proofs of inclusion or non-inclusion for the transaction in the MerkleMap
  const inTxProofNotExists = this.proofNotExists; // Proof of not inclusion before transaction
  const inTxProof = this.proofExists; // Proof of inclusion after transaction

  // Output roots before and after the transaction, might be static if outputs don't change
  const outputRootPrev = this.oldStateSnapshot!.outTxsRoot; 
  const outputRoot = this.outTxsRoot; 

  const blockHash = this.blockHash; 

  const absorbedTransactionHash = hashTx(transactionDestination, transactionBalance, transactionSalt);
  console.log('absorbedTransactionHash:', absorbedTransactionHash.toString());


  const result = await transitionProgram.proveStateAfterAbsorbing(
    Field("3"), // Operation type
    this.prevStateProof, // Previous state proof
    previnclusionmerklePath,
    inclusionmerklePath,
    transactionProof,
    sourceAddress,
    publicKey,
    previousBalance,
    transactionDestination,
    transactionBalance,
    transactionSalt,
    newBalance,
    previousInputRoot,
    newInputRoot,
    destinationsRoot,
    inTxProofNotExists,
    inTxProof,
    outputRootPrev,
    outputRoot,
    absorbedTransactionHash,
    blockHash,
    myPublicOutputs
  );

    this.newStateProof = result;

  //console.log('Absorption proof result:', result);
  return result;
}


  // Method to call the zk-program function for proving transaction after sending
  async proveTxAfterSending(blockHash: Field, transactionSalt: Field, inclusionmerklePath: fieldArray, myPublicOutputs: MyPublicOutputs) {
    const sourceAddress = this.address;
    const publicKey = this.pkHash; // public key is the hash of the public key
    const balanceSent = this.balance.sub(this.balanceNew); 
    const transactionDestination = this.destinationNew;
    const transactionHash = hashTx(transactionDestination, balanceSent, transactionSalt); 

    const result = await transitionProgram.proveTxAfterSending(
      Field("23"),
      this.newStateProof,
      inclusionmerklePath,
      sourceAddress,
      publicKey,
      this.balanceNew,
      balanceSent,
      transactionDestination,
      transactionSalt,
      this.destinationsRoot,
      this.inTxsRootNew, 
      this.outTxsRoot, 
      this.outTxExists, 
      transactionHash,
      blockHash, 
      myPublicOutputs
    );

    this.newTxProof = result;
    //console.log('Transaction proof result:', result);
    return result;
  }

  deriveDestination(pkSaltHash: Field) {

    // Store a snapshot of the current state before making changes
    this.oldStateSnapshot = this.clone();
    this.prevStateProof = this.newStateProof;
    this.balance = this.balanceNew;

    // Set up new destination
    const index = BigInt(this.Destinations.length);
    this.destinationNew = Poseidon.hash([this.pkHash, pkSaltHash]);;
    this.Destinations.push(this.destinationNew);

    // get the witness for the previous dest tree
    this.destinationNotExists = new MerkleWitness4(this.destinations.getWitness(index));

    // Put the new destination in the dest tree
    this.destinations.setLeaf(index, this.destinationNew);

    // get the witness for the current dest tree
    this.destinationExists = new MerkleWitness4(this.destinations.getWitness(index));
    this.destinationsRoot = this.destinationExists.calculateRoot(this.destinationNew);

    this.stateHashNew = Poseidon.hash([this.pkHash, this.address, this.destinationsRoot, this.balance, this.inTxsRootNew, this.outTxsRoot]);
    const messageHash = Poseidon.hash([this.address, this.stateHashNew]);
    return messageHash;
  }


  increaseStealthFunds(amount: Field) {

    // Store a snapshot of the current state before making changes
    this.oldStateSnapshot = this.clone();
    this.prevStateProof = this.newStateProof;
    this.balance = this.balanceNew;

    this.balanceNew = this.balance.add(amount)

    this.stateHashNew = Poseidon.hash([this.pkHash, this.address, this.destinationsRoot, this.balanceNew, this.inTxsRootNew, this.outTxsRoot]);
    const messageHash = Poseidon.hash([this.address, Field(0), amount, this.stateHashNew]);

    return messageHash;
  }



  constructNewTx(destination: Field, balance: Field, salt: Field) {

    // Store a snapshot of the current state before the transaction
    this.oldStateSnapshot = this.clone();
    this.prevStateProof = this.newStateProof;
    this.balance = this.balanceNew;

    console.log(`Previous balance: ${this.balance.toString()}`);
    console.log(`Amount: ${balance.toString()}`);

    if(balance.greaterThan(this.balance).toString() == 'true') {
      console.log("Insufficient funds for the transaction.");
      return destination;
    }

    this.destinationNew = destination;

    // Compute the hash of the new transaction
    this.outTx = hashTx(destination, balance, salt);
    console.log(`outTx: ${this.outTx.toString()}`);

    this.outTxs = new MerkleTree(4);

    let index = BigInt("0"); //TODO: a counter is suitable here
    this.outTxNotExists = new MerkleWitness4(this.outTxs.getWitness(index));
    this.outTxs.setLeaf(index, this.outTx);
    this.outTxsRoot = this.outTxs.getRoot();
    this.outTxExists = new MerkleWitness4(this.outTxs.getWitness(index));

    console.log(`outTxsRoot: ${this.outTxsRoot.toString()}`);
    const rootAfter = this.outTxExists.calculateRoot(this.outTx);
    console.log(`rootAfter: ${rootAfter.toString()}`);

    // Update balances
    this.balanceNew = this.balance.sub(balance);

    this.stateHashNew = Poseidon.hash([this.pkHash, this.address, this.destinationsRoot, this.balanceNew, this.inTxsRootNew, this.outTxsRoot]);
    const messageHash = Poseidon.hash([this.address, this.stateHashNew]);

    return messageHash;
  }


 absorbNewTx(destination: Field, balance: Field, salt: Field, txProof: Proof<Field, MyPublicOutputs>) {
  for (let j = 0; j < this.Destinations.length; j++) {  // Simplified loop
    console.log(`Current equals: ${this.Destinations[j].equals(destination).toString()}`);
    if (this.Destinations[j].equals(destination).toString() == 'true') {
      this.destinationExists = new MerkleWitness4(this.destinations.getWitness(BigInt(j)));
      break;
    }
    if (j == this.Destinations.length) {
      return false;
    }
  }

  this.inTxHash = hashTx(destination, balance, salt);

  const value = this.inTxs.get(this.inTxHash);

  //console.log(`Current equals hash: ${value.equals(Field(0)).toString()}`);
  if (value.equals(Field(0)).toString() == 'false') {
    return false;
  }

  // Store a snapshot of the current state before the transition
  this.oldStateSnapshot = this.clone();
  this.prevStateProof = this.newStateProof;
  this.balance = this.balanceNew;
  this.balanceNew = this.balanceNew.add(balance);

  this.outTxs = new MerkleTree(4);
  this.outTxsRoot = this.outTxs.getRoot();

  this.inTxsRootPrev = this.inTxs.getRoot();

  //console.log(`inTxsRootPrev: ${this.inTxsRootPrev.toString()}`);
  this.proofNotExists = this.inTxs.getWitness(this.inTxHash);
  this.inTxs.set(this.inTxHash, balance);  // store the balance as the value
  this.proofExists = this.inTxs.getWitness(this.inTxHash);
  this.balanceNew = this.balance.add(balance);
  this.inTxsRootNew = this.inTxs.getRoot();

  const [ rootAfter, key ] = this.proofNotExists.computeRootAndKey(balance);
  //console.log(`rootAfter: ${rootAfter.toString()}`);
  //console.log(`key: ${key.toString()}`);

  console.log(`inTxsRootNew: ${this.inTxsRootNew.toString()}`);
  console.log(`balance: ${balance.toString()}`);
  this.stateHashNew = Poseidon.hash([this.pkHash, this.address, this.destinationsRoot, this.balanceNew, this.inTxsRootNew, this.outTxsRoot]);

  return true;
}

}

function hashTx(destination: Field, balance: Field, salt: Field) {
  return Poseidon.hash([destination, balance, salt]);
}

function isPartOf(xs: Field, ls: hashInputs) {
        let condition1 = ls.Left.equals(xs)
        let condition2 = ls.Right.equals(xs)
        
        condition1.or(condition2).assertEquals(true);
}

function step(xsIn: Field, ls: hashInputs, xsOut: Field) {
  xsOut.assertEquals(Poseidon.hash([ls.Left, ls.Right]))
  isPartOf(xsIn, ls);
}

function stepSimple(xsInLeft: Field, xsInRight: Field, xsOut: Field) {
  const left = xsOut.equals(Poseidon.hash([xsInLeft, xsInRight]))
  const right = xsOut.equals(Poseidon.hash([xsInRight, xsInLeft]))
  left.or(right).assertEquals(true);
}

function verifyMerklePath(leaf: Field, expectedRoot: Field, merklePath: Field[]) {
    let rootFound = Bool(false);
    let rootExists = Bool(false);
    (merklePath[0].equals(leaf)).or(merklePath[1].equals(leaf)).assertEquals(true);
    for (let i = 0; i < 127; i+=2) {
        stepSimple(merklePath[i], merklePath[i+1], merklePath[i+2]);
        rootFound = merklePath[i+2].equals(expectedRoot);
        rootExists = rootExists.or(rootFound);
    }
    rootExists.assertEquals(true);
}


const transitionProgram = ZkProgram({
  name: 'transition',
  publicInput: Field,
  publicOutput: MyPublicOutputs,//Bytes(32).provable,
  methods: {
  //proofOfTransitions: 
    proveBaseStateConstruction: {
      privateInputs: [fieldArray, /*fieldArray,*/ Field, Field, Field, Field, Field, Field, MyPublicOutputs],
      method(
        operationType: Field, // Type of operation for recursive operation consistency
        msginclusionmerklePath: fieldArray,
        //inclusionmerklePath: fieldArray,
        sourceAddress: Field, // Address of the account
        publicKey: Field, // Public key of the account
        blsPublicKeyPart1: Field, // First part of the BLS public key
        blsPublicKeyPart2: Field, // Second part of the BLS public key
        stateHash: Field, // Hash of the account's state
        blockHash: Field, // Hash of the block including the account's state
        out: MyPublicOutputs
      ) { 
        //maintain consistency 
        //pubkey should be identical with tx pubkey
        const messageHash = Poseidon.hash([sourceAddress, publicKey, blsPublicKeyPart1, blsPublicKeyPart2, stateHash]);

        //proof of current message inclusion
        verifyMerklePath(messageHash, blockHash, msginclusionmerklePath.array)
        out.Root.assertEquals(blockHash);

        //proof of correct inTx tree transitions
        const newInputRoot = Field("22731122946631793544306773678309960639073656601863129978322145324846701682624"); //empty map root

        //proof of correct outTx tree transitions
        const outputRoot = Field("544619463418997333856881110951498501703454628897449993518845662251180546746"); //empty tree root

        //destinations logic
        const destinationsRoot = Field("544619463418997333856881110951498501703454628897449993518845662251180546746"); //empty tree root

        //balance verification
        const balance = Field(0); 

        //reconstruct new stateHash
        out.Leaf = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, balance, newInputRoot, outputRoot]);
        out.Leaf.assertEquals(stateHash);  /**/

        return out;
      },
    },

    proveFundsBurning: {
      privateInputs: [SelfProof, fieldArray, fieldArray, Field, Field, Field, Field, Field, Field, Field, MerkleMapWitness, MerkleMapWitness, Field, Field, Field, Field, MyPublicOutputs],
      method(
        operationType: Field, // Type of operation to maintain consistency among recursive operations
        prevstateproof: SelfProof<Field, MyPublicOutputs>, //recursive proof
        prevstateinclusionmerklePath: fieldArray,
        msginclusionmerklePath: fieldArray,
        sourceAddress: Field, // Address of the account that absorbs the transaction
        publicKey: Field, // Public key associated with the account
        previousBalance: Field, // Balance before the transaction
        amount: Field, // Balance burnt during the transaction
        newBalance: Field, // Updated balance after absorbing the transaction
        InputRoot: Field, // New root hash of the input transactions Merkle tree after absorbing
        destinationsRoot: Field, // New root hash of the destinations Merkle tree after adding the new destination
        inTxProofNotExists: MerkleMapWitness, // Proof of not inclusion for the absorbed transaction in the previous MerkleMap
        inTxProof: MerkleMapWitness, // Proof of inclusion for the absorbed transaction in the MerkleMap
        outputRootPrev: Field, // Root hash of the output transactions Merkle tree //dummy tree root here
        outputRoot: Field, // Root hash of the output transactions Merkle tree //dummy tree root here
        blockHash: Field, // Hash of the block containing the transaction
        stateHash: Field, // Hash of the account's state
        out: MyPublicOutputs
      ) {
        //maintain consistency  

        //pubkey should be identical with tx pubkey
        const messageHash = Poseidon.hash([sourceAddress, Field("0"), amount, stateHash]);

        //verify proof of previous state 
        prevstateproof.verify();
        Field(3).assertEquals(prevstateproof.publicInput);
        prevstateproof.publicOutput.Leaf.assertEquals(out.Leaf);
        prevstateproof.publicOutput.Root.assertEquals(out.Root);

        //proof of current message inclusion
        verifyMerklePath(messageHash, blockHash, msginclusionmerklePath.array)

        //state inheritance verification //equality of source=source, pk=pk
        const stateHashOld = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, previousBalance, InputRoot, outputRootPrev]);
        stateHashOld.assertEquals(prevstateproof.publicOutput.Leaf);

        //construct new stateHash
        outputRoot = Field("544619463418997333856881110951498501703454628897449993518845662251180546746");
        out.Leaf = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, newBalance, InputRoot, outputRoot]);
        out.Leaf.assertEquals(stateHash);

        //proof of previous state inclusion
        verifyMerklePath(out.Root, blockHash, prevstateinclusionmerklePath.array);

        out.Root = blockHash;

        //balance verification
        const balanceNew = previousBalance.add(amount);
        balanceNew.assertEquals(newBalance); 

        return out;
      },
    },

    proveStateAfterAbsorbing: {
      privateInputs: [SelfProof, fieldArray, fieldArray, SelfProof, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, MerkleMapWitness, MerkleMapWitness, Field, Field, Field, Field, MyPublicOutputs],
      method(
        operationType: Field, // Type of operation to maintain consistency among recursive operations
        prevstateproof: SelfProof<Field, MyPublicOutputs>, //recursive proof
        prevstateinclusionmerklePath: fieldArray,
        inclusionmerklePath: fieldArray,
        txproof: SelfProof<Field, MyPublicOutputs>, //recursive proof
        sourceAddress: Field, // Address of the account that absorbs the transaction
        publicKey: Field, // Public key associated with the account
        previousBalance: Field, // Balance before the transaction
        transactionDestination: Field, // Balance from the absorbed transaction
        transactionBalance: Field, // Balance from the absorbed transaction
        transactionSalt: Field, // Salt from the absorbed transaction
        newBalance: Field, // Updated balance after absorbing the transaction
        previousInputRoot: Field, // Previous root hash of the input transactions Merkle tree
        newInputRoot: Field, // New root hash of the input transactions Merkle tree after absorbing
        destinationsRoot: Field, // New root hash of the destinations Merkle tree after adding the new destination
        inTxProofNotExists: MerkleMapWitness, // Proof of not inclusion for the absorbed transaction in the previous MerkleMap
        inTxProof: MerkleMapWitness, // Proof of inclusion for the absorbed transaction in the MerkleMap
        outputRootPrev: Field, // Root hash of the output transactions Merkle tree //dummy tree root here
        outputRoot: Field, // Root hash of the output transactions Merkle tree //dummy tree root here
        absorbedTransactionHash: Field, // Hash of the absorbed transaction
        blockHash: Field, // Hash of the block containing the transaction
        out: MyPublicOutputs
      ) {
        //maintain consistency  

        //verify proof of previous state 
        prevstateproof.verify();
        Field(3).assertEquals(prevstateproof.publicInput);
        prevstateproof.publicOutput.Leaf.assertEquals(out.Leaf);
        prevstateproof.publicOutput.Root.assertEquals(out.Root);
  
        //state inheritance verification //equality of source=source, pk=pk
        const stateHashOld = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, previousBalance, previousInputRoot, outputRootPrev]);
        stateHashOld.assertEquals(prevstateproof.publicOutput.Leaf);

        //construct new stateHash
        outputRoot = Field("544619463418997333856881110951498501703454628897449993518845662251180546746");
        const stateHash = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, newBalance, newInputRoot, outputRoot]);
        out.Leaf = stateHash;

        //pubkey should be identical with tx pubkey
        const messageHash = Poseidon.hash([sourceAddress, stateHash]);

        //proof of current message inclusion
        verifyMerklePath(messageHash, blockHash, inclusionmerklePath.array)

        //proof of previous state inclusion
        verifyMerklePath(out.Root, blockHash, prevstateinclusionmerklePath.array);

        out.Root = blockHash;

        //proof of tx
        txproof.verify();
        Field(23).assertEquals(txproof.publicInput);

        //verify tx proof public output
        absorbedTransactionHash.assertEquals(txproof.publicOutput.Leaf);

        //transaction hash verification
        const txHash = hashTx(transactionDestination, transactionBalance, transactionSalt)
        absorbedTransactionHash.assertEquals(txHash);

        //proof of correct inTx tree transitions
        inTxProofNotExists.assertEquals(inTxProof);
        const [ rootAfter, lkey ] = inTxProof.computeRootAndKey(transactionBalance);
        const [ rootBefore, rkey ] = inTxProofNotExists.computeRootAndKey(Field(0));
        lkey.assertEquals(rkey);
        newInputRoot.assertEquals(rootAfter);
        previousInputRoot.assertEquals(rootBefore);

        //proof of correct outTx tree transitions
        outputRoot.assertEquals(Field("544619463418997333856881110951498501703454628897449993518845662251180546746"));

        //balance verification
        const balanceNew = previousBalance.add(transactionBalance);
        balanceNew.assertEquals(newBalance); //not really needed here!
 
        return out;
      },
    },

    proveStateAfterAddingDest: {
      privateInputs: [SelfProof, fieldArray, fieldArray, Field, Field, Field, Field, Field, Field, Field, Field, Field, MerkleWitness4, MerkleWitness4, Field, Field, MyPublicOutputs],
      method(
        operationType: Field, // Type of operation to maintain consistency among recursive operations
        prevstateproof: SelfProof<Field, MyPublicOutputs>, //recursive proof
        prevstateinclusionmerklePath: fieldArray,
        inclusionmerklePath: fieldArray,
        sourceAddress: Field, // Address of the account that is adding a new destination
        publicKey: Field, // Public key associated with the account
        balance: Field, // Balance of the account, which remains unchanged here
        previousOutputRoot: Field, // Previous root hash of the output transactions Merkle tree
        newOutputRoot: Field, // New root hash of the output transactions Merkle tree after adding the new destination
        InputRoot: Field, // Root hash of the input transactions Merkle tree //unchanged here
        previousDestinationRoot: Field, // Previous root hash of the destinations Merkle tree
        newDestination: Field, // New destination being added
        newDestinationRoot: Field, // New root hash of the destinations Merkle tree after adding the new destination
        destinationExists: MerkleWitness4, // Proof of not inclusion for the derived destination in the previous MerkleTree
        destinationNotExists: MerkleWitness4, // Proof of inclusion for the derived destination in the previous MerkleTree
        pkSaltHash: Field, // Hash of the public key and some salt, used for generating the new destination address
        blockHash: Field, // Hash of the block in which the transaction will be included
        out: MyPublicOutputs //previous state's public outputs
      ) {
        //maintain consistency 
 
        //verify proof of previous state 
        prevstateproof.verify();
        Field(3).assertEquals(prevstateproof.publicInput);
        prevstateproof.publicOutput.Leaf.assertEquals(out.Leaf);
        prevstateproof.publicOutput.Root.assertEquals(out.Root);

        //state inheritance verification //equality of source=source, pk=pk
        const stateHashOld = Poseidon.hash([publicKey, sourceAddress, previousDestinationRoot, balance, InputRoot, previousOutputRoot]);
        stateHashOld.assertEquals(prevstateproof.publicOutput.Leaf);

        //construct new stateHash
        const stateHash = Poseidon.hash([publicKey, sourceAddress, newDestinationRoot, balance, InputRoot, newOutputRoot]);
        out.Leaf = stateHash;
 
        //construct new messageHash
        const messageHash = Poseidon.hash([sourceAddress, stateHash]);

        //prove destination
        const tempdest = Poseidon.hash([publicKey, pkSaltHash]);
        newDestination.assertEquals(tempdest);

        //proof of previous state's block inclusion in current block
        verifyMerklePath(out.Root, blockHash, prevstateinclusionmerklePath.array)


        out.Root = blockHash;
        //blockHash.assertEquals(prevstateproof.publicOutput.Root);//WRONG LOGIC

        //proof of current state inclusion
        verifyMerklePath(messageHash, out.Root, inclusionmerklePath.array)

        //proof of correct destination tree transition
        destinationExists.assertEquals(destinationNotExists);
        const rootAfter = destinationExists.calculateRoot(newDestination);
        const rootBefore = destinationNotExists.calculateRoot(Field(0));

        newDestinationRoot.assertEquals(rootAfter);
        previousDestinationRoot.assertEquals(rootBefore);
 
        //proof of correct outTx tree transitions
        newOutputRoot.assertEquals(Field("544619463418997333856881110951498501703454628897449993518845662251180546746")); ////empty tree root

         return out;
      },
    },

    proveStateAfterSending: {
      privateInputs: [SelfProof, fieldArray, fieldArray, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, Field, MerkleWitness4, MerkleWitness4, Field, Field, Field, MyPublicOutputs],
      method(
        operationType: Field, // Type of operation for recursive operation consistency
        prevstateproof: SelfProof<Field, MyPublicOutputs>, //recursive proof
        prevstateinclusionmerklePath: fieldArray,
        inclusionmerklePath: fieldArray,
        sourceAddress: Field, // Address of the sender account
        publicKey: Field, // Public key associated with the account
        previousBalance: Field, // Balance before the transaction
        newBalance: Field, // Updated balance after absorbing the transaction
        balanceSent: Field, // Amount of balance being sent
        transactionDestination: Field, // Balance from the absorbed transaction
        transactionSalt: Field, // Salt from the absorbed transaction
        destinationsRoot: Field, // New root hash of the destinations Merkle tree after adding the new destination
        InputRoot: Field, // Root hash of the input transactions Merkle tree //unchanged here
        previousOutputRoot: Field, // Root of the output transactions Merkle tree before this transaction
        newOutputRoot: Field, // New root of the output transactions Merkle tree after this transaction
        outTxNotExists: MerkleWitness4, // Proof of not inclusion for the new tx in the previous MerkleTree
        outTxExists: MerkleWitness4, // Proof of inclusion for the new tx in the previous MerkleTree
        previousInputRoot: Field, // Root of the input transactions Merkle tree //unchanged in this operation
        transactionHash: Field, // Hash of the transaction being sent
        blockHash: Field, // Hash of the block in which this transaction is recorded
        out: MyPublicOutputs
      ) {
        //maintain consistency 

        //verify proof of previous state 
        prevstateproof.verify();
        Field(3).assertEquals(prevstateproof.publicInput);
        prevstateproof.publicOutput.Leaf.assertEquals(out.Leaf);
        prevstateproof.publicOutput.Root.assertEquals(out.Root);

        //state inheritance verification //equality of source=source, pk=pk
        const stateHashOld = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, previousBalance, InputRoot, previousOutputRoot]);
        stateHashOld.assertEquals(prevstateproof.publicOutput.Leaf);

        //construct new stateHash
        const stateHash = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, newBalance, InputRoot, newOutputRoot]);
        out.Leaf = stateHash;

        //pubkey should be identical with tx pubkey
        const messageHash = Poseidon.hash([sourceAddress, stateHash]);

        //proof of current message inclusion
        verifyMerklePath(messageHash, blockHash, inclusionmerklePath.array)

        //proof of previous state inclusion
        verifyMerklePath(out.Root, blockHash, prevstateinclusionmerklePath.array);

        //transaction hash verification
        const outTxHash = hashTx(transactionDestination, balanceSent, transactionSalt);

        //balance verification
        const balanceNew = previousBalance.sub(balanceSent);
        balanceNew.assertEquals(newBalance); //not really needed here!

        //proof of correct out tree transition
        outTxExists.assertEquals(outTxNotExists);
        const rootAfter = outTxExists.calculateRoot(outTxHash);
        const rootBefore = outTxNotExists.calculateRoot(Field(0));
        newOutputRoot.assertEquals(rootAfter);
        previousOutputRoot.assertEquals(rootBefore);

        out.Root = blockHash;

        return out;
      },
    },

    proveTxAfterSending: {
      privateInputs: [SelfProof, fieldArray, Field, Field, Field, Field, Field, Field, Field, Field, Field, MerkleWitness4, Field, Field, MyPublicOutputs],
      method(
        operationType: Field, // Type of operation for recursive operation consistency
        stateproof: SelfProof<Field, MyPublicOutputs>, //recursive proof
        stateinclusionmerklePath: fieldArray,
        sourceAddress: Field, // Address of the sender account
        publicKey: Field, // Public key associated with the account
        Balance: Field, // Balance before the transaction
        balanceSent: Field, // Amount of balance being sent
        transactionDestination: Field, // Balance from the absorbed transaction
        transactionSalt: Field, // Salt from the absorbed transaction
        destinationsRoot: Field, // New root hash of the destinations Merkle tree after adding the new destination
        InputRoot: Field, // Root hash of the input transactions Merkle tree //unchanged here
        OutputRoot: Field, // New root of the output transactions Merkle tree after this transaction
        outTxExists: MerkleWitness4, // Proof of inclusion for the new tx in the previous MerkleTree
        transactionHash: Field, // Hash of the transaction being sent
        blockHash: Field, // Hash of the block in which this transaction is recorded
        out: MyPublicOutputs
      ) {
        //maintain consistency 

        //verify proof of previous state 
        stateproof.verify();
        Field(3).assertEquals(stateproof.publicInput);
        out.Leaf = stateproof.publicOutput.Leaf;
        out.Root = stateproof.publicOutput.Root;

        //state inheritance verification //equality of source=source, pk=pk
        const stateHash = Poseidon.hash([publicKey, sourceAddress, destinationsRoot, Balance, InputRoot, OutputRoot]);
        stateHash.assertEquals(stateproof.publicOutput.Leaf);

        //proof of previous state inclusion
        verifyMerklePath(out.Root, blockHash, stateinclusionmerklePath.array);

        //transaction hash verification
        const outTxHash = hashTx(transactionDestination, balanceSent, transactionSalt);

        //proof of correct out tree transition
        const root = outTxExists.calculateRoot(outTxHash);
        OutputRoot.assertEquals(root);

        out.Leaf = outTxHash;
        out.Root = blockHash; 
        return out;
      },
    },
  },
});

//TODO: subtract fee !!!
//TODO: multiple ins outs & operations in one step proof

