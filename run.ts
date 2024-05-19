import { fieldArray, Wallet, transitionProgram, MyPublicOutputs, hashInputs, MerkleWitness4, FastTree } from './transition.js';
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
      const hash = treeHasher.createMerkleTree([left, right]);
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
      const hash = treeHasher.createMerkleTree([left, right]);
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

  const stateHash = treeHasher.createMerkleTree([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balance, wallet.inTxsRootNew, wallet.outTxsRoot]);
  const messageHash = treeHasher.createMerkleTree([wallet.address, wallet.pkHash, blsPublicKeyPart1, blsPublicKeyPart2, stateHash]);
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
  
  const stateHashPrev = treeHasher.createMerkleTree([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balanceNew, wallet.inTxsRootNew, wallet.outTxsRoot]);
  
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

  
  const stateHashPrev = treeHasher.createMerkleTree([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balanceNew, wallet.inTxsRootNew, wallet.outTxsRoot]);
  
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

  
  const stateHashPrev = treeHasher.createMerkleTree([wallet.pkHash, wallet.address, wallet.destinationsRoot, wallet.balanceNew, wallet.inTxsRootNew, wallet.outTxsRoot]);
  
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
  const stateHashPrev = treeHasher.createMerkleTree([
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
  const messageHash = treeHasher.createMerkleTree([wallet.address, wallet.stateHashNew]);
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
const treeHasher = new FastTree();
/*
const rt = treeHasher.createMerkleTree([Field(0), Field(0), Field(0), Field(0), Field(0), Field("16580941339322802610582068189301308321734543574938171559508035048394212433183"), Field(0)]);
  console.log('ok', rt.toString());
*/


// Function to log the Merkle tree root
function logRoot(tree: any) {
  console.log('Merkle Root:', tree.toString());
}

// Function to create a Merkle tree and log its root
function createAndLogTree(values: string[]) {
  const tree = treeHasher.createMerkleTree(values.map(Field));
  logRoot(tree);
  return tree;
}

// Values from the Go implementation
const values = [
  '4873189445717203891869709543657751406761263631053505132176373572252452677789',
  '13058127730481946522436897880786030368278403329090114642370729753163706971787',
  '19076536815667999206321685256809940940276912559715191631922695230317613961066',
  '24877170551862034748341650785600432060785553267747135356832060321010387053889',
  '21895823484133962081868049115523999957672630985997825193065730315813042635810',
  '21739769541017435382492047971866033642528462375415529552558002466287831014878',
  '28924183915066870257177607240034507598535742440854030026875651622640742161663',
  '7160575979787256275970420256031004591179966024350969785238624014643685678111',
  '14344990353836691150655979524199478547187246089789470259556273170996596824896',
  '21529404727886126025341538792367952503194526155227970733873922327349507971681',
  '28713819101935560900027098060536426459201806220666471208191571483702419118466',
  '6950211166655946918819911076532923451846029804163410966554543875705362634914',
  '14134625540705381793505470344701397407853309869601911440872193032058273781699',
  '21319039914754816668191029612869871363860589935040411915189842188411184928484',
  '2109284607279229059164177500647390700597583087463559924684446093389046711443',
  '7329171514612036647919573344996195155146935555721918958219872595922079681582',
  '22813845783537286646179732109290979201138073945659715278393420468219372547311',
  '9350497743133487788547144621413786283766155853655950882612291576166697782703',
  '24835172012058737786807303385708570329757294243593747202785839448463990648432',
  '11371823971654938929174715897831377412385376151589982807004710556411315883824',
  '26856498240580188927434874662126161458376514541527779127178258428708608749553',
  '13393150200176390069802287174248968541004596449524014731397129536655933984945',
  '28877824469101640068062445938543752586995734839461811051570677408953226850674',
  '15414476428697841210429858450666559669623816747458046655789548516900552086066',
  '26066794514972493554193898141677743898064046077216384252895487018737941311292',
  '14513585888661471522605132613164669111154215621160419432537521752274990828367',
  '1050237848257672664972545125287476193782297529156655036756392860222316063759',
  '16534912117182922663232703889582260239773435919094451356929940732519608929488',
  '3071564076779123805600116401705067322401517827090686961148811840466934164880',
  '18556238345704373803860275165999851368392656217028483281322359712764227030609',
  '5092890305300574946227687678122658451020738125024718885541230820711552266001',
  '20577564574225824944487846442417442497011876514962515205714778693008845131730',
  '7114216533822026086855258954540249579639958422958750809933649800956170367122',
  '22598890802747276085115417718835033625631096812896547130107197673253463232851',
  '4303186579692879572986711157674240890708269660713324011258459410740884827740',
  '21698000262710906397290691881333143067161495686598919906855170908627901975152',
  '8234652222307107539658104393455950149789577594595155511074042016575227210544',
  '23719326491232357537918263157750734195780715984532951831247589888872520076273',
  '10255978450828558680285675669873541278408797892529187435466460996819845311665',
  '25740652719753808678545834434168325324399936282466983755640008869117138177394',
  '12277304679350009820913246946291132407028018190463219359858879977064463412786',
  '27761978948275259819173405710585916453019156580401015680032427849361756278515',
  '14298630907871460961540818222708723535647238488397251284251298957309081513907',
  '835282867467662103908230734831530618275320396393486888470170065256406749299',
  '11487600953742314447672270425842714846715549726151824485576108567093795974525',
  '28882414636760341271976251149501617023168775752037420381172820064980813121937',
  '15419066596356542414343663661624424105796857660033655985391691172928138357329',
  '1955718555952743556711076173747231188424939568029891589610562280875463592721',
  '17440392824877993554971234938042015234416077957967687909784110153172756458450',
  '3977044784474194697338647450164822317044159865963923514002981261120081693842',
  '19461719053399444695598806214459606363035298255901719834176529133417374559571',
  '5998371012995645837966218726582413445663380163897955438395400241364699794963',
  '21483045281920895836226377490877197491654518553835751758568948113661992660692',
  '8019697241517096978593790003000004574282600461831987362787819221609317896084',
  '18672015327791749322357829694011188802722829791590324959893757723446707121310',
  '7118806701480727290769064165498114015812999335534360139535792456983756638385',
  '22603480970405977289029222929792898061804137725472156459709340329281049504114',
  '9140132930002178431396635441915705144432219633468392063928211437228374739506',
  '24624807198927428429656794206210489190423358023406188384101759309525667605235',
  '11161459158523629572024206718333296273051439931402423988320630417472992840627',
  '26646133427448879570284365482628080319042578321340220308494178289770285706356',
  '13182785387045080712651777994750887401670660229336455912713049397717610941748',
  '28667459655970330710911936759045671447661798619274252232886597270014903807477',
  '15204111615566531853279349271168478530289880527270487837105468377962229042869',
  '25856429701841184197043388962179662758730109857028825434211406879799618268095',
  '14303221075530162165454623433666587971820279400972860613853441613336667785170',
  '839873035126363307822035945789395054448361308969096218072312721283993020562',
  '16324547304051613306082194710084179100439499698906892538245860593581285886291',
  '2861199263647814448449607222206986183067581606903128142464731701528611121683',
  '18345873532573064446709765986501770229058719996840924462638279573825903987412',
  '4882525492169265589077178498624577311686801904837160066857150681773229222804',
  '20367199761094515587337337262919361357677940294774956387030698554070522088533',
  '6903851720690716729704749775042168440306022202771191991249569662017847323925',
  '22388525989615966727964908539336952486297160592708988311423117534315140189654',
  '4092821766561570215836201978176159751374333440525765192574379271802561784543',
  '21487635449579597040140182701835061927827559466411361088171090769689578931955',
  '8024287409175798182507595213957869010455641374407596692389961877636904167347',
  '23508961678101048180767753978252653056446779764345393012563509749934197033076',
  '10045613637697249323135166490375460139074861672341628616782380857881522268468',
  '25530287906622499321395325254670244185066000062279424936955928730178815134197',
  '12066939866218700463762737766793051267694081970275660541174799838126140369589',
  '27551614135143950462022896531087835313685220360213456861348347710423433235318',
  '14088266094740151604390309043210642396313302268209692465567218818370758470710',
  '624918054336352746757721555333449478941384176205928069786089926318083706102',
  '11277236140611005090521761246344633707381613505964265666892028428155472931328',
  '28672049823629031914825741970003535883834839531849861562488739926042490078740',
  '15208701783225233057193154482126342966462921439846097166707611033989815314132',
  '1745353742821434199560566994249150049091003347842332770926482141937140549524',
  '17230028011746684197820725758543934095082141737780129091100030014234433415253',
  '3766679971342885340188138270666741177710223645776364695318901122181758650645',
  '19251354240268135338448297034961525223701362035714161015492448994479051516374',
  '5788006199864336480815709547084332306329443943710396619711320102426376751766',
  '21272680468789586479075868311379116352320582333648192939884867974723669617495',
  '7809332428385787621443280823501923434948664241644428544103739082670994852887',
  '18461650514660439965207320514513107663388893571402766141209677584508384078113',
  '6908441888349417933618554986000032876479063115346801320851712318045433595188',
  '22393116157274667931878713750294816922470201505284597641025260190342726460917',
  '8929768116870869074246126262417624005098283413280833245244131298290051696309',
  '24414442385796119072506285026712408051089421803218629565417679170587344562038',
  '10951094345392320214873697538835215133717503711214865169636550278534669797430',
  '26435768614317570213133856303129999179708642101152661489810098150831962663159',
  '12972420573913771355501268815252806262336724009148897094028969258779287898551',
  '28457094842839021353761427579547590308327862399086693414202517131076580764280',
  '14993746802435222496128840091670397390955944307082929018421388239023905999672',
  '12422827447213129718210939698147903260416831045184117845155491735691102342644'
];

// Create trees and log roots
console.log('Creating individual trees for each addition:');
values.forEach((value, index) => {
  const tree = createAndLogTree([value]);
  console.log(`Tree ${index + 1} created with root:`);
  logRoot(tree);
});

console.log('Creating batch trees:');
for (let i = 0; i < values.length; i += 2) {
  const batch = values.slice(i, i + 2);
  const tree = createAndLogTree(batch);
  console.log(`Batch Tree created with roots from values: ${batch}`);
  logRoot(tree);
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

