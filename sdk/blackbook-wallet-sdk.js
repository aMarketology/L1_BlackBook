/**
 * BlackBook L1 Wallet SDK - Fork Architecture V2
 * 
 * Host-Proof Security Model:
 *   password → forkPassword()
 *   ├─ authKey = SHA256(AUTH_DOMAIN + password + auth_salt)  → sent to server
 *   └─ vaultKey = Argon2id(VAULT_DOMAIN + password + vault_salt) → NEVER sent
 * 
 * Server stores bcrypt(auth_key) but CANNOT decrypt vault.
 * 
 * Dependencies: tweetnacl, argon2-browser (browser), tweetnacl (node)
 * 
 * Usage (Browser):
 *   <script src="https://cdn.jsdelivr.net/npm/tweetnacl/nacl-fast.min.js"></script>
 *   <script src="blackbook-wallet-sdk.js"></script>
 * 
 * Usage (Node.js):
 *   const { BlackBookWallet } = require('./blackbook-wallet-sdk.js');
 */

// ═══════════════════════════════════════════════════════════════
// ENVIRONMENT DETECTION & POLYFILLS
// ═══════════════════════════════════════════════════════════════

// Node.js compatibility - load tweetnacl if not already global
let nacl;
if (typeof window === 'undefined' && typeof require !== 'undefined') {
  // Node.js environment
  try {
    nacl = require('tweetnacl');
    // Use Node.js crypto for Web Crypto API compatibility
    const nodeCrypto = require('crypto');
    if (typeof globalThis.crypto === 'undefined') {
      globalThis.crypto = nodeCrypto.webcrypto;
    }
  } catch (e) {
    console.warn('tweetnacl not found. Install with: npm install tweetnacl');
  }
} else if (typeof window !== 'undefined' && window.nacl) {
  // Browser with global nacl
  nacl = window.nacl;
}

// ═══════════════════════════════════════════════════════════════
// CONSTANTS & CONFIGURATION
// ═══════════════════════════════════════════════════════════════

const CHAIN_ID_L1 = 0x01;
const CHAIN_ID_L2 = 0x02;

// Domain separation for Fork Architecture
const AUTH_FORK_DOMAIN = "BLACKBOOK_AUTH_V2";
const VAULT_FORK_DOMAIN = "BLACKBOOK_VAULT_V2";

// Argon2id parameters (balanced security/performance)
const ARGON2_CONFIG = {
  time: 3,        // iterations
  mem: 65536,     // 64 MB
  parallelism: 4,
  hashLen: 32,    // 256 bits
  type: 2         // Argon2id
};

// Canonical payload schemas for deterministic signing
const PAYLOAD_SCHEMAS = {
  transfer: ['from', 'to', 'amount', 'timestamp', 'nonce'],
  bridge_deposit: ['from', 'amount', 'timestamp', 'nonce'],
  bridge_withdraw: ['to', 'amount', 'timestamp', 'nonce'],
  social_post: ['content', 'author', 'timestamp', 'nonce']
};

// ═══════════════════════════════════════════════════════════════
// BIP39 WORDLIST (2048 words)
// ═══════════════════════════════════════════════════════════════

const BIP39_WORDLIST = [
  'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
  'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
  'action','actor','actress','actual','adapt','add','addict','address','adjust','admit',
  'adult','advance','advice','aerobic','affair','afford','afraid','again','age','agent',
  'agree','ahead','aim','air','airport','aisle','alarm','album','alcohol','alert',
  'alien','all','alley','allow','almost','alone','alpha','already','also','alter',
  'always','amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger',
  'angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique',
  'anxiety','any','apart','apology','appear','apple','approve','april','arch','arctic',
  'area','arena','argue','arm','armed','armor','army','around','arrange','arrest',
  'arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset',
  'assist','assume','asthma','athlete','atom','attack','attend','attitude','attract','auction',
  'audit','august','aunt','author','auto','autumn','average','avocado','avoid','awake',
  'aware','away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge',
  'bag','balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain',
  'barrel','base','basic','basket','battle','beach','bean','beauty','because','become',
  'beef','before','begin','behave','behind','believe','below','belt','bench','benefit',
  'best','betray','better','between','beyond','bicycle','bid','bike','bind','biology',
  'bird','birth','bitter','black','blackbook', 'blade','blame','blanket','blast','bleak','bless',
  'blind','blood','blossom','blouse','blue','blur','blush','board','boat','body',
  'boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss',
  'bottom','bounce','box','boy','bracket','brain','brand','brass','brave','bread',
  'breeze','brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze',
  'broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb',
  'bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy',
  'butter','buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call',
  'calm','camera','camp','can','canal','cancel','candy','cannon','canoe','canvas',
  'canyon','capable','capital','captain','car','carbon','card','cargo','carpet','carry',
  'cart','case','cash','casino','castle','casual','cat','catalog','catch','category',
  'cattle','caught','cause','caution','cave','ceiling','celery','cement','census','century',
  'cereal','certain','chair','chalk','champion','change','chaos','chapter','charge','chase',
  'chat','cheap','check','cheese','chef','cherry','chest','chicken','chief','child',
  'chimney','choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle',
  'citizen','city','civil','claim','clap','clarify','claw','clay','clean','clerk',
  'clever','click','client','cliff','climb','clinic','clip','clock','clog','close',
  'cloth','cloud','clown','club','clump','cluster','clutch','coach','coast','coconut',
  'code','coffee','coil','coin','collect','color','column','combine','come','comfort',
  'comic','common','company','concert','conduct','confirm','congress','connect','consider','control',
  'convince','cook','cool','copper','copy','coral','core','corn','correct','cost',
  'cotton','couch','country','couple','course','cousin','cover','coyote','crack','cradle',
  'craft','cram','crane','crash','crater','crawl','crazy','cream','credit','creek',
  'crew','cricket','crime','crisp','critic','crop','cross','crouch','crowd','crucial',
  'cruel','cruise','crumble','crunch','crush','cry','crystal','cube','culture','cup',
  'cupboard','curious','current','curtain','curve','cushion','custom','cute','cycle','dad',
  'damage','damp','dance','danger','daring','dash','daughter','dawn','day','deal',
  'debate','debris','decade','december','decide','decline','decorate','decrease','deer','defense',
  'define','defy','degree','delay','deliver','demand','demise','denial','dentist','deny',
  'depart','depend','deposit','depth','deputy','derive','describe','desert','design','desk',
  'despair','destroy','detail','detect','develop','device','devote','diagram','dial','diamond',
  'diary','dice','diesel','diet','differ','digital','dignity','dilemma','dinner','dinosaur',
  'direct','dirt','disagree','discover','disease','dish','dismiss','disorder','display','distance',
  'divert','divide','divorce','dizzy','doctor','document','dog','doll','dolphin','domain',
  'donate','donkey','donor','door','dose','double','dove','draft','dragon','drama',
  'drastic','draw','dream','dress','drift','drill','drink','drip','drive','drop',
  'drum','dry','duck','dumb','dune','during','dust','dutch','duty','dwarf',
  'dynamic','eager','eagle','early','earn','earth','easily','east','easy','echo',
  'ecology','economy','edge','edit','educate','effort','egg','eight','either','elbow',
  'elder','electric','elegant','element','elephant','elevator','elite','else','embark','embody',
  'embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless',
  'endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enough',
  'enrich','enroll','ensure','enter','entire','entry','envelope','episode','equal','equip',
  'era','erase','erode','erosion','error','erupt','escape','essay','essence','estate',
  'eternal','ethics','evidence','evil','evoke','evolve','exact','example','excess','exchange',
  'excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile','exist','exit',
  'exotic','expand','expect','expire','explain','expose','express','extend','extra','eye',
  'eyebrow','fabric','face','faculty','fade','faint','faith','fall','false','fame',
  'family','famous','fan','fancy','fantasy','farm','fashion','fat','fatal','father',
  'fatigue','fault','favorite','feature','february','federal','fee','feed','feel','female',
  'fence','festival','fetch','fever','few','fiber','fiction','field','figure','file',
  'film','filter','final','find','fine','finger','finish','fire','firm','first',
  'fiscal','fish','fit','fitness','fix','flag','flame','flash','flat','flavor',
  'flee','flight','flip','float','flock','floor','flower','fluid','flush','fly',
  'foam','focus','fog','foil','fold','follow','food','foot','force','forest',
  'forget','fork','fortune','forum','forward','fossil','foster','found','fox','fragile',
  'frame','frequent','fresh','friend','fringe','frog','front','frost','frown','frozen',
  'fruit','fuel','fun','funny','furnace','fury','future','gadget','gain','galaxy',
  'gallery','game','gap','garage','garbage','garden','garlic','garment','gas','gasp',
  'gate','gather','gauge','gaze','general','genius','genre','gentle','genuine','gesture',
  'ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance',
  'glare','glass','glide','glimpse','globe','gloom','glory','glove','glow','glue',
  'goat','goddess','gold','good','goose','gorilla','gospel','gossip','govern','gown',
  'grab','grace','grain','grant','grape','grass','gravity','great','green','grid',
  'grief','grit','grocery','group','grow','grunt','guard','guess','guide','guilt',
  'guitar','gun','gym','habit','hair','half','hammer','hamster','hand','happy',
  'harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health',
  'heart','heavy','hedgehog','height','hello','helmet','help','hen','hero','hidden',
  'high','hill','hint','hip','hire','history','hobby','hockey','hold','hole',
  'holiday','hollow','home','honey','hood','hope','horn','horror','horse','hospital',
  'host','hotel','hour','hover','hub','huge','human','humble','humor','hundred',
  'hungry','hunt','hurdle','hurry','hurt','husband','hybrid','ice','icon','idea',
  'identify','idle','ignore','ill','illegal','illness','image','imitate','immense','immune',
  'impact','impose','improve','impulse','inch','include','income','increase','index','indicate',
  'indoor','industry','infant','inflict','inform','inhale','inherit','initial','inject','injury',
  'inmate','inner','innocent','input','inquiry','insane','insect','inside','inspire','install',
  'intact','interest','into','invest','invite','involve','iron','island','isolate','issue',
  'item','ivory','jacket','jaguar','jar','jazz','jealous','jeans','jelly','jewel',
  'job','join','joke','journey','joy','judge','juice','jump','jungle','junior',
  'junk','just','kangaroo','keen','keep','ketchup','key','kick','kid','kidney',
  'kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi','knee','knife',
  'knock','know','lab','label','labor','ladder','lady','lake','lamp','language',
  'laptop','large','later','latin','laugh','laundry','lava','law','lawn','lawsuit',
  'layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal',
  'legend','leisure','lemon','lend','length','lens','leopard','lesson','letter','level',
  'liar','liberty','library','license','life','lift','light','like','limb','limit',
  'link','lion','liquid','list','little','live','lizard','load','loan','lobster',
  'local','lock','logic','lonely','long','loop','lottery','loud','lounge','love',
  'loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics','machine','mad',
  'magic','magnet','maid','mail','main','major','make','mammal','man','manage',
  'mandate','mango','mansion','manual','maple','marble','march','margin','marine','market',
  'marriage','mask','mass','master','match','material','math','matrix','matter','maximum',
  'maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt',
  'member','memory','mention','menu','mercy','merge','merit','merry','mesh','message',
  'metal','method','middle','midnight','milk','million','mimic','mind','minimum','minor',
  'minute','miracle','mirror','misery','miss','mistake','mix','mixed','mixture','mobile',
  'model','modify','mom','moment','monitor','monkey','monster','month','moon','moral',
  'more','morning','mosquito','mother','motion','motor','mountain','mouse','move','movie',
  'much','muffin','mule','multiply','muscle','museum','mushroom','music','must','mutual',
  'myself','mystery','myth','naive','name','napkin','narrow','nasty','nation','nature',
  'near','neck','need','negative','neglect','neither','nephew','nerve','nest','net',
  'network','neutral','never','news','next','nice','night','noble','noise','nominee',
  'noodle','normal','north','nose','notable','note','nothing','notice','novel','now',
  'nuclear','number','nurse','nut','oak','obey','object','oblige','obscure','observe',
  'obtain','obvious','occur','ocean','october','odor','off','offer','office','often',
  'oil','okay','old','olive','olympic','omit','once','one','onion','online',
  'only','open','opera','opinion','oppose','option','orange','orbit','orchard','order',
  'ordinary','organ','orient','original','orphan','ostrich','other','outdoor','outer','output',
  'outside','oval','oven','over','own','owner','oxygen','oyster','ozone','pact',
  'paddle','page','pair','palace','palm','panda','panel','panic','panther','paper',
  'parade','parent','park','parrot','party','pass','patch','path','patient','patrol',
  'pattern','pause','pave','payment','peace','peanut','pear','peasant','pelican','pen',
  'penalty','pencil','people','pepper','perfect','permit','person','pet','phone','photo',
  'phrase','physical','piano','picnic','picture','piece','pig','pigeon','pill','pilot',
  'pink','pioneer','pipe','pistol','pitch','pizza','place','planet','plastic','plate',
  'play','please','pledge','pluck','plug','plunge','poem','poet','point','polar',
  'pole','police','pond','pony','pool','popular','portion','position','possible','post',
  'potato','pottery','poverty','powder','power','practice','praise','predict','prefer','prepare',
  'present','pretty','prevent','price','pride','primary','print','priority','prison','private',
  'prize','problem','process','produce','profit','program','project','promote','proof','property',
  'prosper','protect','proud','provide','public','pudding','pull','pulp','pulse','pumpkin',
  'punch','pupil','puppy','purchase','purity','purpose','purse','push','put','puzzle',
  'pyramid','quality','quantum','quarter','question','quick','quit','quiz','quote','rabbit',
  'raccoon','race','rack','radar','radio','rail','rain','raise','rally','ramp',
  'ranch','random','range','rapid','rare','rate','rather','raven','raw','razor',
  'ready','real','reason','rebel','rebuild','recall','receive','recipe','record','recycle',
  'reduce','reflect','reform','refuse','region','regret','regular','reject','relax','release',
  'relief','rely','remain','remember','remind','remove','render','renew','rent','reopen',
  'repair','repeat','replace','report','require','rescue','resemble','resist','resource','response',
  'result','retire','retreat','return','reunion','reveal','review','reward','rhythm','rib',
  'ribbon','rice','rich','ride','ridge','rifle','right','rigid','ring','riot',
  'ripple','risk','ritual','rival','river','road','roast','robot','robust','rocket',
  'romance','roof','rookie','room','rose','rotate','rough','round','route','royal',
  'rubber','rude','rug','rule','run','runway','rural','sad','saddle','sadness',
  'safe','sail','salad','salmon','salon','salt','salute','same','sample','sand',
  'satisfy','satoshi','sauce','sausage','save','say','scale','scan','scare','scatter',
  'scene','scheme','school','science','scissors','scorpion','scout','scrap','screen','script',
  'scrub','sea','search','season','seat','second','secret','section','security','seed',
  'seek','segment','select','sell','seminar','senior','sense','sentence','series','service',
  'session','settle','setup','seven','shadow','shaft','shallow','share','shed','shell',
  'sheriff','shield','shift','shine','ship','shiver','shock','shoe','shoot','shop',
  'short','shoulder','shove','shrimp','shrug','shuffle','shy','sibling','sick','side',
  'siege','sight','sign','silent','silk','silly','silver','similar','simple','since',
  'sing','siren','sister','situate','six','size','skate','sketch','ski','skill',
  'skin','skirt','skull','slab','slam','sleep','slender','slice','slide','slight',
  'slim','slogan','slot','slow','slush','small','smart','smile','smoke','smooth',
  'snack','snake','snap','sniff','snow','soap','soccer','social','sock','soda',
  'soft','solar','soldier','solid','solution','solve','someone','song','soon','sorry',
  'sort','soul','sound','soup','source','south','space','spare','spatial','spawn',
  'speak','special','speed','spell','spend','sphere','spice','spider','spike','spin',
  'spirit','split','spoil','sponsor','spoon','sport','spot','spray','spread','spring',
  'spy','square','squeeze','squirrel','stable','stadium','staff','stage','stairs','stamp',
  'stand','start','state','stay','steak','steel','stem','step','stereo','stick',
  'still','sting','stock','stomach','stone','stool','story','stove','strategy','street',
  'strike','strong','struggle','student','stuff','stumble','style','subject','submit','subway',
  'success','such','sudden','suffer','sugar','suggest','suit','summer','sun','sunny',
  'sunset','super','supply','supreme','sure','surface','surge','surprise','surround','survey',
  'suspect','sustain','swallow','swamp','swap','swarm','swear','sweet','swift','swim',
  'swing','switch','sword','symbol','symptom','syrup','system','table','tackle','tag',
  'tail','talent','talk','tank','tape','target','task','taste','tattoo','taxi',
  'teach','team','tell','ten','tenant','tennis','tent','term','test','text',
  'thank','that','theme','then','theory','there','they','thing','this','thought',
  'three','thrive','throw','thumb','thunder','ticket','tide','tiger','tilt','timber',
  'time','tiny','tip','tired','tissue','title','toast','tobacco','today','toddler',
  'toe','together','toilet','token','tomato','tomorrow','tone','tongue','tonight','tool',
  'tooth','top','topic','topple','torch','tornado','tortoise','toss','total','tourist',
  'toward','tower','town','toy','track','trade','traffic','tragic','train','transfer',
  'trap','trash','travel','tray','treat','tree','trend','trial','tribe','trick',
  'trigger','trim','trip','trophy','trouble','truck','true','truly','trumpet','trust',
  'truth','try','tube','tuition','tumble','tuna','tunnel','turkey','turn','turtle',
  'twelve','twenty','twice','twin','twist','two','type','typical','ugly','umbrella',
  'unable','unaware','uncle','uncover','under','undo','unfair','unfold','unhappy','uniform',
  'unique','unit','universe','unknown','unlock','until','unusual','unveil','update','upgrade',
  'uphold','upon','upper','upset','urban','urge','usage','use','used','useful',
  'useless','usual','utility','vacant','vacuum','vague','valid','valley','valve','van',
  'vanish','vapor','various','vast','vault','vehicle','velvet','vendor','venture','venue',
  'verb','verify','version','very','vessel','veteran','viable','vibrant','vicious','victory',
  'video','view','village','vintage','violin','virtual','virus','visa','visit','visual',
  'vital','vivid','vocal','voice','void','volcano','volume','vote','voyage','wage',
  'wagon','wait','walk','wall','walnut','want','warfare','warm','warrior','wash',
  'wasp','waste','water','wave','way','wealth','weapon','wear','weasel','weather',
  'web','wedding','weekend','weird','welcome','west','wet','whale','what','wheat',
  'wheel','when','where','whip','whisper','wide','width','wife','wild','will',
  'win','window','wine','wing','wink','winner','winter','wire','wisdom','wise',
  'wish','witness','wolf','woman','wonder','wood','wool','word','work','world',
  'worry','worth','wrap','wreck','wrestle','wrist','write','wrong','yard','year',
  'yellow','you','young','youth','zebra','zero','zone','zoo'
];

// ═══════════════════════════════════════════════════════════════
// TEST ACCOUNTS (Correctly derived from seeds - for development/testing)
// Address = L1_ + SHA256(pubkey)[0..20].toUpperCase()
// ═══════════════════════════════════════════════════════════════

const TEST_ACCOUNTS = {
  // Alice: Primary test account with 20,000 BB starting balance
  ALICE: {
    username: 'alice_test',
    email: 'alice@blackbook.test',
    address: 'L1_52882D768C0F3E7932AAD1813CF8B19058D507A8',
    seed: '18f2c2e3bcb7a4b5329cfed4bd79bf17df4d47aa1888a6b3d1a1450fb53a8a24',
    publicKey: 'c0e349153cbc75e9529b5f1963205cab783463c6835c826a7587e0e0903c6705',
    startingBalance: 20000.0,
  },
  
  // Bob: Secondary test account with 10,000 BB starting balance  
  BOB: {
    username: 'bob_test',
    email: 'bob@blackbook.test',
    address: 'L1_5DB4B525FB40D6EA6BFD24094C2BC24984BAC433',
    seed: 'e4ac49e5a04ef7dfc6e1a838fdf14597f2d514d0029a82cb45c916293487c25b',
    publicKey: '582420216093fcff65b0eec2ca2c8227dfc2b6b7428110f36c3fc1349c4b2f5a',
    startingBalance: 10000.0,
  },
  
  // Dealer: House bankroll account with 100,000 BB
  DEALER: {
    username: 'dealer',
    address: 'L1_EB8B2F3A7F97A929D3B8C7E449432BC00D5097BC',
    seed: 'd4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d',
    publicKey: '65328794ed4a81cc2a92b93738c22a545f066cc6c0b6a72aa878cfa289f0ba32',
    startingBalance: 100000.0,
  }
};

// ═══════════════════════════════════════════════════════════════
// CRYPTOGRAPHIC UTILITIES
// ═══════════════════════════════════════════════════════════════

/**
 * Generate cryptographically secure random bytes
 */
function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

/**
 * Convert bytes to hex string
 */
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Convert hex string to bytes
 */
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * SHA-256 hash (async)
 */
async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = typeof data === 'string' ? encoder.encode(data) : data;
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  return bytesToHex(new Uint8Array(hashBuffer));
}

/**
 * Generate UUID v4 nonce
 */
function generateNonce() {
  return crypto.randomUUID();
}

// ═══════════════════════════════════════════════════════════════
// FORK ARCHITECTURE - Password Splitting
// ═══════════════════════════════════════════════════════════════

/**
 * Fork password into auth_key and vault_key
 * 
 * @param {string} password - User's password
 * @param {string} authSalt - Salt for auth_key (64 hex chars)
 * @param {string} vaultSalt - Salt for vault_key (64 hex chars)
 * @returns {Promise<{authKey: string, vaultKey: Uint8Array}>}
 */
async function forkPassword(password, authSalt, vaultSalt) {
  // FORK A: Auth Key (fast SHA256 - server will bcrypt this again)
  const authDomain = AUTH_FORK_DOMAIN + authSalt;
  const authKey = await sha256(authDomain + password);
  
  // FORK B: Vault Key (slow Argon2id - never sent to server)
  const vaultDomain = VAULT_FORK_DOMAIN + vaultSalt;
  const vaultKeyHash = await argon2.hash({
    pass: vaultDomain + password,
    salt: vaultSalt,
    ...ARGON2_CONFIG
  });
  
  return {
    authKey,
    vaultKey: vaultKeyHash.hash
  };
}

// ═══════════════════════════════════════════════════════════════
// VAULT ENCRYPTION (AES-256-GCM)
// ═══════════════════════════════════════════════════════════════

/**
 * Encrypt vault with AES-256-GCM (vault_salt in AAD)
 * 
 * @param {string} mnemonic - BIP39 mnemonic to encrypt
 * @param {Uint8Array} vaultKey - Derived vault key (32 bytes)
 * @param {string} vaultSalt - Vault salt (embedded in AAD)
 * @returns {Promise<{ciphertext: string, nonce: string}>}
 */
async function encryptVault(mnemonic, vaultKey, vaultSalt) {
  const nonce = randomBytes(12);
  const encoder = new TextEncoder();
  const data = encoder.encode(mnemonic);
  
  // Import vault_key for Web Crypto API
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    vaultKey,
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  );
  
  // Encrypt with vault_salt in AAD (Additional Authenticated Data)
  const aad = encoder.encode(vaultSalt);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad
    },
    cryptoKey,
    data
  );
  
  return {
    ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext))),
    nonce: bytesToHex(nonce)
  };
}

/**
 * Decrypt vault with AES-256-GCM
 * 
 * @param {string} ciphertext - Base64 encoded ciphertext
 * @param {string} nonceHex - Nonce (24 hex chars)
 * @param {Uint8Array} vaultKey - Derived vault key (32 bytes)
 * @param {string} vaultSalt - Vault salt (from AAD)
 * @returns {Promise<string>} - Decrypted mnemonic
 */
async function decryptVault(ciphertext, nonceHex, vaultKey, vaultSalt) {
  const nonce = hexToBytes(nonceHex);
  const ciphertextBytes = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    vaultKey,
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  );
  
  const encoder = new TextEncoder();
  const aad = encoder.encode(vaultSalt);
  
  const decrypted = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: nonce,
      additionalData: aad
    },
    cryptoKey,
    ciphertextBytes
  );
  
  return new TextDecoder().decode(decrypted);
}

// ═══════════════════════════════════════════════════════════════
// ED25519 SIGNING (Canonical Payloads)
// ═══════════════════════════════════════════════════════════════

/**
 * Create canonical payload hash for deterministic signing
 * 
 * @param {string} operationType - e.g., "transfer", "bridge_deposit"
 * @param {object} fields - Payload fields
 * @returns {Promise<string>} - SHA256 hash of ordered fields
 */
async function createCanonicalPayloadHash(operationType, fields) {
  const schema = PAYLOAD_SCHEMAS[operationType];
  if (!schema) {
    throw new Error(`Unknown operation type: ${operationType}`);
  }
  
  // Concatenate fields in schema order
  const orderedValues = schema.map(key => {
    const value = fields[key];
    if (value === undefined) throw new Error(`Missing field: ${key}`);
    return typeof value === 'object' ? JSON.stringify(value) : String(value);
  });
  
  const canonical = orderedValues.join('|');
  return await sha256(canonical);
}

/**
 * Sign request with Ed25519 (V2 canonical format)
 * 
 * @param {Uint8Array} privateKey - Ed25519 private key (32 bytes)
 * @param {string} operationType - Operation type
 * @param {object} payloadFields - Payload data
 * @param {string} requestPath - API endpoint path
 * @param {number} chainId - Chain ID (0x01 = L1, 0x02 = L2)
 * @returns {Promise<object>} - Signed request object
 */
async function signRequest(privateKey, operationType, payloadFields, requestPath, chainId = CHAIN_ID_L1) {
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = generateNonce();
  
  // Add timestamp and nonce to payload
  const fullPayload = { ...payloadFields, timestamp, nonce };
  
  // Create canonical hash
  const payloadHash = await createCanonicalPayloadHash(operationType, fullPayload);
  
  // Construct signing message with domain separation
  const domainPrefix = `BLACKBOOK_L${chainId}_${requestPath}`;
  const message = `${domainPrefix}\n${payloadHash}\n${timestamp}\n${nonce}`;
  
  // Sign with Ed25519
  const keyPair = nacl.sign.keyPair.fromSecretKey(privateKey);
  const messageBytes = new TextEncoder().encode(message);
  const signature = nacl.sign.detached(messageBytes, privateKey);
  
  return {
    public_key: bytesToHex(keyPair.publicKey),
    payload_hash: payloadHash,
    payload_fields: fullPayload,
    operation_type: operationType,
    schema_version: 2,
    timestamp,
    nonce,
    chain_id: chainId,
    request_path: requestPath,
    signature: bytesToHex(signature)
  };
}

// ═══════════════════════════════════════════════════════════════
// WALLET CLASS
// ═══════════════════════════════════════════════════════════════

class BlackBookWallet {
  /**
   * Create a new BlackBook wallet instance
   * 
   * @param {string} l1Url - L1 blockchain server URL (default: localhost:8080)
   * @param {string} supabaseUrl - Supabase project URL for auth/vault storage
   * @param {string} supabaseKey - Supabase anon key
   */
  constructor(l1Url = 'http://localhost:8080', supabaseUrl = null, supabaseKey = null) {
    this.apiUrl = l1Url;  // L1 blockchain server (balance, transfer, bridge)
    this.supabaseUrl = supabaseUrl;  // Supabase (register, login, vault)
    this.supabaseKey = supabaseKey;
    this.mnemonic = null;
    this.privateKey = null;
    this.publicKey = null;
    this.address = null;
    this.username = null;
  }

  /**
   * Register new wallet with Fork Architecture V2
   * 
   * NOTE: This stores the encrypted vault in Supabase, NOT the L1 server.
   * The L1 server only handles blockchain operations (balances, transfers).
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @param {string} mnemonic - BIP39 mnemonic (optional, generates if not provided)
   * @returns {Promise<object>} - Registration result
   */
  async register(username, password, mnemonic = null) {
    // Validate inputs
    if (!username || username.length < 3) {
      throw new Error('Username must be at least 3 characters');
    }
    if (!password || password.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }
    
    // Generate or validate mnemonic
    if (!mnemonic) {
      mnemonic = await this._generateMnemonic();
    }
    
    // Derive Ed25519 keypair from mnemonic
    const seed = await this._mnemonicToSeed(mnemonic);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    
    this.mnemonic = mnemonic;
    this.privateKey = keyPair.secretKey;
    this.publicKey = keyPair.publicKey;
    this.address = 'bb1_' + bytesToHex(keyPair.publicKey);
    this.username = username;
    
    // Generate salts for Fork Architecture
    const authSalt = bytesToHex(randomBytes(32));
    const vaultSalt = bytesToHex(randomBytes(32));
    
    // Fork password
    const { authKey, vaultKey } = await forkPassword(password, authSalt, vaultSalt);
    
    // Encrypt vault with vault_key (vault_salt in AAD)
    const { ciphertext, nonce } = await encryptVault(mnemonic, vaultKey, vaultSalt);
    
    // Register with server
    const response = await fetch(`${this.apiUrl}/auth/register`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        public_key: bytesToHex(this.publicKey),
        encrypted_vault: {
          version: 2,
          salt: vaultSalt,  // For V2, this is ignored (salt in AAD)
          ciphertext,
          nonce,
          address: this.address,
          created_at: Date.now()
        },
        auth_key: authKey,
        auth_salt: authSalt,
        fork_version: 2
      })
    });
    
    return await response.json();
  }

  /**
   * Login with Fork Architecture V2
   * 
   * @param {string} username - Username
   * @param {string} password - Password
   * @returns {Promise<object>} - Login result
   */
  async login(username, password) {
    // Step 1: Get auth_salt from server
    const saltResponse = await fetch(`${this.apiUrl}/auth/salt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    
    const saltData = await saltResponse.json();
    if (!saltData.success) {
      throw new Error(saltData.error || 'Failed to get auth salt');
    }
    
    const { auth_salt, fork_version } = saltData;
    
    if (fork_version < 2) {
      throw new Error('V1 vaults require migration. Please use migrateToV2()');
    }
    
    // Step 2: Derive auth_key ONLY (we don't have vault_salt yet)
    // Use empty string for vaultSalt since we only need authKey for authentication
    const { authKey } = await forkPassword(password, auth_salt, '');
    
    // Step 3: Authenticate and get encrypted vault + vault_salt
    const loginResponse = await fetch(`${this.apiUrl}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        auth_key: authKey
      })
    });
    
    const loginData = await loginResponse.json();
    if (!loginData.success) {
      throw new Error(loginData.error || 'Login failed');
    }
    
    // Step 4: Extract vault_salt from server response and decrypt
    const { encrypted_blob, nonce, vault_salt } = loginData;
    
    if (!vault_salt) {
      throw new Error('Server did not return vault_salt. Database may be corrupted.');
    }
    
    // Now derive the correct vaultKey using the REAL vault_salt from server
    const { vaultKey } = await forkPassword(password, auth_salt, vault_salt);
    
    // Decrypt vault (vault_salt is embedded in AAD for integrity)
    let mnemonic;
    try {
      mnemonic = await decryptVault(encrypted_blob, nonce, vaultKey, vault_salt);
    } catch (err) {
      throw new Error('Vault decryption failed. Wrong password or corrupted vault.');
    }
    
    // Restore wallet state
    const seed = await this._mnemonicToSeed(mnemonic);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    
    this.mnemonic = mnemonic;
    this.privateKey = keyPair.secretKey;
    this.publicKey = keyPair.publicKey;
    this.address = 'bb1_' + bytesToHex(keyPair.publicKey);
    this.username = username;
    
    return { success: true, address: this.address };
  }

  /**
   * Send signed transfer request
   */
  async transfer(to, amount) {
    if (!this.privateKey) throw new Error('Wallet not initialized');
    
    const signedRequest = await signRequest(
      this.privateKey,
      'transfer',
      { from: this.address, to, amount },
      '/transfer',
      CHAIN_ID_L1
    );
    
    const response = await fetch(`${this.apiUrl}/transfer`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(signedRequest)
    });
    
    return await response.json();
  }

  /**
   * Get wallet balance (PUBLIC - no auth required)
   */
  async getBalance() {
    if (!this.address) throw new Error('Wallet not initialized');
    
    // Use public balance endpoint - no signature required
    const response = await fetch(`${this.apiUrl}/balance/${this.address}`);
    return await response.json();
  }

  /**
   * Get balance for any address (static method)
   */
  static async getBalanceFor(apiUrl, address) {
    const response = await fetch(`${apiUrl}/balance/${address}`);
    return await response.json();
  }

  /**
   * Bridge tokens to L2 (lock on L1)
   */
  async bridgeToL2(amount) {
    if (!this.privateKey) throw new Error('Wallet not initialized');
    
    const signedRequest = await signRequest(
      this.privateKey,
      'bridge_deposit',
      { from: this.address, amount },
      '/bridge/initiate',
      CHAIN_ID_L1
    );
    
    const response = await fetch(`${this.apiUrl}/bridge/initiate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ...signedRequest,
        target_layer: 'L2',
      })
    });
    
    return await response.json();
  }

  /**
   * Get bridge status
   */
  async getBridgeStatus(lockId) {
    const response = await fetch(`${this.apiUrl}/bridge/status/${lockId}`);
    return await response.json();
  }

  /**
   * Get transaction by ID from explorer
   */
  async getTransaction(txId) {
    const response = await fetch(`${this.apiUrl}/explorer/tx/${txId}`);
    return await response.json();
  }

  /**
   * Get account transaction history from explorer
   */
  async getAccountHistory(limit = 50, offset = 0) {
    if (!this.address) throw new Error('Wallet not initialized');
    
    const response = await fetch(
      `${this.apiUrl}/explorer/account/${this.address}/history?limit=${limit}&offset=${offset}`
    );
    return await response.json();
  }

  /**
   * Get block by slot from explorer
   */
  async getBlock(slot) {
    const response = await fetch(`${this.apiUrl}/explorer/block/${slot}`);
    return await response.json();
  }

  /**
   * Get latest block header (for light clients)
   */
  async getLatestHeader() {
    const response = await fetch(`${this.apiUrl}/headers/latest`);
    return await response.json();
  }

  /**
   * Get Merkle proof for account (for light client verification)
   */
  async getAccountProof() {
    if (!this.address) throw new Error('Wallet not initialized');
    
    const response = await fetch(`${this.apiUrl}/proof/account/${this.address}`);
    return await response.json();
  }

  /**
   * Check if wallet needs recovery after password reset
   * @param {string} username - Username to check
   * @returns {Promise<{needs_recovery: boolean}>}
   */
  async checkRecoveryStatus(username) {
    const response = await fetch(`${this.apiUrl}/wallet/recovery-status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    return await response.json();
  }

  /**
   * Recover wallet after password reset using SSS shares
   * 
   * Flow:
   * 1. User resets password via Supabase (triggers needs_recovery flag)
   * 2. User provides PIN + backup share (from cloud/email)
   * 3. Server combines with its share to recover mnemonic
   * 4. Client re-encrypts vault with new password
   * 
   * @param {string} username - Username
   * @param {string} newPassword - New password (after reset)
   * @param {string} pin - 6-digit PIN used to encrypt backup shares
   * @param {string} encryptedBackupShare - PIN-encrypted share from cloud/email
   * @returns {Promise<object>} - Recovery result
   */
  async recoverAfterPasswordReset(username, newPassword, pin, encryptedBackupShare) {
    // Validate inputs
    if (!pin || pin.length !== 6 || !/^\d+$/.test(pin)) {
      throw new Error('PIN must be exactly 6 digits');
    }
    if (!newPassword || newPassword.length < 8) {
      throw new Error('Password must be at least 8 characters');
    }
    
    // Step 1: Get auth_salt from server
    const saltResponse = await fetch(`${this.apiUrl}/auth/salt`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username })
    });
    
    const saltData = await saltResponse.json();
    if (!saltData.success) {
      throw new Error(saltData.error || 'Failed to get auth salt');
    }
    
    // Step 2: Request SSS recovery with encrypted backup share
    const recoveryResponse = await fetch(`${this.apiUrl}/wallet/recover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        pin,
        encrypted_backup_share: encryptedBackupShare
      })
    });
    
    const recoveryData = await recoveryResponse.json();
    if (!recoveryData.success) {
      throw new Error(recoveryData.error || 'SSS recovery failed. Check PIN and backup share.');
    }
    
    // Step 3: Server returns recovered mnemonic (transmitted securely)
    const { mnemonic, public_key: expectedPublicKey } = recoveryData;
    
    // Step 4: Verify recovered mnemonic matches expected public key
    const seed = await this._mnemonicToSeed(mnemonic);
    const keyPair = nacl.sign.keyPair.fromSeed(seed);
    const recoveredPublicKey = bytesToHex(keyPair.publicKey);
    
    if (recoveredPublicKey !== expectedPublicKey) {
      throw new Error('Recovered wallet does not match. SSS shares may be corrupted.');
    }
    
    // Step 5: Generate new salts for Fork Architecture with new password
    const newAuthSalt = bytesToHex(randomBytes(32));
    const newVaultSalt = bytesToHex(randomBytes(32));
    
    // Step 6: Fork new password
    const { authKey, vaultKey } = await forkPassword(newPassword, newAuthSalt, newVaultSalt);
    
    // Step 7: Re-encrypt vault with new vaultKey
    const { ciphertext, nonce } = await encryptVault(mnemonic, vaultKey, newVaultSalt);
    
    // Step 8: Update server with new encrypted vault
    const updateResponse = await fetch(`${this.apiUrl}/wallet/update-vault`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        encrypted_vault: {
          version: 2,
          salt: newVaultSalt,
          ciphertext,
          nonce
        },
        auth_key: authKey,
        auth_salt: newAuthSalt,
        fork_version: 2
      })
    });
    
    const updateData = await updateResponse.json();
    if (!updateData.success) {
      throw new Error(updateData.error || 'Failed to update vault');
    }
    
    // Step 9: Restore wallet state
    this.mnemonic = mnemonic;
    this.privateKey = keyPair.secretKey;
    this.publicKey = keyPair.publicKey;
    this.address = 'bb1_' + bytesToHex(keyPair.publicKey);
    this.username = username;
    
    return { 
      success: true, 
      address: this.address,
      message: 'Wallet recovered and re-encrypted with new password'
    };
  }

  /**
   * Change password (when user knows old password)
   * No SSS needed - decrypt with old, re-encrypt with new
   * 
   * @param {string} oldPassword - Current password
   * @param {string} newPassword - New password
   * @returns {Promise<object>} - Result
   */
  async changePassword(oldPassword, newPassword) {
    if (!this.username) throw new Error('Must be logged in to change password');
    if (!newPassword || newPassword.length < 8) {
      throw new Error('New password must be at least 8 characters');
    }
    
    // Ensure we have the mnemonic decrypted
    if (!this.mnemonic) {
      throw new Error('Wallet not fully loaded. Login first.');
    }
    
    // Generate new salts
    const newAuthSalt = bytesToHex(randomBytes(32));
    const newVaultSalt = bytesToHex(randomBytes(32));
    
    // Fork new password
    const { authKey, vaultKey } = await forkPassword(newPassword, newAuthSalt, newVaultSalt);
    
    // Re-encrypt vault
    const { ciphertext, nonce } = await encryptVault(this.mnemonic, vaultKey, newVaultSalt);
    
    // Update server
    const response = await fetch(`${this.apiUrl}/auth/change-password`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: this.username,
        encrypted_vault: {
          version: 2,
          salt: newVaultSalt,
          ciphertext,
          nonce
        },
        auth_key: authKey,
        auth_salt: newAuthSalt,
        fork_version: 2
      })
    });
    
    return await response.json();
  }

  /**
   * Initialize wallet directly from a seed (for test accounts)
   * 
   * @param {string} seedHex - 32-byte seed as 64 hex characters
   * @param {string} knownAddress - Pre-computed address (optional)
   * @returns {object} - Wallet info { address, publicKey }
   */
  initFromSeed(seedHex, knownAddress = null) {
    const seedBytes = hexToBytes(seedHex);
    if (seedBytes.length !== 32) {
      throw new Error('Seed must be exactly 32 bytes (64 hex chars)');
    }
    
    const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    this.privateKey = keyPair.secretKey;
    this.publicKey = keyPair.publicKey;
    
    // Use known address if provided, otherwise derive it
    if (knownAddress) {
      this.address = knownAddress;
    } else {
      // Derive L1 address from public key (async would be needed for proper SHA256)
      // For now, require the address to be passed in for seed-based init
      throw new Error('knownAddress is required for initFromSeed. Use initFromTestAccount() for test accounts.');
    }
    
    return {
      address: this.address,
      publicKey: bytesToHex(this.publicKey)
    };
  }

  /**
   * Initialize from a test account (Alice, Bob, or Dealer)
   * 
   * @param {string} accountName - 'alice', 'bob', or 'dealer'
   * @returns {object} - Wallet info { address, publicKey, balance }
   */
  initFromTestAccount(accountName) {
    const account = TEST_ACCOUNTS[accountName.toUpperCase()];
    if (!account) {
      throw new Error(`Unknown test account: ${accountName}. Use 'alice', 'bob', or 'dealer'`);
    }
    
    const seedBytes = hexToBytes(account.seed);
    const keyPair = nacl.sign.keyPair.fromSeed(seedBytes);
    
    this.privateKey = keyPair.secretKey;
    this.publicKey = keyPair.publicKey;
    this.address = account.address;
    this.username = account.username;
    
    return {
      address: this.address,
      publicKey: bytesToHex(this.publicKey),
      expectedBalance: account.startingBalance
    };
  }

  // ═══════════════════════════════════════════════════════════════
  // INTERNAL HELPERS
  // ═══════════════════════════════════════════════════════════════

  /**
   * Generate BIP39 compliant 24-word mnemonic
   * Uses crypto.getRandomValues() for 256-bit entropy
   */
  async _generateMnemonic() {
    // 256 bits of entropy for 24 words
    const entropy = randomBytes(32);
    
    // Convert entropy to binary string
    const entropyBits = Array.from(entropy)
      .map(b => b.toString(2).padStart(8, '0'))
      .join('');
    
    // Calculate SHA256 checksum of entropy (BIP39 spec)
    const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
    const hashArray = new Uint8Array(hashBuffer);
    const checksumBits = Array.from(hashArray)
      .map(b => b.toString(2).padStart(8, '0'))
      .join('')
      .slice(0, 8); // First 8 bits for 256-bit entropy
    
    const allBits = entropyBits + checksumBits;
    
    // Split into 24 x 11-bit segments
    const mnemonic = [];
    for (let i = 0; i < 24; i++) {
      const index = parseInt(allBits.slice(i * 11, (i + 1) * 11), 2);
      mnemonic.push(BIP39_WORDLIST[index]);
    }
    
    return mnemonic.join(' ');
  }

  /**
   * Derive 32-byte seed from mnemonic using BIP39 spec
   * PBKDF2 with HMAC-SHA512, salt = "mnemonic" + passphrase, 2048 iterations
   */
  async _mnemonicToSeed(mnemonic, passphrase = '') {
    const encoder = new TextEncoder();
    
    // Import mnemonic as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(mnemonic.normalize('NFKD')),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );
    
    // BIP39 spec: salt is "mnemonic" + optional passphrase
    const salt = encoder.encode('mnemonic' + passphrase);
    
    // Derive 512 bits (64 bytes) per BIP39, we use first 32 for Ed25519
    const seed = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: 2048,
        hash: 'SHA-512'
      },
      keyMaterial,
      512
    );
    
    // Return first 32 bytes for Ed25519 seed
    return new Uint8Array(seed).slice(0, 32);
  }

  /**
   * Zero sensitive data from memory
   */
  destroy() {
    if (this.privateKey) {
      this.privateKey.fill(0);
      this.privateKey = null;
    }
    if (this.mnemonic) {
      this.mnemonic = '';
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// EXPORTS
// ═══════════════════════════════════════════════════════════════

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    // Main wallet class
    BlackBookWallet,
    
    // Core crypto functions
    forkPassword,
    encryptVault,
    decryptVault,
    signRequest,
    createCanonicalPayloadHash,
    
    // Constants
    CHAIN_ID_L1,
    CHAIN_ID_L2,
    BIP39_WORDLIST,
    
    // Test accounts (public credentials only)
    TEST_ACCOUNTS,
    
    // Utility functions
    randomBytes,
    bytesToHex,
    hexToBytes,
    sha256,
    generateNonce
  };
}
