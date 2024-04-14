from hashlib import sha256
from string import ascii_lowercase
from tqdm import tqdm

p = 99126081498110679622117208839946568977975346033127530222404078981480201164078403345496146296949856728918789240336343638617422048283132242454464446291492611584384751501785383357838317732828318093759885347973087134144406693627357857330950504134924555608896346799104280246597972464783116857557440201146239820962614737545356185926303055992966419563962391182588280591946549056511488286585225437441847723071671691983100789423850862625728681245227608953095286385917258671161510940257372122458091056338357381929396029892868891726999599401117716948670950295974901401487901706396092675230119537481992404521806171202857131482218447629266273659693800992655608637431138440796299719773966019160861946691736898018974264372149526585927739463345353811003110493041611686230570445853159167671930184015631656166581888140313132779812582289364648438529584403147703014843916154647757047547530701247017078776589293631650327878203453320557338297607
q = 219417094215275962897891584141934286732289959275399446266197828228881499677887
gen_p = 5
gen_q = 72154714647924720796474763306018150527191193551579074454752226970361323910715225761684479052710319044131664417748053567305559594047843955631623493511776191150761624423057712199333695861546969039213115324133903199540888607688395526099308852693693849968497163766267565896327807964016029443580636143801729508911217765863848341671551118348011046973222684768978887554468357759171837184458551001147236382457538449300832986979798907732863289077628954566687210037771632552199142257829844076857480798150476647417848684957787136264909313143902413998900899314654316452799924876033142970490676851821804729747044276455816438355824263753284809574944174976279150615425997612511094163023294534830728406472125525906164174075985781960904415647895164715282031620157048260175517210288249757399650428148616065918428303867923400176690656556468547499914734843233868999940689417190530787085270228716948016475608585812032578630717685685190825328784

Xenc = 19460524269501469684380940282404035263353475313570685944699777212278714734233974848616532867976938042391556360448138597452928815967385556209404253936404195331278865945748733691583103481233229973739048062149957215958944755071256292474208675643955038432029107148362075643154731697188203476192416818811805475474850424618204910903885276181033693382352648269079678235759177277207911853342711777657979574476592861894959055793978346494827004441820586113252218266204154732012769528643417011794778849554113853620663572084387325155825471739765022830613504350108584120580421755123376416482883250676048630917915780936724250343400455175393922102390667903435317779694694201051038813069086292000645527387556789454121634247313392246822415341019000805020774276218525198099950909055708841086228189494310403615523629305142137297289569411467841488144672894655471512477575751150978532821174700641398949624570034053598900921113884230462963866530
Yenc = 84670717381205440016719090853798939852418749646038823712435648781665144674461878466063166092569283277546919853772421423008690176544659974816667496981163582048472771734186856375338199938692385892071921329848173035737798082097050940388245739636034935245388068536162882410878110071666242695027971713211776153590965483658618178623976672289798767865497599628578488556347449529427918783922082152119048313627919960326510868635530829264575197739953531608841678502422411582312533043052417916055931979687498721896870961159953728004205770476809412625065667055305692843846613243187997480887311556221895849073881321743490721175815615271924666478464203749498025199664746342454585100519032431215000822959406154079422638289685952728634178556229042892358538313317485004490629892684268877050700293424487323426716589875776900888155996590033379362982943090598235769506118719008120861616330790103010762602452608987506626094830297346246555325568

Hsrv = bytes.fromhex('0589fc1f04fa4393c82a53ec18668897a9e88b6a2fe3de22bb134eb9f7d27a32')
Hcli = bytes.fromhex('3c0416f06455670bb12c8b2865e09874cd4135e26bebf1f744cfc6aed6fcb53e')

# x: mod q
# X    = gq^x     mod p
# Xenc = X * gp^k mod p

# y: mod q
# Y    = gq^y     mod p
# Yenc = Y * gp^k mod p

# K = Yenc^x * gp^-kx mod p


def test(a: int):
    print(f'Process {chr(a)}')

    for b in alpha:
        for c in alpha:
            for d in alpha:
                pwd = bytes([a,b,c,d])
                key = int.from_bytes(sha256(pwd).digest(), 'big')
                d = pow(gen_p, -key, p)
                X = Xenc * d % p
                Y = Yenc * d % p

                if pow(X, q, p) == 1 and pow(Y, q, p) == 1:
                    print('-'*30)
                    print('pwd:', pwd.decode())
                    print(f'FCSC{{{sha256(pwd).hexdigest()}}}')


from multiprocessing import Pool
alpha = ascii_lowercase.encode()

with Pool(4) as p:
    p.map(test, alpha)
