# Ruby knihovna pro EET 2.0 - technická analýza

Stav k 21. 7. 2026. Dokument vychází z aktuálních oficiálních podkladů EET 2.0,
živého testu Playgroundu a auditu původního projektu
[`ciihla/ruby-eet-cz`](https://github.com/ciihla/ruby-eet-cz).

## 1. Závěr

Novou samostatnou Ruby knihovnu lze implementovat i plnohodnotně testovat proti
Playgroundu už nyní.

Prakticky bylo ověřeno, že čistá implementace založená na `Nokogiri`, `OpenSSL` a
`Net::HTTP` dokáže:

1. vytvořit v4.1 SOAP request podle XSD;
2. podepsat právě `soap:Body` pomocí Exclusive C14N, SHA-256 a RSA-SHA256;
3. odeslat request přes HTTP/1.1 a TLS 1.2+;
4. přijmout POK z Playgroundu;
5. ověřit digest a XML podpis odpovědi;
6. ověřit podpisový certifikát odpovědi až ke zveřejněnému kořeni I.CA;
7. ověřit shodu request/response UUID a příznak testovacího prostředí.

Není vhodné oživovat ani forkovat původní `ruby-eet-cz`. Část základních konceptů
je podobná, ale wire kontrakt je nekompatibilní a původní bezpečnostní i aplikační
architektura neodpovídá dnešním požadavkům. Doporučení je clean-room rewrite v novém
gemu s novým namespacem a verzovaným protokolovým jádrem.

Produkční připravenost zatím nelze uzavřít. K dnešnímu dni:

- návrh zákona prošel Poslaneckou sněmovnou, ale 21. 7. 2026 byl teprve doručen
  Senátu;
- technický dokument výslovně vychází ze sněmovního tisku 189/0, nikoli z konečného
  zákona;
- produkční DNS `trzbyeet.gov.cz` dosud není dostupné;
- DNS pro publikované CA renewal API také dosud není dostupné;
- produkční pokladní certifikáty mají být dostupné přes DIS+ od 1. 11. 2026;
- není publikován dokument „Popis položek datové zprávy a příklady situací při
  evidenci tržeb“, na který technická specifikace odkazuje;
- produkční odpověď má podle publikovaného provozního dokumentu používat systémový
  certifikát SSSVD; SSSVD/NCA publikuje konkrétní RSA root a SubCA2 včetně SHA-256
  otisků a certifikační politiky, ale skutečný EET produkční leaf/chain zatím nelze
  ověřit proti živé odpovědi.

To neblokuje implementaci protokolu ani reálné Playground testy. Blokuje to pouze
prohlášení knihovny za produkčně hotovou.

## 2. Co je dnes oficiálně k dispozici

[Portál EET pro vývojáře](https://eet.gov.cz/pro-vyvojare/) publikuje:

- popis rozhraní v1.0 ze dne 2. 6. 2026;
- XSD schéma a WSDL pro rozhraní 4.1 na URL s major verzí `/v4`;
- Playground endpoint;
- tři podepsané vzorové requesty;
- tři sdílené Playground PKCS#12 certifikáty a heslo;
- kořenový a mezilehlý certifikát CA EET Playground;
- provozní informace pro Playground a produkci;
- certifikační politiku;
- postup prvního vydání a automatické obnovy certifikátu;
- OpenAPI 3.1 kontrakt renewal API s JWT autentizací.

### 2.1 Endpointy

| Prostředí | Endpoint | Stav 21. 7. 2026 |
|---|---|---|
| Playground | `https://pg.trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4` | dostupný a funkční |
| Produkce | `https://trzbyeet.gov.cz/eet/services/EETServiceSOAP/v4` | DNS zatím neexistuje |
| CA test | `https://test.caeet.gov.cz/api` | DNS zatím neexistuje |
| CA zkušební | `https://zkus.caeet.gov.cz/api` | DNS zatím neexistuje |
| CA produkce | `https://caeet.gov.cz/api` | DNS zatím neexistuje |

Playground je podle Finanční správy určen výhradně vývojářům. POK z Playgroundu
není zákonným potvrzovacím kódem a končí `-ff`.

### 2.2 Ověřené checksumy zdrojových artefaktů

Checksumy níže jsou snapshot z 21. 7. 2026. Implementace má mít obdobný verzovaný
manifest a CI kontrolu změn upstream souborů.

| Soubor | SHA-256 |
|---|---|
| `EET_popis_rozhrani_v1.pdf` | `26a7c015b039ba6dbb5c54998f220ebf3b3761d81c4af670e7a183afd3059707` |
| `EETXMLSchema.xsd` | `83597d08520cbfab7e51145df9a765d5ca22e2f9a38644a468d695657c7a032a` |
| `EETServiceSOAP.wsdl` | `df149c0bef4ac18c2a6e82116b6eb9bb17d29c055cb0821ac6d3885ec90faeb4` |
| Playground provozní informace v1.1 | `f29c73d3bc84be8d073344dc7053466e9fa143792cbee2bc997f289d67329880` |
| `CAEET_Playground_2026_v1.zip` | `711ca591e2e58e906212befab55ea72cbc5d960af49e444765b0428751002491` |
| `CZ00000019.eet.v4.req.xml` | `4392b4ca0e6eb586c10b6f80d8946f5269f500a5b2b0d94fa7a092ace867ade5` |

Upstream soubory se nemají stahovat za běhu aplikace. XSD/WSDL a potřebné veřejné
trust anchors mají být vendored, opatřené provenancí, verzí a checksumem.

## 3. Wire protokol EET 2.0

### 3.1 Transport

- SOAP 1.1, document/literal;
- HTTP/1.1 je povinné;
- HTTPS je povinné;
- TLS 1.2 nebo vyšší;
- bez klientské autentizace na TLS vrstvě;
- operace `OdeslaniTrzby`;
- SOAPAction `http://fs.gov.cz/eet/OdeslaniTrzby`;
- request/response je synchronní;
- request včetně SOAP obálky smí mít maximálně 12 kB;
- odpověď může nést `X-Global-Transaction-ID`, který je nutné bezpečně ukládat pro
  podporu a trasování;
- endpoint musí používat DNS jméno, ne IP adresu. Produkce používá DNS balancing a
  klient nesmí IP adresy sám dlouhodobě cachovat nebo pinovat.

### 3.2 Request

`soap:Body` obsahuje jediný `Trzba` s elementy `Hlavicka` a `Data`.

Povinná hlavička:

- `uuid_zpravy` - UUID zprávy, doporučená verze 4;
- `dat_odesl` - ISO 8601 včetně časové zóny, bez zlomků sekundy;
- `prvni_zaslani` - `true` pro první pokus, `false` pro opakované zaslání stejné tržby;
- `overeni` - nepovinné, `true` znamená pouze ověření spojení.

Povinná data:

- `eic_popl`;
- `id_jednotky`;
- `id_pokl`;
- `porad_cis`;
- `dat_trzby`;
- `celk_trzba`.

Nepovinná data:

- `eic_poverujiciho`;
- `povereni_vice_popl`;
- `urceno_cerp_zuct`;
- `cerp_zuct`.

Prázdné atributy jsou zakázané. Nepoužitý nepovinný atribut se musí úplně vynechat.
Částky jsou CZK, přesně na dvě desetinná místa, bez nevýznamných nul a v absolutní
hodnotě pod 100 milionů Kč. Implementace nesmí pro částky používat `Float`; veřejné
API má přijímat `BigDecimal`, případně bezpečně parsovaný desetinný string.

### 3.3 Identita tržby a retry

Stejnou evidovanou tržbu identifikuje kanonická šestice:

1. `eic_popl`;
2. `id_jednotky`;
3. `id_pokl`;
4. `porad_cis`;
5. `dat_trzby`;
6. `celk_trzba`.

Retry zachovává všech šest hodnot, vytvoří nové `uuid_zpravy` a nastaví
`prvni_zaslani=false`. UUID identifikuje pokus/zprávu, nikoli obchodní tržbu.

Knihovna proto nesmí provádět skryté automatické retry uvnitř HTTP klienta. Každé
volání musí představovat přesně jeden auditovatelný pokus. Persistenci identity tržby,
frontu, backoff a zákonnou lhůtu vlastní hostitelská aplikace.

Aktuální FAQ uvádí mezní dobu odezvy nejméně 2 sekundy a opakování bezodkladně po
pominutí příčiny, nejpozději do 48 hodin. Protože zákon ještě není konečný, tyto lhůty
nesmějí být nevratně zakódovány do protokolového jádra gemu.

### 3.4 Podpis requestu

Podepisuje se právě jeden element: `soap:Body`.

- WS-Security 1.1 a XML Digital Signature;
- Exclusive XML Canonicalization 1.0;
- digest SHA-256;
- podpis RSA-SHA256, tedy RSA PKCS#1 v1.5 se SHA-256;
- X.509 certifikát je vložen jako Base64 DER v `BinarySecurityToken`;
- `Reference` musí jednoznačně odkazovat na `wsu:Id` těla;
- request nemá přidávat Timestamp, WS-Addressing ani další podepisované elementy.

### 3.5 Response

Úspěšná odpověď `Potvrzeni` obsahuje:

- request UUID;
- `dat_prij`;
- POK;
- na Playgroundu `test=true` a POK končící `-ff`;
- nula až deset varování;
- XML podpis systému EET.

Chybová odpověď `Chyba` je podle specifikace nepodepsaná. Kód `0` je úspěch
ověřovacího módu, nikoli evidence a nikoli POK. Kód `-1` je dokumentovaná dočasná
technická chyba. Kódy `2` až `8` pokrývají encoding, XSD, podpis, EIČ, velikost a
obecnou technickou/datovou chybu. HTTP 200 samo o sobě nikdy neznamená úspěch.

U `Potvrzeni` smí klient vrátit `accepted` pouze po ověření:

1. striktní a bezpečné XML struktury;
2. přesně jednoho Envelope, Header, Body, Signature, tokenu a Reference;
3. jednoznačného odkazu podpisu právě na jediný `soap:Body`;
4. povolených algoritmů bez možnosti downgrade;
5. digestu těla;
6. kryptografického XML podpisu;
7. platnosti a certifikačního řetězce podpisového certifikátu;
8. profilu a prostředí podpisového certifikátu;
9. shody response UUID s requestem;
10. `test=true` a `-ff` pouze na Playgroundu, naopak jejich nepřítomnosti v produkci;
11. XSD a datových formátů POK, času, chyb a varování.

To je podstatně přísnější než „najít element Potvrzeni a přečíst POK“.

## 4. Rozdíly proti EET1 a starému gemu

| Oblast | EET1 / `ruby-eet-cz` | EET2 v4.1 |
|---|---|---|
| Namespace | `http://fs.mfcr.cz/eet/schema/v3` | `http://fs.gov.cz/eet/schema/v4` |
| Endpoint | `pg.eet.cz` / `prod.eet.cz`, `/v3` | `pg.trzbyeet.gov.cz` / `trzbyeet.gov.cz`, `/v4` |
| Poplatník | DIČ `dic_popl` | EIČ `eic_popl` |
| Provozní identita | `id_provoz` | `id_jednotky` |
| Režim | `rezim`, včetně zjednodušeného | odstraněn |
| Kontrolní kódy requestu | PKP a BKP | odstraněny |
| Úspěšný kód | FIK, response obsahovala BKP | POK, bez BKP |
| DPH rozpad | řada základů/daní a dalších polí | odstraněn |
| Čerpání/zúčtování | podporováno | zůstává |
| Pověření více poplatníky | není | nové pole |
| Délka `porad_cis` | 20 | 25 |
| Certifikát | starý profil CA EET | nová dvouúrovňová CA, certifikát 366 dní |

Původní gem má poslední commit z 29. 9. 2020 a jedinou prerelease verzi
`1.0.0.pre`. Je svázaný s ActiveSupport/ActiveModel, Savon 2.12 a globálním
monkey-patchem Akami. Má mutable klienta, class-global fake mode, neřešené síťové
výjimky (`TODO`) a neověřuje podpis odpovědi ani její trust chain. Při parsování navíc
odstraňuje namespace a považuje přítomnost `Potvrzeni` za dostatečný důkaz úspěchu.

### Co lze převzít jako inspiraci

- rozdělení na request, client a response;
- podporu PKCS#12 i odděleného certifikátu/klíče;
- princip validace formátů;
- rozlišení Playground/production a ověřovacího módu;
- reprezentaci varování a chyb jako samostatných hodnot.

### Co nepřebírat

- namespace, endpointy, XSD/WSDL a datové modely v3;
- PKP/BKP/FIK a daňové položky;
- Savon/Akami monkey-patch;
- ActiveSupport/ActiveModel jako runtime dependency;
- mutable globální konfiguraci a fake mode;
- automatickou tvorbu requestu současně se síťovým voláním;
- odstranění XML namespace při parsování;
- VCR kazety se zastaralými certifikáty;
- API, které vrací success bez kryptografického ověření odpovědi.

Pokud by se ze starého projektu kopíroval konkrétní kód, je nutné zachovat MIT licenci
a atribuci. Doporučený rewrite ale konkrétní kód kopírovat nepotřebuje.

## 5. Doporučená hranice nové knihovny

Gem má vlastnit pouze wire protokol a kryptografickou správnost:

- value objects a jejich formátovou validaci;
- serializaci v4.1;
- XSD validaci;
- tvorbu a ověření XML podpisu;
- import/inspekci credentials;
- bezpečný jednorázový HTTP transport;
- striktní parsování a typované výsledky;
- verzované endpointy a trust policy;
- sanitizovaná technická metadata pro audit.

Gem nemá vlastnit:

- rozhodnutí, zda je konkrétní platba evidovaná;
- fakturu, payment lifecycle nebo ORM;
- generování podnikové posloupnosti `porad_cis`;
- databázovou idempotenci;
- persistentní queue, retry scheduler a 48hodinovou lhůtu;
- ukládání P12, hesla, raw XML nebo POK;
- logování, metriky a alerting hostitelské aplikace;
- UI;
- Rails integraci.

Tato hranice umožní knihovnu používat v Rails, Hanami, CLI i samostatné službě a
zabrání tomu, aby zákonné/productové změny rozbíjely protokolové jádro.

## 6. Navržená architektura gemu

Pracovní název gemu může zůstat `ruby-eet2-cz`, veřejný require `eet2` a namespace
`Eet2`. Verze gemu je SemVer a je nezávislá na verzi státního protokolu.

```text
lib/eet2/
  contracts/v4_1/
    schema.rb
    request_builder.rb
    response_parser.rb
    eet.xsd
    eet.wsdl
  sale.rb
  credential.rb
  signing_key.rb
  prepared_request.rb
  result.rb
  xml_signer.rb
  xml_signature_verifier.rb
  certificate_verifier.rb
  trust_policy.rb
  transport.rb
  net_http_transport.rb
  client.rb
sig/eet2.rbs
data/trust/playground/
data/source-manifest.yml
```

### 6.1 Veřejný tok

```ruby
credential = Eet2::Credential.from_pkcs12(
  bytes: encrypted_p12,
  password: password,
  legacy_provider: :explicitly_allowed
)

sale = Eet2::Sale.new(
  taxpayer_eic: "CZ00000019",
  evidence_unit_id: 303,
  register_id: "web-1",
  sequence_number: "payment/2027/123",
  occurred_at: occurred_at,
  amount_czk: BigDecimal("1250.00")
)

client = Eet2::Client.playground(credential: credential)
prepared = client.prepare(sale:, first_submission: true)

# Host může před network callem atomicky uložit UUID, signed XML a hash.
persist_attempt(prepared)

# Přesně jeden síťový pokus, bez skrytého retry.
result = client.send(prepared)
```

Rozdělení `prepare` a `send` je zásadní. Aplikace musí mít možnost uložit konkrétní
podepsaný pokus ještě před síťovým voláním, aby po crashi nebo timeoutu neztratila
auditní stopu.

### 6.2 Value objects

Použít immutable objekty (`Data.define` je dostupné od Ruby 3.2), žádné hashové API
na veřejné hranici. Objekty mají zachovat původní hodnotu a serializovaný tvar.

Základní typy:

- `Sale`;
- `PreparedRequest` - UUID, XML, endpoint, protocol/schema verze, hash těla a requestu;
- `Accepted` - POK, response UUID, datum, warnings, test flag, response hash a support ID;
- `Rejected` - kód, popis, warnings, datum a support ID;
- `TransportFailure` - zda request prokazatelně nebyl odeslán, mohl být odeslán, nebo je
  stav neznámý;
- `InvalidResponse` - odpověď existuje, ale neprošla trust/signature/schema kontrolou.

Chyby protistrany jsou návratové hodnoty. Programátorské chyby, nevalidní lokální
vstup a porušení bezpečnostního kontraktu používají úzce typované exceptions.

### 6.3 Transport

Výchozí implementace má používat `Net::HTTP`:

- protokol má jednu operaci a pevný endpoint;
- WSDL discovery za běhu není potřeba;
- odpadnou transitive dependencies Savonu;
- knihovna má plnou kontrolu nad raw XML a hlavičkami;
- TLS peer verification je explicitní a povinná;
- minimální TLS verze je 1.2;
- HTTP redirect se automaticky nenásleduje;
- endpoint je allowlisted podle environmentu;
- open/read timeout jsou explicitní;
- response body má konzervativní size limit;
- transport nikdy automaticky neopakuje POST.

Pro testy a nestandardní deployment stačí malý duck-typed transport interface. Není
nutné zavádět Faraday jako runtime dependency.

### 6.4 XML a podpis

Použít `Nokogiri` pro:

- tvorbu XML;
- strict/nonet parsing bez DTD a external entities;
- XSD validaci;
- Exclusive C14N.

Použít Ruby `OpenSSL` pro SHA-256, RSA-SHA256 a X.509 chain validation. Runtime
implementace bude záměrně podporovat jen přesný profil EET; obecný XMLDSig engine by
zbytečně zvětšil attack surface.

`xmlsec1` doporučuji jako nezávislý testovací oracle v Linux CI, nikoli jako povinnou
runtime binárku. Každý podpis vytvořený Ruby implementací musí projít i `xmlsec1` a
naopak vybrané validní fixture z `xmlsec1` musí projít Ruby verifierem.

### 6.5 Signing key abstraction

Credential nemá nutně obsahovat exportovatelný `OpenSSL::PKey`. Interní rozhraní má
být přibližně:

```ruby
signer.sign_sha256_rsa(canonical_signed_info) # vrátí raw signature bytes
```

Výchozí `LocalKeySigner` použije klíč z PKCS#12/PEM. Host může dodat signer nad
vaultem nebo KMS, takže soukromý klíč nemusí opustit bezpečné úložiště. To odpovídá
doporučení Finanční správy.

### 6.6 Verze kontraktu

Implementace nemá mít anonymní `current schema`. Má mít explicitní
`Contracts::V4_1`. Minor kompatibilní změny a major nekompatibilní změny tak mohou
existovat vedle sebe. Každý `PreparedRequest` nese:

- gem version;
- protocol major `4`;
- schema/WSDL version `4.1`;
- checksum vendored XSD/WSDL;
- environment a endpoint.

## 7. Certifikáty a OpenSSL 3

### 7.1 Důležitá kompatibilita PKCS#12

Oficiální Playground P12 obsahuje:

- MAC SHA-1;
- certificate bags chráněné `RC2-40-CBC`;
- private key bag chráněný 3DES-CBC.

OpenSSL 3 tyto algoritmy ve výchozím provideru odmítá. Toto není hypotetické: načtení
oficiálního P12 na Ruby 3.4.9 / OpenSSL 3.6 bez legacy provideru skončilo
`PKCS12_parse: unsupported`. Po explicitním `OpenSSL::Provider.load("legacy")` funguje.

Oficiální dokumentace problém potvrzuje a doporučuje buď:

- cíleně zapnout legacy provider jen v procesu, který import provádí;
- nebo certifikát v důvěryhodném prostředí převést do PEM či moderně zabaleného P12;
- nebo klíč uložit do vaultu/KMS.

Knihovna nesmí legacy provider tiše globálně zapnout. Bez explicitního opt-in má vrátit
srozumitelnou `LegacyPkcs12Unsupported` chybu. Pro serverovou aplikaci je vhodný
izolovaný import/conversion worker a následné uložení ve vaultu. Nešifrovaný privátní
klíč se nesmí zapisovat na disk ani do logu.

Ruby nedokáže spolehlivě garantovat zeroizaci stringů v paměti; dokumentace knihovny
musí tuto hranici přiznat.

### 7.2 Request certificate

Playground poskytuje tři sdílené testovací certifikáty pro předem přidělená EIČ.
Testovaný `CZ00000019` je platný od 13. 5. 2026 do 14. 5. 2027. Jeho policy OID je
Playground profil a certifikát obsahuje user notice, že je pouze pro EET2 testování.

Produkční pokladní certifikát:

- RSA 2048;
- platnost 366 dní;
- první vydání probíhá ručně přes DIS+;
- soubor obsahuje certifikát, klíč i chain;
- obnova má proběhnout před expirací, doporučeně 2-3 týdny předem;
- automatická obnova používá samostatné REST API a JWT RS256 podepsaný stávajícím
  platným certifikátem.

Automatickou obnovu je vhodné implementovat jako oddělený modul až po stabilizaci
základního submit klienta. Má vlastní stavový workflow a v současnosti není možné její
endpointy živě otestovat.

### 7.3 Response certificate

Playground odpověď je podepsaná certifikátem I.CA:

- issuer `I.CA Public CA/RSA 06/2022`;
- subject organization `Generální finanční ředitelství`;
- skutečný ověřený chain vede přes I.CA intermediate ke `I.CA Root CA/RSA 05/2022`;
- root SHA-256 je
  `d279c01a12e8dd9a6230e459faa447ceb336998477338c2ee4135c96737418eb`;
- intermediate SHA-256 je
  `df5baf6d7e1a7d14e9911c5b8c676ec6ebcad9354a74f4ac7314e133e07a94de`.

Nesmí se pinovat konkrétní leaf certifikát. Trust policy má ověřovat chain, platnost,
key usage/policy a environment profil a musí umožnit bezpečnou rotaci.

Produkční dokument určuje systémový certifikát autority SSSVD a subject
`O = Generální finanční ředitelství`. Oficiální NCA repozitář publikuje RSA root
`NCA Root CA/RSA 10/2023` (SHA-256
`d2d98e1b7af2d0e33276a33120d30863a66858d881eafd7400d09a4942630cb7`) a
technologický intermediate `NCA SubCA2/RSA 12/2023` (SHA-256
`ae36c864fc904b29cbc4b38a096364ae311ff1db544c5c064c12ec4bf9c5a8b3`).
RSA technologická politika má OID `1.2.203.19122063.10.1.72.1.0`. Tyto podklady
umožňují implementovat oddělenou, verzovanou production trust policy; před
produkčním releasem je stále nutné ověřit skutečný leaf a celý chain na živé EET
odpovědi a potvrdit revocation/rotation chování.

## 8. Ověření proveditelnosti 21. 7. 2026

Byly provedeny dva živé testy proti Playgroundu.

### Test A - oficiální sample

- odeslán oficiální podepsaný XML pro `CZ00000019`;
- HTTP 200;
- response UUID odpovídalo requestu;
- vráceno `test=true` a POK s `-ff`;
- `X-Global-Transaction-ID` byl přítomen;
- digest i RSA-SHA256 podpis odpovědi byly validní;
- podpisový certifikát prošel chain validation vůči oficiálním I.CA certifikátům.

### Test B - vlastní Ruby request

Prototyp běžel na stacku, který je kompatibilní se současnou FakturaOnline aplikací:

- Ruby 3.2.2;
- OpenSSL 3.6.2;
- Nokogiri 1.19.3;
- Net::HTTP.

Výsledek:

- request byl vytvořen od nuly, nikoli upravením sample XML;
- request měl 3 853 bajtů a prošel oficiálním XSD;
- digest a podpis requestu byly lokálně validní;
- Playground request přijal a vrátil HTTP 200 a POK `-ff`;
- response UUID odpovídalo nově vygenerovanému UUID;
- response digest, podpis a I.CA chain byly validní.

Tím je ověřena nejrizikovější technická část navrhované knihovny.

## 9. Testovací strategie

### 9.1 Unit a contract testy

- všechny XSD formáty a hraniční délky;
- částky včetně `0.00`, `-0.01`, maxima, zakázaného `-0.00` a vedoucích nul;
- časové zóny, DST, zakázané zlomky sekundy;
- vynechání nepoužitých atributů;
- UUID variant/version;
- stabilní serializace se vstříknutým clock a UUID generátorem;
- request do 12 kB;
- XSD validace každého generated request fixture;
- official sample jako golden interoperability fixture;
- RBS validace veřejného API.

### 9.2 Kryptografické negativní testy

Verifier musí odmítnout:

- změněné tělo po podpisu;
- změněný digest nebo signature;
- SHA-1 nebo jiný algoritmus;
- Reference mimo Body;
- dvě Body, dvě Signature, dva tokeny, dvě stejné `wsu:Id`;
- signature wrapping a namespace confusion;
- DTD, external entity, XInclude a network resolution;
- neznámý, expirovaný nebo wrong-environment certifikát;
- validní podpis z nedůvěryhodného self-signed certifikátu;
- Playground certifikát v produkční odpovědi a naopak;
- podepsanou odpověď s cizím request UUID;
- unsigned `Potvrzeni`;
- `test=true` nebo POK `-ff` v produkčním klientovi;
- produkční-looking POK v Playground klientovi.

Kritický verifier má mít 100% branch coverage a samostatný security review. Validní i
nevalidní podpisy mají být křížově testované pomocí `xmlsec1`.

### 9.3 Transport testy

- connect timeout před odesláním;
- read timeout po možném odeslání - stav musí být `ambiguous`, ne automaticky failed;
- connection reset v různých fázích;
- TLS hostname/chain failure;
- HTTP 4xx/5xx;
- SOAP Fault;
- prázdná, zkrácená a příliš velká odpověď;
- business error v HTTP 200;
- redirect se nesmí následovat;
- zachování `X-Global-Transaction-ID`;
- žádný automatický retry.

### 9.4 Playground test matrix

Spouštět odděleně od běžných hermetických testů, manuálně nebo plánovaně:

1. `overeni=true`, validní request - očekávat unsigned error code `0`, bez POK;
2. ostrý mód Playgroundu, validní request - podepsané `Potvrzeni`, POK `-ff`;
3. validní request s propustnou EIČ chybou - POK plus warning;
4. nevalidní podpis - error code `4`;
5. nevalidní XSD - error code `3`;
6. request nad 12 kB - error code `7`;
7. retry stejné šestice s novým UUID a `prvni_zaslani=false`;
8. budoucí/starý čas - warningy;
9. test všech tří zveřejněných EIČ/certifikátů;
10. detekce rotace response leaf certifikátu bez rozbití chain-based trustu.

Protože jsou testovací certifikáty sdílené, musí každý běh používat unikátní
`id_pokl`/`porad_cis`. CI má artefakty stáhnout z oficiálního webu, ověřit checksum a
nikdy nevypsat P12, heslo nebo podepsaný request do veřejného logu.

## 10. Moderní projektový základ

### 10.1 Ruby a dependency policy

K 21. 7. 2026 je aktuální Ruby 4.0.6. FakturaOnline ale používá Ruby 3.2.2. Aby byl
gem do současné aplikace skutečně instalovatelný, musí podporovat přesně tuto patch
verzi; bezpečnostní upgrade host aplikace zůstává samostatným doporučením:

- `required_ruby_version >= 3.2.2`;
- vývoj na Ruby 4.0.6;
- CI matrix 3.2.2, 3.2.11, 3.3.12, 3.4.10 a 4.0.6;
- MRI jako garantovanou platformu v první stabilní verzi;
- JRuby až po samostatném testu C14N/OpenSSL/provider kompatibility;
- žádný horní limit Ruby bez konkrétní inkompatibility.

Ruby 3.2.2 je compatibility floor, nikoli bezpečnostní doporučení. FakturaOnline lze
integrovat bez předchozího Ruby upgradu, ale provoz host aplikace by měl být nezávisle
povýšen na podporovanou Ruby řadu.

Runtime dependencies držet minimální:

- `nokogiri`;
- explicitní default gems, které veřejně používáme, zejména `openssl`, `net-http` a
  `base64`, pokud je příslušná Ruby verze nebalí jako garantovanou součást;
- žádný Rails, ActiveSupport, Savon, Faraday, dry-rb ani logging framework.

### 10.2 Quality gates

- RSpec;
- Standard nebo jeden konzistentní RuboCop setup, ne oba;
- RBS signatures v `sig/` a `rbs validate` v CI;
- `bundler-audit`;
- CodeQL security-extended pro public GitHub repo;
- dependency review na PR;
- build/install smoke test výsledného `.gem`;
- test, že gem package neobsahuje privátní testovací klíče, hesla ani runtime logs;
- reproducibilní source manifest oficiálních EET artefaktů;
- `SECURITY.md`, coordinated disclosure a podporované verze;
- changelog a conventional SemVer release policy;
- GitHub protected release environment;
- RubyGems Trusted Publishing přes OIDC, bez dlouhodobého API tokenu.

První veřejná verze má být `0.x`, dokud nebude ověřena produkce a konečný zákon.
`1.0.0` až po produkčním contract testu, security review a stabilizaci veřejného API.

## 11. Doporučený implementační postup

### Fáze 0 - source freeze

- uložit oficiální XSD/WSDL, jejich URL, datum, verzi a checksum;
- uložit veřejné trust anchors s provenancí a checksumem;
- založit ADR pro library boundary, XMLDSig a certifikáty;
- přihlásit projekt na distribuční seznam vývojářů EET přes `epodpora@fs.gov.cz`.

### Fáze 1 - protocol core

- gem scaffold;
- `Sale`, validace a serializer v4.1;
- XSD validation;
- deterministic clock/UUID injection;
- `PreparedRequest`;
- local signer pro moderní PEM/P12;
- explicitní legacy P12 import.

Gate: generated request projde XSD, Ruby verifierem a `xmlsec1`.

### Fáze 2 - response security

- strict parser;
- exact-profile XMLDSig verifier;
- Playground trust policy;
- typed accepted/rejected/invalid results;
- UUID/environment/POK checks;
- adversarial fixture suite.

Gate: live response a všechny negativní security fixture.

### Fáze 3 - transport a Playground

- Net::HTTP adapter;
- endpoint allowlist;
- TLS/timeout/size limits;
- redacted diagnostics;
- úplná Playground matrix;
- README s integračním příkladem.

Gate: opakovatelný end-to-end test bez ručního zásahu.

### Fáze 4 - integrace do FakturaOnline

- gem nejdřív používat přes git SHA nebo interní prerelease;
- aplikace uloží prepared attempt před network call;
- aplikace vlastní idempotenci, retry, deadline, persistence a secrets;
- gem API se upraví pouze na základě reálného consumer feedbacku;
- teprve potom vydat veřejné `0.x` na RubyGems.

### Fáze 5 - certificate renewal

- samostatný CA client podle OpenAPI 3.1;
- JWT RS256 s `x5t#S256`, `iat` a `exp <= iat + 5 minut`;
- polling podle `Retry-After`;
- bezpečné claim/ack workflow bez logování P12/hesla;
- výměna credentialu až po ověření nového certifikátu;
- test až po zprovoznění CA endpointů.

### Fáze 6 - production release gate

- konečný zákon a metodika;
- diff finálního XSD/WSDL a všech dokumentů;
- produkční DNS/TLS endpoint;
- skutečný produkční pokladní certifikát;
- živě pozorovaný production response leaf/chain proti publikované SSSVD/NCA policy;
- potvrzené revocation a rotation chování signer certifikátu;
- produkční ověřovací mód;
- kontrolovaný ostrý smoke test;
- externí security review XMLDSig/trust implementace.

## 12. Otevřené otázky pro Finanční správu

1. Potvrdí Finanční správa, že produkční EET signer používá RSA technologický profil
   NCA SubCA2 s policy OID `1.2.203.19122063.10.1.72.1.0`?
2. Které EKU, další subject atributy a revocation kontroly jsou pro produkční
   response signer závazné nad rámec publikovaného `O = Generální finanční ředitelství`?
3. Je pro Playground response signer závazný konkrétní I.CA chain, nebo pouze profil
   popsaný v provozním dokumentu?
4. Jak bude oznamována rotace signer intermediate/root certifikátu?
5. Bude publikováno testovací prostředí renewal API a budou v něm fungovat sdílené
   Playground certifikáty?
6. Kdy bude publikován dokument „Popis položek datové zprávy a příklady situací při
   evidenci tržeb“?
7. Změnil schválený sněmovní text proti 189/0 některé technické předpoklady, zejména
   lhůtu 48 hodin, režimy nebo rozsah evidovaných plateb?
8. Jak má klient jednoznačně klasifikovat code `8`, SOAP Fault a timeout po odeslání?
9. Existuje doporučený postup pro podporu při ambiguous requestu kromě
   `X-Global-Transaction-ID` a opakování stejné sale identity?
10. Budou k dispozici oficiální negativní test vectors a očekávané response fixture?

## 13. Hlavní rizika

| Riziko | Dopad | Opatření |
|---|---|---|
| Změna zákona/specifikace | změna doménového mapování nebo kontraktu | verzovaný contract, source diff gate |
| Chyba XMLDSig/verifieru | přijetí podvrženého POK | exact profile, anti-wrapping, xmlsec oracle, security review |
| Timeout po přijetí serverem | duplicitní/nejasný stav | prepared attempt, immutable retry, stejná šestice, nové UUID |
| Tichý downgrade algoritmu | oslabení podpisu | pevný allowlist jediného profilu |
| Leaf pinning | výpadek při rotaci | chain/profile validation, verzované anchors |
| Příliš volný trust store | přijetí cizího validního certifikátu | environment-specific trust a subject/policy checks |
| Legacy P12/OpenSSL 3 | nefunkční import nebo globální oslabení procesu | explicitní opt-in, izolovaný import, moderní repack/vault |
| Únik privátního klíče | zákonný i bezpečnostní incident | signer abstraction, vault, redaction, žádné raw logs |
| Skryté HTTP retry | neauditované vícečetné pokusy | přesně jeden POST na volání |
| Sdílené Playground identity | kolize testů | unikátní register/sequence, oddělené live testy |
| Produkce není dostupná | neověřená production cesta | `0.x`, production release gate |

## 14. Primární zdroje

- [EET - dokumentace pro vývojáře](https://eet.gov.cz/pro-vyvojare/)
- [Popis datového rozhraní v1.0](https://eet.gov.cz/files/EET_popis_rozhrani_v1.pdf)
- [XSD 4.1](https://eet.gov.cz/files/EETXMLSchema.xsd)
- [WSDL 4.1](https://eet.gov.cz/files/EETServiceSOAP.wsdl)
- [Playground provozní informace v1.1](https://eet.gov.cz/files/EET_pristupove_provozni_informace_playground_1_1.pdf)
- [Produkční provozní informace v1.0](https://eet.gov.cz/files/EET_pristupove_provozni_informace_produkce_v1.pdf)
- [Postupy získání pokladního certifikátu v2](https://eet.gov.cz/files/CAEET_postupy_zadost_certifikat_v2.pdf)
- [CA EET certifikační politika](https://eet.gov.cz/files/CAEET_certifikacni_politika_v1.pdf)
- [I.CA certifikační autority a fingerprinty](https://www.ica.cz/korenove-certifikaty)
- [Finanční správa - mezní doba odezvy](https://app.fs.gov.cz/dotazy-verejnosti/dotaz/co-je-to-doba-odezvy-a-jak-ji-nastavit-2573)
- [Finanční správa - výpadek připojení](https://app.fs.gov.cz/dotazy-verejnosti/dotaz/co-se-stane-v-pripade-vypadku-internetoveho-pripojeni-2578)
- [Poslanecká sněmovna - tisk 189](https://www.psp.cz/sqw/historie.sqw?o=10&t=189)
- [Ruby - aktuální verze](https://www.ruby-lang.org/en/downloads/)
- [Nokogiri - XML, XSD a C14N API](https://nokogiri.org/rdoc/)
- [RubyGems Trusted Publishing](https://guides.rubygems.org/trusted-publishing/)
