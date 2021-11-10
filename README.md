# PKIZONE

OpenSSL 기반의 인증서 발급 서비스


# 사용자(클라이언트)

* 클라이언트는 최종 사용자(End User) 또는 최종 사용자에게 인증서 발급을 대행하는
역할을 수행할 수 있다.
* 클라이언트는 CA에 등록된 사용자로, 자격 증명을 위한 개인키, 공개키 쌍을 생성해야 한다. 

# 사용자 등록(Registration)

사용자 등록을 위해 
* 서명용 키 쌍을 생성
* CA에 서명용 티켓(ticket)을 요청
* 티켓에 자신의 개인키로 서명하여 등록 토큰을 생성
* 서버의 자신의 계정(Email), 등록토큰, 공개키를 전달
하는 과정을 수행한다. 

클라이언트 서명키와 공개키 생성(create client sign key and public key)
```
client_sign_key=sign.key
client_sign_pub=sign.pub
openssl ecparam -genkey -name $client_sign_alg -noout -out $client_sign_key
openssl ec -in $client_sign_key -pubout -out $client_sign_pub
```

인증기관 접근 티켓 발급(get a access ticket)
```
##인증 기관(my-ca_name)에 접근할 수 있는 정보인 티켓 발급
##티켓은 인증기관별로 생성되는 난수이다.
curl -fk -o ./ca_name.ticket "https://localhost/ticket/my-ca_name
#or
curl "https://localhost/ticket/my-ca_name"
```

인증기관 접근 토큰 생성 - create ca token(script)
```
##ticket에 클라이언트 개인키로 서명한 값인 토큰을 생성한다.
##인증서 발급 신청을 위해서는 토큰을 CA에 제시, 신청자가 클라이언트 자신임을 증명해야 한다.
token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"
```

사용자를 pkizone에 등록
```
# ca의 ticket 다운로드
curl -fk -o ./$ca_name.ticket  "$ticket/$ca_name"

# 서명 토큰 생성
token="$(openssl dgst -sha1 -sign sign.key ./$ca_name.ticket | openssl base64 -A)"

# id:token
# 공개키와 id를 등록
curl -fk  --data-binary @sign.pub "https://localhost/clientadd/$ca_name?clientid=$clientid&token=$cient-id:$token"
```

# PKIZONE 사용법(Usage)

PKIZONE 구동

```
docker run -d -p 80:8080 -p 443:8443 
      --env CA_LIST=iot_smarthome,nse \
      --env CA_CN_nse="CA for NSE" \
      --env CA_CN_iot_smarthome="IoT Smart Home CA" \
      --mount type=bind,source=/home/ubuntu/ca.service/ssl/ca,destination=/ssl/ca jkkim7202/pkizone:latest
```

Docker secret 생성
* docker secret은 개인키 패스워드를 도커 내부에 전달하기 위한 수단으로 사용된다 

```
#파일에서 시크릿 생성
docker secret create ca1_password ca1.password
docker secret create ca2_password ca2.password

#파일 없이 시크릿 생성
echo "mypass2" | docker secret create ca1_password -
echo "mypass2" | docker secret create ca2_password -

#시크릿 확인
docker secret ls
```

Docker SWARM mode에서 구동
```
##docker swarm mode init
docker swarm init

##pkizone containe pull
docker pull jkkim7202/pkizone:latest

##도커 서비스로 구동
docker  service create \
      --name pkizone_ca_service  \
      --replicas 1 \
      --secret source=ca1_password,target=ca1_password \
      --secret source=ca2_password,target=ca2_password \
      -p 80:8080 -p 443:8443 \
      --env CA_LIST=ca1,ca2 \
      --env CA_CN_ca1="CA1" \
      --env CA_CN_ca2="CA2" \
      --mount type=bind,source=/home/ubuntu/ca.service/ssl/ca,destination=/ssl/ca jkkim7202/pkizone:latest
```

Docker-compose로 구동
```
docker-compose up -d
```

docker-compose.yml 파일
```
version: '3.9'
services:
  pki:
    image: jkkim7202/pkizone:latest
    ports:
      - "80:8080"
      - "443:8443"
    environment:
      - CA_LIST=ca1,ca2
      - CA_CN_ca1=CA1
      - CA_CN_ca2=CA2
    volumes:
      - /Users/jkkim/dev/ca.service/ssl/ca:/ssl/ca
    secrets:
      - ca1_password
      - ca2_password

secrets:
  ca1_password:
    file: ca1.password
  ca2_password:
    file: ca2.password

```

# PKIZONE 서비스

개인키 쌍/인증서신청서 생성(Create a private key and certificate request):

```
# RSA 키 쌍 생성
openssl req -new -newkey rsa:2048 -keyout host-key.pem -nodes -out host.csr -subj "/"

# ECDSA 키 쌍 생성
openssl ecparam -list_curves #타원곡선 키 파라메터 확인
openssl ecparam -genkey -name secp256r1  -out my.key # 개인키 파일 생성
openssl req -new -key my.key  -out my.csr -subj "/"
```

인증서 발급(Sign the certificate)
* localhost를 실제 서버주소로 대체한다.
* 인증서는 my.pemd에 저장된다. 

```
emailid="myid@mailaddr"
MY_DN="/C=KR/O=my-org/OU=my-ou/CN=my-cn"
curl -fk -o ./ca_name.ticket "https://localhost/ticket/my-ca_name
token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"

curl -fk --data-binary @my.csr -o my.pem "https://localhost/sign?dn=$MY_DN&token=$emailid:$token"
```

발급된 인증서 확인(Check the certificate):

```
openssl x509 -noout -text -in my.pem
```

DN 대신 'cn'으로 인증서 발급:

```
curl -fk --data-binary @my.csr -o my.pem "https://localhost/sign?cn=my-cn&ns=my-host.localdomain?token=$emailid:$token"

# O, NS 필드를 추가
curl -fk --data-binary @my.csr -o my.pem "https://localhost/sign?cn=my-host&o=company&ns=my-host.localdomain&token=..."
curl -fk --data-binary @my.csr -o my.pem "https://localhost/sign?dn=/CN=my-host/O=company&ns=my-host.localdomain&token=..."
```


1라인 인증서 신청:

```
openssl req -new -newkey rsa:2048 -keyout host-key.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o host.pem "https://localhost/sign?cn=my-host&ns=my-host.localdomain&token"
```

인증서 신청서에 CN 추가:

```
openssl req -new -newkey rsa:2048 -keyout host-key.pem -nodes -subj "/CN=my-host" | \
  curl -fk --data-binary @- -o host.pem "https://localhost/sign?ns=my-host.localdomain"
```

IP, NS 추가:

**Note:** IP나 NS가 제공되지 않으면, 클라이언트 인증서가 생성된다. 서버 인증서를 생성하기 위해서는 IP나 NS를(또는 둘다) 제공해야 한다.

```
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ip=10.0.0.1"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ip=10.0.0.1,192.168.0.1"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ns=localhost,my-host.localdomain"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ip=10.0.0.1&ns=my-host.localdomain"
```

인증서 유효기간 설정

```
#days를 추가하지 않으면 /ssl/ca/$CA/ca.cnf에 정의된 default days를 사용한다. 
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&days=30"
```

키 쌍 생성을 서버에서 수행(keygen)

```
# 타원곡선 알고리즘
# xsign API와 keygen 파라메터를 제공한다.
# eg) keygen=rsa:2048
curl -fk -o mykeypair.pem "https://localhost/xsign/$ca_name?dn=$dn&days=365&keygen=ecc:secp256k1&token=<SECRET>"
cat mykeypair.pem
```

CA인증서 다운로드
```
curl -fk -o cacert.pem "https://localhost/ca/$ca_name"
openssl x509 -in cacert.pem -text -noout
```

CRL 다운로드
```
curl -fk -o crl.pem "https://localhost/crl/$ca_name"
openssl crl -in crl.pem -text
```

인증서 리스트 다운로드
```
curl -fk -o database.txt "https://localhost/database/$ca_name"
cat database.txt
```


인증서 폐지(revocation)
```
curl -fk --data-binary @my.pem   "https://localhost/revoke/$ca_name"
#stdout --> 폐지된 인증서 파일 출력
```


CRL생성(gencrl)
```
curl -fk --data-binary @my.pem   "https://localhost/gencrl/$ca_name"
#stdout --> CRL 파일 출력
```

OCSP 검증(ocsp_verify)
```
#my.pem 인증서의 유효성을 검증
curl -fk --data-binary @my.pem   "https://localhost/ocsp_verify/$ca_name"

```
# CMS(Cryptographic Message Syntax) 메시지 서비스

CMS 암호화(cms_encrypt)
```
#메시지(eg, plain.txt)를 인증서로 암호화하고 CMS(EnvelopedMessage)로 인코딩
#cipher : aes-128-cbc/aes-192-cbc/aes-256-cbc
#serial : 암호화에 사용될 인증서의 시리얼번호($ca_name이 발급한 인증서에만 해당함) - 필수
#outformat : pem/smime(Default)
curl -fk --data-binary @plain.txt -o plain.txt.enc "https://localhost/cms_encrypt/$ca_name?cipher=aes-192-cbc&serial=<SERIAL>&outformat=pem"
curl -fk --data-binary @plain.txt "https://localhost/cms_encrypt/$ca_name?serial=<SERIAL>"
#run.sh 사용시
./run.sh cms_encrypt plain.txt <SERIAL>
```

CMS 복호화(cms_decrypt) - 임시
```
#CMS메시지를 복호화하고 원문을 반환, 개인키가 필요하며 현재 이 기능은 데모용으로만 제공됨

#serial : 암호화에 사용될 인증서의 시리얼번호($ca_name이 발급한 인증서에만 해당함) - 필수
#outformat : pem/smime(Default)
curl -fk --data-binary @plain.txt.enc -o plain.txt.dec "https://localhost/cms_decrypt/$ca_name?serial=<SERIAL>&outformat=pem"
curl -fk --data-binary @plain.txt.enc "https://localhost/cms_decrypt/$ca_name?serial=<SERIAL>"

#run.sh 사용시
./run.sh cms_decrypt plain.txt.enc <SERIAL>

```


CMS 서명(cms_sign) - 임시
```
#메시지에 전자서명을 추가 CMS(SignedMessage)를 생성, 개인키가 필요하며 현재 이 기능은 데모용으로만 제공됨

#serial : 암호화에 사용될 인증서의 시리얼번호($ca_name이 발급한 인증서에만 해당함) - 필수
#outformat : pem/smime(Default)
curl -fk --data-binary @plain.txt -o plain.txt.sign "https://localhost/cms_sign/$ca_name?serial=<SERIAL>&outformat=pem"
curl -fk --data-binary @plain.txt "https://localhost/cms_sign/$ca_name?serial=<SERIAL>"

#run.sh 사용시
./run.sh cms_sign plain.txt <SERIAL>

```


CMS 검증(cms_verify)
```
#CMS(SignedMessage)의 서명이 올바른지 검증

#outformat : pem/smime(Default)
curl -fk --data-binary @plain.txt.cms -o result.txt "https://localhost/cms_verify/$ca_name"
curl -fk --data-binary @plain.txt.cms "https://localhost/cms_verify/$ca_name"

#run.sh 사용시
./run.sh cms_verify plain.txt.cms 

```


CMS 메시지 파싱(cms_parse)
```
#CMS(SignedMessage) 구문을 분석(parsing)하여 텍스트로 

#outformat : pem/smime(Default)
curl -fk --data-binary @plain.txt.cms -o result.txt "https://localhost/cms_parse/$ca_name"
curl -fk --data-binary @plain.txt.cms "https://localhost/cms_parse/$ca_name"

#run.sh 사용시
./run.sh cms_parse plain.txt.cms 

```

OCSP 검증(ocsp_verify)
```
#my.pem 인증서의 유효성을 검증
curl -fk --data-binary @my.pem   "https://localhost/ocsp_verify/$ca_name"

```



# 다중 인증 기관(Multi Certificate Authority) 설정

CA 서비스는 여러 인증서를 동시에 발급할 수 있다(다중 인증 기관: Multiple-CA)

```
docker run -d -p 80:8080 -p 443:8443 \
  -e CA_LIST=ca1,ca2,ca3 \
  -e CA_CN_ca1="CA1 server" \
  -e CA_CN_ca2="CA2" \
  -e CA_CN_ca3="ca3 certiciate authority" \
  jkkim7202/pkizone:latest
  
openssl req -new -newkey rsa:2048 -keyout ca1.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o ca1.pem "https://localhost/sign/ca1?cn=ca1"
openssl req -new -newkey rsa:2048 -keyout ca2-key.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o ca2.pem "https://localhost/sign/ca2?cn=ca2 admin&o=system:masters"
```

* /ssl/ca 폴더에 인증 기관의 인증서와 환경 설정 정보가 추가된다.

* `/sign` and `/xsign`은 `default` 인증 기관을 의미한다.
* `/sign/<ca_id>`, `/xsign/<ca_id>`은 <ca_id>에 대응되는 인증기관의 설정을 사용한다 

TLS 설정
* TLS 인증서가 별도로 설정되지 않으면, PKIZONE은 다음 순서대로 1회용 인증서를 생성한다. 
* 'CA_DEFAULT'에 해당하는 CA로 인증서 생성
* `CA_LIST`에 명시된 첫번째 인증 기관 설정을 이용, TLS 인증서 생성


# 파라메터(Parameters)

인증서 발급을 파라메터(xsign도 동일): '/sign', '/xsign' 메소드:

* `dn`: 인증서 DN(Distinguished name), 형식은 다음과 같다: `/O=.../OU=.../.../CN=...`
* `cn`: 사용자 이름(Common name): `/CN=` 형식으로 지정
* `o`: 조직명(소문자 o를 사용)
* `ip`: 사용자 IP 주소. IP주소가 주어지면 서버 인증서를 생성한다
* `ns`: 네임서버(ip, ns는 ","로 분리된 리스트를 사용할 수 있다). `ip`나 `ns`가 제공되면 서버 인증서를 그렇지 않은 경우 클라이언트 인증서를 생성한다
* `days`: 인증서 유효기간
* `token`: 인증서 발급시 제공해야 하는 토큰, "사용자ID:서명값"으로 구성된다.
* `keygen`: xsign 메소드에서 사용, 개인키를 서버에서 생성하기 원하는 경우, "알고리즘:파라메터" 형식으로 제공.

# PKIZONE 옵션

인증서버 구동을 위한 환경설정:

* `CRT_DAYS`: 발급된 인증서 유효기간, 디폴트는 365(days). `&days=<days>`와 같이 변경 가능
* `CA_DAYS`: CA 인증서 유효기간(자동 생성인 경우에만 적용). 디폴트는 10년(3652(days).
* `CA_CN`: CA 자동 생성 시 CA 인증서의 CN값을 지정
* `CERT_TLS`: TLS 인증서(https), 디폴트: `/ssl/www/localhost.pem`. 파일이 존재하지 않으면 자동으로 생성된다
* `CERT_TLS_DNS`: CA 서버 DNS, TLS 인증서를 자동 생성하는 경우 적용된다(`CERT_TLS_DNS`, `CERT_TLS_IP`, 둘 중 하나는 설정되어야 한다)
* `CERT_TLS_IP`: CA 서버 공인 IP. `CERT_TLS_DNS`와 동일한 설정을 사용.
* `CERT_TLS_DAYS`: CA 서버 TLS 인증서의 유효기간(default: 365 days)

When using multi certificate authority, the following environment variables might also be defined:

* `CA_LIST`: comma separated list of IDs of CAs. IDs must match `[a-z0-9_]`. The default value is one certificate authority: `default`
* `CA_DEFAULT`: ID of the certificate authority that should be used on `/sign` and `/ca` methods. `default` is used if not provided. Note that if `CA_LIST` doesn't include `default` and `CA_DEFAULT` isn't provided, `/sign` and `/ca` methods will issue `404 Not Found`.
* `CRT_DAYS_<ca_id>`: override default `CRT_DAYS`
* `CA_DAYS_<ca_id>`: override default `CA_DAYS`
* `CA_CN_<ca_id>`: override default `CA_CN`

# 운영 적용

* `/ssl` 디렉토리가 마운트 되어야 한다. 인증서 생성 정보가 저장되는 디렉토리

# 로그

* `/ssl/ca/pkizone.log` 파일 참조
