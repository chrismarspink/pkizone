# PKIZONE

OpenSSL 기반의 인증서 발급 서비스


# 사용자(클라이언트)

클라이언트는 최종 사용자(End User) 또는 최종 사용자에게 인증서 발급을 대행하는
역할을 수행할 수 있다
클라이언트는 CA에 등록된 사용자로, 자격 증명을 위한 개인키, 공개키 쌍을 생성해야 한다. 

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
curl "https://localhost/ticket/my-ca_name"
```

인증기관 접근 토큰 생성 - create ca token(script)
```
##ticket에 클라이언트 개인키로 서명한 값인 토큰을 생성한다.
##인증서 발급 신청을 위해서는 토큰을 CA에 제시, 신청자가 클라이언트 자신임을 증명해야 한다.
token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"
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

* docker-compose.yml 파일
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
Create a private key and certificate request:

```
openssl req -new -newkey rsa:2048 -keyout host-key.pem -nodes -out host.csr -subj "/"
```

Sign the certificate -- change `localhost` to the IP if Docker Server is on a VM - eg Docker Machine:

```
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ns=my-host.localdomain"
```

Check the certificate:

```
openssl x509 -noout -text -in host.pem
```

Using `dn` instead `cn`:

```
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?dn=/CN=my-host&ns=my-host.localdomain"
```

Shortcut to organizationName and `dn` syntax - Note that `ca.cnf` changed on `0.7`,
you should update or remove `<local-ca-dir>/ssl/ca/ca.cnf` before restart `pkizone`:

```
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&o=company&ns=my-host.localdomain"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?dn=/CN=my-host/O=company&ns=my-host.localdomain"
```



One liner key and cert:

```
openssl req -new -newkey rsa:2048 -keyout host-key.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o host.pem "https://localhost/sign?cn=my-host&ns=my-host.localdomain"
```

Using subject from the request - `cn` is optional since `0.7`:

```
openssl req -new -newkey rsa:2048 -keyout host-key.pem -nodes -subj "/CN=my-host" | \
  curl -fk --data-binary @- -o host.pem "https://localhost/sign?ns=my-host.localdomain"
```

Using alternative IP, NS or both:

**Note:** If neither IP nor NS is provided, a client certificate would be generated. Always provide IP, NS or both for server certificates.

```
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ip=10.0.0.1"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ip=10.0.0.1,192.168.0.1"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ns=localhost,my-host.localdomain"
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&ip=10.0.0.1&ns=my-host.localdomain"
```

Using alternative number of days:

```
curl -fk --data-binary @host.csr -o host.pem "https://localhost/sign?cn=my-host&days=30"
```

The signing of certificates can also be protected with a token:

```
echo -n "mysupersecret" | md5sum
docker run -d -p 80:8080 -p 443:8443 \
  -e TOKEN=md5:6dc90cbae61d22f5cd1ca3f4025c47a3 \
  jkkim7202/pkizone:latest
```

Now `/sign` method must provide `&token=mysupersecret` param, otherwise the certificate won't be signed. If using echo to generate the hash, remember to use `-n` so echo won't add a line break into your secret.

# 다중 인증 기관(Multi Certificate Authority)

CA 서비스는 여러 인증서를 동시에 발급할 수 있다(다중 인증 기관: Multiple-CA)

```
docker run -d -p 80:8080 -p 443:8443 \
  -e CA_LIST=ca1,ca2,ca3 \
  -e CA_CN_servers="CA1 server" \
  -e CA_CN_etcd="CA2" \
  -e CA_CN_kube="ca3 certiciate authority" \
  jkkim7202/pkizone:latest
openssl req -new -newkey rsa:2048 -keyout ca1.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o ca1.pem "https://localhost/sign/ca1?cn=ca1"
openssl req -new -newkey rsa:2048 -keyout ca2-key.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o ca2.pem "https://localhost/sign/ca2?cn=ca2 admin&o=system:masters"
```

/ssl/ca 폴더에 인증 기관의 인증서와 환경 설정 정보가 추가된다.

Both syntax are still valid: `/sign` and `/ca` using `default` certificate authority, and the new `/sign/<ca_id>` and `/ca/<ca_id>`. The ID of the certificate authority of the first syntax can be changed declaring `CA_DEFAULT` environment variable.

If TLS certificate for https isn't provided, the CA which will sign the certificate will be chosen in the following order:

* Certificate authority declared with `CA_DEFAULT`, which defaults to `default`
* If the above certificate authority ID does not exist, the first certificate authority declared on `CA_LIST` will be used

New certificate authorities can be included updating `CA_LIST` environment variable. 

Note that removing CAs from the `CA_LIST` will deny the access from `/sign` and `/ca` methods but won't remove it from the schema. If the CA is reincluded to the list, the same CA cert and private key will continue to sign certificates.

# Parameters

The following parameters can be used in the query string of the `/sign` method:

* `dn`: Distinguished name in the following format: `/O=.../OU=.../.../CN=...`
* `cn`: Common name of the certificate - do not use the `/CN=` prefix
* `o`: Comma separated list of organizationName - do not use the `/O=` prefix
* `ip`: Comma separated list of IPs of server certificate
* `ns`: Comma separated list of name servers of server certificate. Either `ip` or `ns` must be provided for server certificates, otherwise a client certificate will be generated
* `days`: The number of days to certify the signed certificate
* `token`: Security token, should be provided when signing certificates if the server was started with `TOKEN` envvar

# Options

The following optional environment variables may be defined:

* `TOKEN`: hash of the secret token. If defined the `&token=` is mandatory and must match the value. The token has the following format: `<algorithm>:<hash-itself>`. The currently supported algorithms are `md5`, `sha1`, `sha256` and `sha512`
* `CRT_DAYS`: default number of days to certify signed certificates, defaults to 365, can be changed per signed certificate with `&days=<days>`
* `CA_DAYS`: number of days to certify the auto generated CA certificate, defaults to 3652 (10 years)
* `CA_DIR`: path to directory of all certificate authorities. A new cert and key will be created for any CA if not found
* `CA_CN`: A self generated CA will use `CA_CN` as its common name, defaults to `my-ca`
* `CERT_TLS`: TLS certificate and key file used by web server to provide https, defaults to `/ssl/www/localhost.pem`. If not found, CA itself will sign a certificate
* `CERT_TLS_DNS`: name server of the CA server, used on auto generated TLS certificate. At least one of `CERT_TLS_DNS` or `CERT_TLS_IP` should be provided
* `CERT_TLS_IP`: public IP of the CA server, used on auto generated TLS certificate. At least one of `CERT_TLS_DNS` or `CERT_TLS_IP` should be provided
* `CERT_TLS_DAYS`: number of days to certify the CA server cert, used on auto generated TLS certificate, defaults to 365 days

When using multi certificate authority, the following environment variables might also be defined:

* `CA_LIST`: comma separated list of IDs of CAs. IDs must match `[a-z0-9_]`. The default value is one certificate authority: `default`
* `CA_DEFAULT`: ID of the certificate authority that should be used on `/sign` and `/ca` methods. `default` is used if not provided. Note that if `CA_LIST` doesn't include `default` and `CA_DEFAULT` isn't provided, `/sign` and `/ca` methods will issue `404 Not Found`.
* `CRT_DAYS_<ca_id>`: override default `CRT_DAYS`
* `CA_DAYS_<ca_id>`: override default `CA_DAYS`
* `CA_CN_<ca_id>`: override default `CA_CN`

# Deploy

* Mount the `/ssl` directory to ensure that nothing will be lost if the container is recreated
* The external directory should be owned by container's `lighttpd` user (uid 100)

This systemd unit has the most common configuration:

```
[Unit]
Description=Simple CA
After=docker.service
Requires=docker.service
[Service]
ExecStartPre=-/usr/bin/docker stop my-ca
ExecStartPre=-/usr/bin/docker rm my-ca
ExecStartPre=/usr/bin/mkdir -p /var/lib/my-ca/ssl
ExecStartPre=/bin/bash -c 'chown $(docker run --rm jkkim7202/pkizone:latest id -u lighttpd) /var/lib/my-ca/ssl'
ExecStart=/usr/bin/docker run \
  --name my-ca \
  -p 80:8080 \
  -p 443:8443 \
  -e CERT_TLS_DNS=ca.mycompany.com \
  -e CA_CN=MyCompany-CA \
  -v /var/lib/my-ca/ssl:/ssl \
  jkkim7202/pkizone:latest
RestartSec=10s
Restart=always
[Install]
WantedBy=multi-user.target
```
