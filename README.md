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

create client sign key and public key
```
client_sign_key=sign.key
client_sign_pub=sign.pub
openssl ecparam -genkey -name $client_sign_alg -noout -out $client_sign_key
openssl ec -in $client_sign_key -pubout -out $client_sign_pub
```

CA  create access token
```
curl -fk -o ./ca_name.ticket "https://localhost/ticket/my-ca_name
curl "https://localhost/ticket/my-ca_name"
```

create ca token(script)
```
token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"
```



# Usage

Run the CA:

```
docker run -d -p 80:8080 -p 443:8443 jkkim7202/pkizone:latest
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
  quay.io/jcmoraisjr/simple-ca
```

Now `/sign` method must provide `&token=mysupersecret` param, otherwise the certificate won't be signed. If using echo to generate the hash, remember to use `-n` so echo won't add a line break into your secret.

# Multi Certificate Authority

Since 0.8 simple-ca has support for multiple certificate authorities:

```
docker run -d -p 80:8080 -p 443:8443 \
  -e CA_LIST=servers,etcd,kube \
  -e CA_CN_servers="CA for servers" \
  -e CA_CN_etcd="Etcd CA" \
  -e CA_CN_kube="Kubernetes CA" \
  quay.io/jcmoraisjr/simple-ca
openssl req -new -newkey rsa:2048 -keyout kube-etcd-key.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o kube-etcd.pem "https://localhost/sign/etcd?cn=kube"
openssl req -new -newkey rsa:2048 -keyout kube-admin-key.pem -nodes -subj "/" | \
  curl -fk --data-binary @- -o kube-admin.pem "https://localhost/sign/kube?cn=admin&o=system:masters"
```

When running 0.8 the first time on a schema of an old version, simple-ca will update to the new schema creating the CA `default`. All new certificate authorities are created as sub-directories of `/ssl/ca`.

Both syntax are still valid: `/sign` and `/ca` using `default` certificate authority, and the new `/sign/<ca_id>` and `/ca/<ca_id>`. The ID of the certificate authority of the first syntax can be changed declaring `CA_DEFAULT` environment variable.

If TLS certificate for https isn't provided, the CA which will sign the certificate will be chosen in the following order:

* Certificate authority declared with `CA_DEFAULT`, which defaults to `default`
* If the above certificate authority ID does not exist, the first certificate authority declared on `CA_LIST` will be used

New certificate authorities can be included updating `CA_LIST` environment variable. The next start of simple-ca will update the schema.

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
ExecStartPre=-/usr/bin/docker stop simple-ca
ExecStartPre=-/usr/bin/docker rm simple-ca
ExecStartPre=/usr/bin/mkdir -p /var/lib/simple-ca/ssl
ExecStartPre=/bin/bash -c 'chown $(docker run --rm quay.io/jcmoraisjr/simple-ca id -u lighttpd) /var/lib/simple-ca/ssl'
ExecStart=/usr/bin/docker run \
  --name simple-ca \
  -p 80:8080 \
  -p 443:8443 \
  -e CERT_TLS_DNS=ca.mycompany.com \
  -e CA_CN=MyCompany-CA \
  -v /var/lib/simple-ca/ssl:/ssl \
  quay.io/jcmoraisjr/simple-ca:latest
RestartSec=10s
Restart=always
[Install]
WantedBy=multi-user.target
```
