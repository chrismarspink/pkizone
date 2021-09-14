#!/bin/bash
set -e

VERSION="Verion: 1.0.1"
DATE=$(date "+%Y%M%d%H%m.%S")
PROG="PKIZONE(c), GreenZone Security Co., Ltd. All rights reserved."

VERIFIED_OK="Verified OK"


d() {
  date -u '+%Y/%m/%d %H:%M:%S GMT'
}

badRequest() {
  echo "HTTP/1.1 400 Bad Request"
  echo "Content-Type: text/plain"
  echo
  echo "$*"
  echo "$*" | sed "s;^;[$(d)] ERROR - ;" >&2
  exit 1  
}

notFound() {
  echo "HTTP/1.1 404 Not Found"
  echo "Content-Type: text/plain"
  echo
  echo "404 Not Found"
  exit 1  
}

unAuthorized() {
  echo "HTTP/1.1 401 Unauthorized"
  echo "Content-Type: text/plain"
  echo
  echo "401 Unauthorized"
  exit 1  
}

info() {
  echo "[$(d)] $*" >&2
}

#1 token
checktoken() {
  info "TOKEN: $TOKEN"
  IFS=":" read -r algo hash <<<"$TOKEN"
  info "algo: $algo"
  info "hash: $hash"  
  [ -z "$hash" ] && echo "Hash algorithm wasn't provided" && return 1
  case "$algo" in
    md5|sha1|sha256|sha512) check=$(echo -n "$1" | openssl dgst -$algo -r | cut -d' ' -f1) ;;
    *) echo "Unsupported algorithm: $algo" && return 1 ;;
  esac
  info "check: $check"
  info "hash $hash"
  info "in token: $1"
  [ "$check" != "$hash" ] && echo "Invalid token" && return 1
  return 0
}


### sign() exec as a subprocess - do not write HTTP headers
#1 Output
sign() {
  local paramOutput=$1
  unset dn cn ip ns o days ou c keygen token
  # No decode, no space from QUERY_STRING
  for param in ${QUERY_STRING//&/ }; do
    varname="${param%%=*}"
    varvalue="${param#*=}"
    case "$varname" in
      dn) dn=$varvalue ;;
      cn) cn=$varvalue ;;
      ip) ip=$varvalue ;;
      ns) ns=$varvalue ;;
      o) o=$varvalue ;;
      ou) ou=$varvalue ;;
      c) c=$varvalue ;;
      days) days=$varvalue ;;
      token) token=$varvalue ;;
      keygen) keygen=$varvalue;;
    esac
  done

  info "sign) get token: $token"

  [ -n "$TOKEN" ] && ! checktoken "$token" && return 1
  [ -n "$cn" -a -n "$dn" ] && echo "Pick either cn or dn" && return 1

  [ -z "$dn" -a -n "$cn" ] && dn="/CN=$cn"
  for vo in ${o//,/ }; do
    dn+="/O=$vo"
  done

  export RANDFILE=.rnd
  exec 100<ca.cnf && \
  flock 100 && \
  openssl ca \
    -batch \
    -config ca.cnf \
    $([ -n "$dn" ] && echo "-subj $dn" || :) \
    -notext \
    $([ -n "$days" ] && echo "-days $days" || :) \
    -in <(cat -) \
    -passin file:/run/secrets/"$ca_id"_password \
    -out "$paramOutput" \
    -extfile <(
      echo "basicConstraints = CA:FALSE"
      echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment"
      echo "extendedKeyUsage = clientAuth$([ -n "$ip$ns" ] && echo ", serverAuth")"
      if [ -n "$ip" ] || [ -n "$ns" ]; then
        echo "subjectAltName = @alt_names"
        echo "[ alt_names ]"
        i=1
        for alt_ip in ${ip//,/ }; do
          echo "IP.${i} = $alt_ip"
          ((i++))
        done
        i=1
        for alt_ns in ${ns//,/ }; do
          echo "DNS.${i} = $alt_ns"
          ((i++))
        done
      fi
    )
}


xsign() {
  local paramOutput=$1
  unset dn cn ip ns o days ou c keygen token
  # No decode, no space from QUERY_STRING
  for param in ${QUERY_STRING//&/ }; do
    varname="${param%%=*}"
    varvalue="${param#*=}"
    case "$varname" in
      dn) dn=$varvalue ;;
      cn) cn=$varvalue ;;
      ip) ip=$varvalue ;;
      ns) ns=$varvalue ;;
      o) o=$varvalue ;;
      ou) ou=$varvalue ;;
      c) c=$varvalue ;;
      days) days=$varvalue ;;
      token) token=$varvalue ;;
      keygen) keygen=$varvalue;;
    esac
  done

  info "do xsign - certificate with keypair"
  info "get token: $token"
  [ -n "$TOKEN" ] && ! checktoken "$token" && return 1
  [ -n "$cn" -a -n "$dn" ] && echo "Pick either cn or dn" && return 1

  [ -z "$dn" -a -n "$cn" ] && dn="/CN=$cn"
  for vo in ${o//,/ }; do
    dn+="/O=$vo"
  done

  mydate=$(date "+%Y%M%d%H%m.%S")

  KEY=/tmp/key-$mydate.pem
  REQ=/tmp/req-$mydate.pem

  trap "rm -f $KEY" EXIT
  trap "rm -f $REQ" EXIT

  info "key file: $KEY"
  info "req file: $REQ"

  info "keygen: $keygen"

  if [[ -n $keygen ]] && [[ $keygen =~ ^rsa ]]; then
    
    openssl req -new -newkey $keygen -keyout "$KEY" -nodes -out "$REQ" -subj "/"
    CSR=$(openssl req -in "$REQ" -text -noout)
    info "RSA.CSR: $CSR"

  elif [[ -n $keygen ]] && [[ $keygen =~ ^ecc ]]; then
    param=$(echo -n "$keygen" |  cut -d':' -f2) ;
    info "ECC CURVE: $param"
    openssl ecparam -genkey -name $param  -out $KEY
    openssl req -new -key $KEY  -out $REQ -subj "/"

    info "tmp-reqfile($REQ): $(cat $REQ)"
     
  fi

  export RANDFILE=.rnd
  exec 100<ca.cnf && \
  flock 100 && \
  openssl ca \
    -batch \
    -config ca.cnf \
    $([ -n "$dn" ] && echo "-subj $dn" || :) \
    -notext \
    $([ -n "$days" ] && echo "-days $days" || :) \
    -in $REQ  \
    -passin file:/run/secrets/"$ca_id"_password \
    -out "$paramOutput" \
    -extfile <(
      echo "basicConstraints = CA:FALSE"
      echo "keyUsage = nonRepudiation, digitalSignature, keyEncipherment"
      echo "extendedKeyUsage = clientAuth$([ -n "$ip$ns" ] && echo ", serverAuth")"
      if [ -n "$ip" ] || [ -n "$ns" ]; then
        echo "subjectAltName = @alt_names"
        echo "[ alt_names ]"
        i=1
        for alt_ip in ${ip//,/ }; do
          echo "IP.${i} = $alt_ip"
          ((i++))
        done
        i=1
        for alt_ns in ${ns//,/ }; do
          echo "DNS.${i} = $alt_ns"
          ((i++))
        done
      fi
    )

  cat $KEY >> $paramOutput
}

upload-file(){
  file=/tmp/$$-$RANDOM

  # CGI output must start with at least empty line (or headers)
  printf '\r\n'
    cat <<EOF
<html>
<head>
<title>Upload</title>
<meta http-equiv="Content-Type" content="text/html; charset=iso-8859-1" />
</head>
<body>
EOF

  IFS=$'\r'
  read -r delim_line

  IFS=''
  delim_line="${delim_line}--"$'\r'

  read -r line
  filename=$(echo $line | sed 's/^.*filename=//' | sed 's/\"//g' | sed 's/.$//')
  fileext=${filename##*.}

  while read -r line; do
    test "$line" = '' && break
    test "$line" = $'\r' && break
  done

  # Note: This will result in junk at end of line (see format above)
  cat > $file

  # Get the line count
  LINES=$(wc -l $file | cut -d ' ' -f 1)

  # Remove the last line
  head -$((LINES - 1)) $file >$file.1

  # Copy eveything but the last line to a temp file
  head -$((LINES - 2)) $file.1 >$file.2

  # Copy the new last line but remove trailing \r\n
  tail -1 $file.1 > $file.3
  tail -c 2 $file.3 > $file.5
  CRLF=$(hexdump -ve '/1 "%.2x"' $file.5)
  # Check if the last two bytes are \r\n
  if [ "$CRLF" = "0d0a" ];then
    BYTES=$(wc -c $file.3 | cut -d ' ' -f 1)
    truncate -s $((BYTES-2)) $file.3
  fi

  rm $file.5
  cat $file.2 $file.3 > $file.4
  cp $file.4 $file

  cat <<EOF
<h1>Upload Successful</h1>
EOF

  cat <<EOF
</body>
</html>
EOF

  exit 0

}

##---------- ----------
## CMS encrypt ver1
## no security
##---------- ----------
cms-encrypt() {
  local paramOutput=$1
  unset from to subject enc serial
  # No decode, no space from QUERY_STRING
  for param in ${QUERY_STRING//&/ }; do
    varname="${param%%=*}"
    varvalue="${param#*=}"
    case "$varname" in
      from) from=$varvalue ;;
      to) to=$varvalue ;;
      subject) subject=$varvalue ;;
      serial) serial=$varvalue ;;
    esac
  done

  mydate=$(date "+%Y%M%d%H%m.%S")

  info "command: openssl cms -encrypt -in <(cat -) -out $paramOutput -aes256 ./newcerts/$serial.pem"
  openssl cms -encrypt -in <(cat -) -out $paramOutput -aes256 ./newcerts/$serial.pem
  #openssl cms -aes256 \
  #  $([ -n "$from" ] && echo "-from $from" || :) \
  #  $([ -n "$subject" ] && echo "-subject $subject" || :) \
  #  $([ -n "$to" ] && echo "-to $to" || :) \
  #  -in <(cat -) \
  #  -out "$paramOutput" \
  #  ./newcerts/$serial.pem


  info $(cat $paramOutput)
}

revoke() {
  local paramOutput=$1
  info "paramOutput: $paramOutput"
  openssl x509   -in <(cat -)  -out $paramOutput
  
  info "revoked cert: $(cat $paramOut)"
  exec 100<ca.cnf &&  flock 100 &&  openssl ca -batch -config ca.cnf -passin file:/run/secrets/"$ca_id"_password  -revoke $paramOutput
}

gencrl() {
  local paramOutput=$1
  info "generate crl..."
  exec 100<ca.cnf &&  flock 100 &&  openssl ca  -config ca.cnf  -gencrl -out ./crl/crl.pem -passin file:/run/serets/"$ca_id"_password
  openssl crl -passin file:/run/secrets/"$ca_id"_password   -in ./crl/crl.pem -text -noout -out $paramOutput
  info "CRL DATA: $(cat $paramOutput)"
}


clientadd_new() {
  info "client registration, 2" 
  info "QS: $QUERY_STRING"
}


clientadd() {
  local pubkeyfile=$1
  nset clientid token publickey dn cn ip ns o days ou c keygen
  for param in ${QUERY_STRING//&/ }; do
    varname="${param%%=*}"
    varvalue="${param#*=}"
    case "$varname" in
      clientid) clientid=$varvalue ;;
      token) token=$varvalue ;;
      publickey) publickey=$varvalue ;;
    esac
  done

  info "client registration, 2" 

  [ ! -n "$clientid"  ] && echo "no client id supplied" >&2  && return 1
  [ ! -n "$token" ] && echo "no client token supplied" >&2 && return 1

  info "client registration, id=[$clientid], token=[$token]"
  info "tmpfile(public key file): $pubkeyfile"

  ##1. ticket file for verify client token
  ticketfile=./ca.ticket

  #2. publickey를 저장
  openssl ec -pubin -in <(cat -) -outform PEM -out $pubkeyfile

  #3. verify client token
  echo  $token | openssl base64 -d > $pubkeyfile.sig

  #echo "dec token ==> $detoken"
  result="$(openssl dgst -sha1 -verify $pubkeyfile -signature $pubkeyfile.sig $ticketfile)"
  info "verify result ==> [$result]" 

  if [[ $result == $VERIFIED_OK ]]; then 
    info "cp pubkey file to clients"
    info "remove sig file."
    info "temp pubkey file is trapped on EXIT 배리파이 성공"
    cp $pubkeyfile ./clients/$clientid.pub
    echo $clientid > $pubkeyfile
    
  else 
    info "error: $result"
  fi

  rm $pubkeyfile.sig

}

##
## 전제조건
## xsign ==> 
    #### 일회용 키로 암호화 + 키를 메일로 전달
    #### 메일주소를 키로 사용
#### sign/xsign으로 생성된 경우에 한해 가능
    #### ENC 가능
    #### DEC: 자신의 개인키가 필요 - 불가능
    #### SIGN: 자신의 개인키가 필요 - 불가능
    #### VERIFY: 쌉 가능
## register --> mykey hash를 생성  md4
## CMS-API를 위한 등록 과정 수행 --> 인증서마다 고유의 ID를 부여
## CMS-ENC: infile, GET(certid)
## CMS-DEC: infile, GET(keyid: pkey, certificate)
## CMS-SIGN: infile, mykeyid
## CMS-VERIFY: infile, cacert
##
findcert() {
  local paramOutput=$1
  unset dn cn ip ns o days ou c keygen token
  for param in ${QUERY_STRING//&/ }; do
    varname="${param%%=*}"
    varvalue="${param#*=}"
    case "$varname" in
      dn) dn=$varvalue ;;
      cn) cn=$varvalue ;;
      ip) ip=$varvalue ;;
      serial) serial=$varvalue ;;
    esac
  done

  info "do findcert- find certificate, without private key"
  #[ -n "$cn" -a -n "$serial" ] && echo "Pick either cn or dn" && return 1

  case "$varname" in
    serial)
      lines=`grep -i "$serial" index.txt`
      for x in $lines; do   # <--- isn't this an array
        info "line: $x" 
        result=$(echo $x | cut -f3)     
        if [ "$result" == "$serial" ]; then 
          certstr=$(openssl x509 -in ./newcerts/$serial.pem -text)
          echo $certstr >> paramOutput
        fi
      done
      ;;
    cn)
      info "find certificate with comman name"
      ;;
  esac
}


# breakdown /<ca_method>[/<ca_id>]
IFS="/" read -r ca_method ca_id <<<"${PATH_INFO#/}"
ca_id="${ca_id:-$CA_DEFAULT}"
grep -Eq ",${ca_id}," <<<",${CA_LIST}," || notFound
cd "$CA_DIR/$ca_id" 2>/dev/null || notFound
case "$ca_method" in
  test)
    info "hello ..."
    out=ca.pem
    ;;
  ## ---------- ----------
  ## 일단 보안 무시하고 암호화
  ## ---------- ----------
  cms-encrypt)  
    CMS=/tmp/cms-enc-out-$$.pem
    trap "rm -f $CMS" EXIT
    err=$(cms-encrypt "$CMS" 2>&1)  || badRequest "$err"
    info "Encrypt with CMS(2): $(openssl cms -cmsout -in $CMS -text)"
    out=$CMS
    ;;
  sign)  
    CRT=/tmp/crt-$$.pem
    trap "rm -f $CRT" EXIT
    err=$(sign "$CRT" 2>&1)  || badRequest "$err"
    info "New cert: $(openssl x509 -noout -subject -in $CRT)"
    out=$CRT
    ;;
  xsign)  
    XCRT=/tmp/xcrt-$$.pem
    trap "rm -f $XCRT" EXIT
    err=$(xsign "$XCRT" 2>&1) || badRequest "$err"
    info "new keypair and certificate generated($XCRT): $(openssl x509 -noout -subject -in $XCRT)"
    out=$XCRT
    ;;
  cacert)
    out=ca.pem
    info "CA cert($ca_id): $(openssl x509 -noout -subject -in ca.pem)"
    ;;
  revoke)
    revoke_subj=/tmp/revoke_subj-$$.pem
    trap "rm -f $revoke_subj" EXIT
    err=$(revoke "$revoke_subj" 2>&1) || badRequest "$err"
    info "Revoke cert, $revoke_subj"
    out=$revoke_subj
    ;;
  gencrl)
    crldata=/tmp/crldata-$$.pem
    trap "rm -f $crldata" EXIT
    err=$(gencrl "$crldata" 2>&1) || badRequest "$err"
    info "crl-data(2): $crldata"
    out=./crl/crl.pem
    ;;
  crl)
    info "download crl"
    out=./crl/crl.pem
    ;;
  ticket)
    ticketfile=ca.ticket
    out=$ticketfile
    t="$(cat $out)"
    info "ticket file: $out"
    out=$ticketfile
    ;;
  clientadd)
    tmpid=/tmp/clientid-pubkey-$$.pem
    trap "rm -f $tmpid" EXIT
    info "begin add client ==> tmpclientid file: $tmpid"
    err=$(clientadd "$tmpid"  ) || badRequest "$err"
    info "end add client..."
    out=$tmpid
    ;;
  database)
    info "download database"
    out=index.txt
    ;;
  info)
    info "get version"
    echo $PROG     > /tmp/pkizone.info
    echo $VERSION >> /tmp/pkizone.info
    echo $DATE    >> /tmp/pkizone.info
    out=/tmp/pkizone.info
    ;;

  findcert)
    tmpcert=/tmp/tmp-certificate-$$.pem
    info "search: tmpfile=$tmpcert"
    trap "rm -f $tmpcert" EXIT

    err=$(searchcertificate "$tmpcert"  ) || badRequest "$err"

    out=$tmpcert
    ;;

  *)
    notFound
    ;;
esac

echo "HTTP/1.1 200 OK"
echo "Content-Type: text/plain"
echo
cat "$out"
