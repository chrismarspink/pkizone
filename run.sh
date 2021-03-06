#!/bin/bash
set -e

LOCAL_HOST_NAME="jkkimui-MacBookPro.local"
SERVICE_HOST_NAME="ip-172-31-13-17"

mydate=$(date "+%Y%M%d%H%m.%S")
#hostname=$(hostname)
hostname=$LOCAL_HOST_NAME
if [ $hostname == $SERVICE_HOST_NAME ]; then
    echo "hostname: $hostname"
    pkizone_src=./
    ca_home=/home/ubuntu/ca.service/ssl/ca
    server=https://3.37.221.15
    client_secret="mysecret"

else
    echo ""
    echo "-----------------------"
    echo "build on localhost"
    echo "-----------------------"
    pkizone_src=./
    ca_home=/Users/jkkim/dev/ca.service/ssl/ca
    server=https://127.0.0.1
    client_secret="mysecret"
    
fi 

#tk=$(echo -n $client_secret | md5sum)
tk=$(echo -n "$client_secret" | openssl dgst -md5 -r | cut -d' ' -f1) 
server_token="md5:$tk"

echo "hostname      : $hostname"
echo "src           : $pkizone_src"
echo "server        : $server"
echo "cahome        : $ca_home"
echo "client secret : $client_secret"
echo "server token  : $server_token"

sign=$server/sign
xsign=$server/xsign
revoke=$server/revoke
gencrl=$server/gencrl
crl=$server/crl
ticket=$server/ticket
clientadd=$server/clientadd
test=$server/test
cms_encrypt=$server/cms_encrypt
cms_decrypt=$server/cms_decrypt
cms_sign=$server/cms_sign
cms_verify=$server/cms_verify
cms_parse=$server/cms_parse

ocsp_verify=$server/ocsp_verify
database=$server/database

#client_sign_key=./sign.key
#client_sign_pub=./sign.pub
client_sign_alg=secp112r1

ca_name=iot_smarthome

clientid=jkkim@ermind.co.kr

#swam mode init
command=$1
case "$command" in
    install)
        sudo apt install docker.io
        sudo curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        ;;
    build)
        echo "------------------------------"
        echo "Build docker image            "
        echo "------------------------------"
        ##./build.sh 
        docker build --tag pkizone:latest $pkizone_src
        ;;
    login)
        docker login
        ;;
    release)
        echo "------------------------------"
        echo "push to Docker Hub.           "
        echo "------------------------------"
        ##./release.sh $2
        set -x
        docker build --tag pkizone:$2 $pkizone_src
        docker tag pkizone:$2 jkkim7202/pkizone:$2
        docker push jkkim7202/pkizone:$2

        #docker tag pkizone:$2 jkkim7202/pkizone:latest
       # docker push jkkim7202/pkizone:latest
        ;;
    pkizone-secret)
        docker secret create iot_smarthome_password iot_smarthome.password
        docker secret create nse_password nse.password
        docker secret ls 
        ;;
    
    start)
        ## service name is ca, admin, log : can be replaced to other container.
        if [ $2 == "ca" ]; then
            echo "start ca service"
            if [[ "$(docker service ls)" == *"jkkim7202/pkizone"* ]]; then
                docker service rm $(docker service ls | grep "jkkim7202/pkizone" | cut -f1 -d" ")
                echo "docker service rm ..."
            else
                echo "no pkizone_ca_serivice"
            fi
            docker pull jkkim7202/pkizone:latest
            docker  service create \
                --name pkizone_ca_service  \
                --replicas 1 \
                --secret source=iot_smarthome_password,target=iot_smarthome_password \
                --secret source=nse_password,target=nse_password \
                -p 80:8080 -p 443:8443 \
                --env CA_LIST=iot_smarthome,nse \
                --env CA_CN_nse="CA for NSE" \
                --env CA_CN_iot_smarthome="IoT Smart Home CA" \
                --env TOKEN="$server_token" \
                --mount type=bind,source=$ca_home,destination=/ssl/ca jkkim7202/pkizone:latest
        elif [[ $2 == "admin" ]]; then
            echo "start portainer"
        elif [[ $2 == "dozzle" ]]; then
            echo "start dozzle"
        fi
        ;;
    stop)
        ## service name is ca, admin, log : can be replaced to other container.
        if [ $2 == "ca" ]; then
            echo "stop ca service"
            if [ "$(docker service ls)" == *"jkkim7202/pkizone"* ]; then
                docker service rm $(docker service ls | grep "jkkim7202/pkizone" | cut -f1 -d" ")
            else
                echo "no pkizone_ca_serivice"
            fi
        elif [ $2 == "admin" ]; then
            echo "stop portainer"
        elif [ $2 == "dozzle" ]; then
            echo "stop dozzle"
        fi
        ;;

    up)
        echo "------------------------------"
        echo "Start docker PKI service.     "
        echo " - docker swarm mode init  "
        echo "------------------------------"
        ## if need portainer and volume not created
        if [ ! -d portainer_data ]; then 
            docker volume create portainer_data
        fi
        docker pull jkkim7202/pkizone:latest
        docker-compose up -d 
        ;;
    swarm)
        docker swarm init
        ;;
    
    genkey)
        echo "------------------------------"
        echo "generate client sign key pair "
        echo "------------------------------"
        if [ ! -f ./sign.key ]; then
            openssl ecparam -genkey -name $client_sign_alg -noout -out $client_sign_key
            openssl ec -in $client_sign_key -pubout -out $client_sign_pub
            ## if RSA need...
            #openssl genrsa -out sign.key 2048
            #openssl rsa -in sign.key -outform PEM -pubout -out sign.pub
            if [ -f $client_sign_key ]; then
                echo "client sign key generated: $client_sign_key"
            else
                echo "error: client sign key generation failed: $client_sign_key"
            fi
        else 
            echo "$client_sign_key already exists"
            exit
        fi
        ;;
    ticket)
        echo "------------------------------"
        echo "request ticket"
        echo "------------------------------" 
        curl -fk -o ./$ca_name.ticket  "$ticket/$ca_name"
        echo "TICKET($ca_name)  ==> $(cat ./$ca_name.ticket)"
        echo "ticket file: $ca_name.ticket"
        ;;
    
    database)
        echo "------------------------------"
        echo "request DATABASE"
        echo "------------------------------" 
        curl -fk "$database/$ca_name"
        
        ;;
    token)
        echo "------------------------------"
        echo "token generate"
        echo "------------------------------" 
        curl -fk -o ./$ca_name.ticket  "$ticket/$ca_name"
        echo "TICKET($ca_name)  ==> $(cat ./$ca_name.ticket)"
        echo "ticket file: $ca_name.ticket"
        
        token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"

        echo "token ==> $token"
        echo $token > ./$ca_name.token
        clientid=jkkim@ermind.co.kr

        echo "token file ==> ./$ca_name.token"
        ;;

    register)
        
        echo "------------------------------"
        echo "client registration "
        echo "------------------------------" 

        curl -fk -o ./$ca_name.ticket  "$ticket/$ca_name"
        echo "TICKET($ca_name) ==> $(cat ./$ca_name.ticket)"

        token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"

        echo "token ==> $token"
        
        echo "begin registration"
        curl -fk  --data-binary @$client_sign_pub "$clientadd/$ca_name?clientid=$clientid&token=$token"
        echo "end registration"
        ;;

    cms_encrypt)
        curl -fk --data-binary @$2 -o $2.enc \
        "$cms_encrypt/$ca_name?cipher=aes-192-cbc&serial=$3&outformat=pem"
        #"$cms_encrypt/$ca_name?from=sender@email&serial=$3&to=receiver.email&subject=test&cipher=aes-192-cbc"
        ;;
    cms_decrypt)
        curl -fk --data-binary @$2 -o $2.dec \
        "$cms_decrypt/$ca_name?cipher=aes-192-cbc&serial=$3&outformat=pem"
        ;;

    cms_sign)
        curl -fk --data-binary @$2 -o $2.sign \
        "$cms_sign/$ca_name?serial=$3&outformat=PEM"
        ;;

    cms_verify)
        curl -fk --data-binary @$2  "$cms_verify/$ca_name"
        ;;
    
    cms_parse)
        curl -fk --data-binary @$2  "$cms_parse/$ca_name"
        ;;

    sign)
        idtoken="mysecret"
        echo "token: $idtoken"

        openssl req -new -newkey rsa:2048 -keyout host_$mydate.key -nodes -subj "/" |   curl -fk --data-binary @- -o host_$mydate.pem \
        "$sign/$ca_name?dn=/C=KR/O=Test/OU=Testou/CN=host_$mydate&days=365&token=$idtoken"

        openssl x509 -in ./host_$mydate.pem -noout -subject

        cat ./host_$mydate.pem
        ;;
        
    ocsp_verify)
        curl -fk --data-binary @$2 "$ocsp_verify/$ca_name?ocsp_verify"
        ;;

    xsign2)
        idtoken="mysecret"
        echo "id-token: $idtoken"

        dn="/C=KR/O=Test/OU=Testou/CN=host_$mydate"
        curl -fk -o host_$mydate.pfx "$xsign/$ca_name?dn=$dn&days=30&keygen=ecc:secp256k1&token=$idtoken&outformat=pkcs12"
        file host_$mydate.pfx
        ;;
    
    xsign)
        idtoken="mysecret"
        echo "id-token: $idtoken"

        dn="/C=KR/O=Test/OU=Testou/CN=host_$mydate"
        curl -fk -o host_$mydate.pem "$xsign/$ca_name?dn=$dn&days=30&keygen=ecc:secp256k1&token=$idtoken"
        cat host_$mydate.pem
        ;;
    
    gencrl)
        curl -fk  "$gencrl/$ca_name"
        ;;
    crl)
        curl -fk  "$crl/$ca_name"
        ;;
    revoke)
        echo "revoke: $2"
        curl -fk --data-binary @$2   "$revoke/$ca_name"
        ;;
            
    *)
        echo "invalid command: ./run.sh COMMAND ARGS"
        exit
        ;;

esac
