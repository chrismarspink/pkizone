#!/bin/bash
set -e


mydate=$(date "+%Y%M%d%H%m.%S")

#server=https://127.0.0.1
server=https://3.37.221.15
sign=$server/sign
xsign=$server/xsign
revoke=$server/revoke
gencrl=$server/gencrl
crl=$server/crl
ticket=$server/ticket
clientadd=$server/clientadd
test=$server/test

client_sign_key=./sign.key
client_sign_pub=./sign.pub
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
        docker build --tag pkizone:test ../pkizone_src/
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
        docker build --tag pkizone:$2 ../pkizone_src/
        docker tag pkizone:$2 jkkim7202/pkizone:$2
        docker push jkkim7202/pkizone:$2

        docker tag pkizone:$2 jkkim7202/pkizone:latest
        docker push jkkim7202/pkizone:latest
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
            if [ "$(docker service ls)" == *"jkkim7202/pkizone"* ]; then
                docker service rm $(docker service ls | grep "jkkim7202/pkizone" | cut -f1 -d" ")
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
                --env TOKEN="510bef9b27e4ad5e97510f30116a8966" \
                --mount type=bind,source=/home/ubuntu/ca.service/ssl/ca,destination=/ssl/ca jkkim7202/pkizone:latest
        elif [ $2 == "admin" ]; then
            echo "start portainer"
        elif [ $2 == "dozzle" ]; then
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

    sign)
        curl -fk -o ./$ca_name.ticket  "$ticket/$ca_name"
        echo "ticket: $(cat ./$ca_name.ticket)"
        token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"
        echo "token: $token"

        ##idtoken="$clientid:$token"
        idtoken="06c219e5bc8378f3a8a3f83b4b7e4649"
        echo "id-token: $idtoken"

        openssl req -new -newkey rsa:2048 -keyout host_$mydate.key -nodes -subj "/" |   curl -fk --data-binary @- -o host_$mydate.pem \
        "$sign/$ca_name?dn=/C=KR/O=Test/OU=Testou/CN=host_$mydate&days=365&token=$idtoken"

        openssl x509 -in ./host_$mydate.pem -noout -subject
        #openssl x509 -in ./host_$mydate.pem -text -noout

        cat ./host_$mydate.pem
        ;;

    xsign)
        curl -fk -o ./$ca_name.ticket  "$ticket/$ca_name"
        echo "ticket: $(cat ./$ca_name.ticket)"
        token="$(openssl dgst -sha1 -sign $client_sign_key ./$ca_name.ticket | openssl base64 -A)"
        echo "token: $token"

        idtoken="$clientid:$token"
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
