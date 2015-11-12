#shadock README

## Requirements

Packages:

 * Debian: libcurl-dev, gcc
 * CentOs: libcurl-devel, openldap-devel, gcc

Other:

mongodb, redis, elasticsearch

## References


https://docs.docker.com/v1.1/reference/api/docker-io_api/

https://docs.docker.com/reference/api/docker-io_api/#user-login
https://docs.docker.com/reference/api/docker_remote_api_v1.18/#ping-the-docker-server
https://docs.docker.com/reference/api/registry_api/#put-image-layer_1
https://github.com/docker/docker-registry

## Run

registry v1:

    docker run --rm -p 5000:5000 -v /root/registry:/registry -e STANDALONE=false -e STORAGE_PATH=/registry -e SEARCH_BACKEND=sqlalchemy -e INDEX_ENDPOINT=https://VM-3135.genouest.org/   registry

registry v2

    Web proxy needs to add X-FORWARDED-PROTO header to https requests

    docker run --rm -p 5000:5000 -v /root/certs:/root/certs -v /root/registryv2:/registryv2 -v /root/registry:/registry  -e REGISTRY_AUTH=token -e REGISTRY_AUTH_TOKEN_REALM="https://docker-ui.genouest.org/v2/token/" -e REGISTRY_AUTH_TOKEN_SERVICE="docker-registry.genouest.org" -e REGISTRY_AUTH_TOKEN_ISSUER="docker-ui.genouest.org" -e REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/root/certs/wildcard.genouest.org.crt  registry:2 /registryv2/config.yml

need to also setup registry location to match registry v2. Should in fact specify a config.yml as args and mount it in container for prod.

    python setup.py develop
    pserve development.ini (for dev)
    gunicorn -D -p bioshadock.pid --log-config=production.ini --paste production.ini  (for prod)

    # For background builder
    # Can set environ BIOSHADOCK_CONFIG to specify config file (development.ini,
    # ...)
    python builder.py start    

## Dev / Debug

SSL Key

ssh-keygen -t ecdsa -b 256


modulus/exponent

openssl x509  -in wildcard.genouest.org.crt -text -noout

convert crt to der

openssl x509 -outform der -in certificate.pem -out certificate.der

SSL INFO

openssl x509 -in GSRootCA-2014.cer -inform PEM -text -noout


# Docker

  docker run -p 443:443 -v path_to_certs:/etc/ssl/certs -v development.ini:/opt/bioshadock/development.ini osallou/bioshadock web|builder

dev: web interface (for devpt)
web: web interface (for production)
builder: background Docker image builder

  Certs should contain bioshadock.crt, bioshadock.key , ...


# Client

    docker login cloud-30.genouest.org (registry)
    # Fill credentials
    docker push cloud-30.genouest.org/osallou/testimage


# Credits
https://github.com/hectorj2f/codemirror-docker
http://commons.wikimedia.org/wiki/File:Shipping_containers_at_Clyde.jpg
