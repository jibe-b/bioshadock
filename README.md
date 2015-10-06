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

    docker run --rm -p 5000:5000 -v /root/certs:/root/certs -v /root/registryv2:/registryv2  -e REGISTRY_AUTH=token -e REGISTRY_AUTH_TOKEN_REALM="https://cloud-45.genouest.org/v2/token/" -e REGISTRY_AUTH_TOKEN_SERVICE="cloud-30.genouest.org" -e REGISTRY_AUTH_TOKEN_ISSUER="cloud-45.genouest.org" -e REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/root/certs/wildcard.genouest.org.crt  distribution/distribution /registryv2/config.yml

need to also setup registry location to match registry v2. Should in fact specify a config.yml as args and mount it in container for prod.

    python setup.py develop
    pserve development.ini (for dev)
    gunicorn -p bioshadock.pid --log-config=production.ini --paste production.ini & (for prod)

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




Docker client: docker -D -H 127.0.0.1:2375 push cloud-30.genouest.org/testosallou


# TODO

* user registration (and password recovery)
* user credentials check
* checks ACLs when pushing to library
* add admin setup

# Docker

  docker run -p 443:443 -v path_to_certs:/etc/ssl/certs -v development.ini:/opt/bioshadock/development.ini osallou/bioshadock web|builder

dev: web interface (for devpt)
web: web interface (for production)
builder: background Docker image builder

  Certs should contain bioshadock.crt, bioshadock.key , ...



# Credits
https://github.com/hectorj2f/codemirror-docker
http://commons.wikimedia.org/wiki/File:Shipping_containers_at_Clyde.jpg