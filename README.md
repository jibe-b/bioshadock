#Bioshadock README

## Requirements

Packages:

 * Debian: libcurl-dev, gcc, libldap2-dev, openssl, libpython-dev, libffi-dev, libssl-dev
 * CentOs: libcurl-devel, openldap-devel, gcc, openssl, python-devel, libffi-devel, openssl-devel

Other:

mongodb, redis, elasticsearch

## HTTPS

server MUST run behind an HTTPS proxy server. Server should also add the header X-FORWARDED-PROTO and set to it to *https*, both to web interface and registry

## References

Docker registry API

 * https://docs.docker.com/v1.1/reference/api/docker-io_api/
 * https://docs.docker.com/reference/api/docker-io_api/#user-login
 * https://docs.docker.com/reference/api/docker_remote_api_v1.18/#ping-the-docker-server
 * https://docs.docker.com/reference/api/registry_api/#put-image-layer_1
 * https://github.com/docker/docker-registry

## Run registry v2


Web proxy needs to add X-FORWARDED-PROTO header to https requests.
Need to also setup registry location to match registry v2. Should in fact specify a config.yml as args and mount it in container for prod.


    docker run --rm -p 5000:5000 -v /root/certs:/root/certs -v /root/registryv2:/registryv2 -v /root/registry:/registry  -e REGISTRY_AUTH=token -e REGISTRY_AUTH_TOKEN_REALM="https://docker-ui.genouest.org/v2/token/" -e REGISTRY_AUTH_TOKEN_SERVICE="docker-registry.genouest.org" -e REGISTRY_AUTH_TOKEN_ISSUER="docker-ui.genouest.org" -e REGISTRY_AUTH_TOKEN_ROOTCERTBUNDLE=/root/certs/wildcard.genouest.org.crt  registry:2 /registryv2/config.yml


    python setup.py develop
    pserve development.ini (for dev)
    gunicorn -D -p bioshadock.pid --log-config=production.ini --paste production.ini  (for prod)

    # For background builder
    # Can set environ BIOSHADOCK_CONFIG to specify config file (development.ini,
    # ...)
    python builder.py start


## Dev / Debug

For development purpose, one can skip https requirements as well as authentication:

    # Allow http
    export BIOSHADOCK_INSECURE=1
    # Bypass password checks
    export BIOSHADOCK_AUTH=fake


Registry v1:

    docker run --rm -p 5000:5000 -v /root/registry:/registry -e STANDALONE=false -e STORAGE_PATH=/registry -e SEARCH_BACKEND=sqlalchemy -e INDEX_ENDPOINT=https://VM-3135.genouest.org/   registry


SSL Key

ssh-keygen -t ecdsa -b 256


modulus/exponent

openssl x509  -in wildcard.genouest.org.crt -text -noout

convert crt to der

openssl x509 -outform der -in certificate.pem -out certificate.der

SSL INFO

openssl x509 -in GSRootCA-2014.cer -inform PEM -text -noout


# Run as a Docker container

  docker run -p 443:443 -v path_to_certs:/etc/ssl/certs -v development.ini:/opt/bioshadock/development.ini osallou/bioshadock web|builder

dev: web interface (for devpt)
web: web interface (for production)
builder: background Docker image builder

  Certs should contain bioshadock.crt, bioshadock.key , ...


# Client

    docker login xx.genouest.org (registry)
    # Fill credentials
    docker push xx.genouest.org/osallou/testimage


# API

API key is available in user page.

get all public containers:  /container/all
get container tags: /container/tags/*id
build container from a git repo: /container/git/*id?apikey=XX
tag a container: /container/tag/*id/tagvalue?apikey=XX

swagger definition in shadock/webapp/app/api/bioshadock.json
online: http://www.genouest.org/api/bioshadock-api/

# Credits

https://github.com/hectorj2f/codemirror-docker
http://commons.wikimedia.org/wiki/File:Shipping_containers_at_Clyde.jpg
