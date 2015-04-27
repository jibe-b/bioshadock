shadock README


https://docs.docker.com/v1.1/reference/api/docker-io_api/

https://docs.docker.com/reference/api/docker-io_api/#user-login
https://docs.docker.com/reference/api/docker_remote_api_v1.18/#ping-the-docker-server
https://docs.docker.com/reference/api/registry_api/#put-image-layer_1
https://github.com/docker/docker-registry


registry:

docker run --rm -p 5000:5000 -v /root/registry:/registry -e STANDALONE=false -e STORAGE_PATH=/registry -e SEARCH_BACKEND=sqlalchemy -e INDEX_ENDPOINT=https://cloud-45/   registry
