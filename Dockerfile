FROM debian:stable
RUN apt-get update && apt-get install -y --force-yes mongodb openssl libpython-dev libffi-dev libssl-dev python python-dev python-pip libcurl4-openssl-dev gcc
EXPOSE 6543
ADD shadock /opt/bioshadock/shadock
ADD CHANGES.txt README.md /opt/bioshadock/
ADD *.py /opt/bioshadock/
RUN cd /opt/bioshadock && python setup.py develop
WORKDIR /opt/bioshadock
RUN mkdir -p /opt/bioshadock
ENTRYPOINT ["pserve", "development.ini"]
