FROM debian:stable
RUN apt-get update && apt-get install -y --force-yes apache2 openssl libpython-dev libffi-dev libssl-dev python python-dev python-pip libcurl4-openssl-dev gcc
EXPOSE 6543
RUN a2enmod proxy
RUN a2enmod proxy_http
RUN a2enmod ssl
ADD apache2/default-ssl.conf /etc/apache2/sites-enabled/
ADD apache2/bioshadock.key /etc/ssl/certs/
ADD apache2/bioshadock.crt /etc/ssl/certs/
ADD *.sh /opt/bioshadock
RUN systemctl enable apache2
ADD shadock /opt/bioshadock/shadock
ADD CHANGES.txt README.md /opt/bioshadock/
ADD *.py /opt/bioshadock/
RUN cd /opt/bioshadock && pip install -r requirements.txt
RUN cd /opt/bioshadock && python setup.py develop
WORKDIR /opt/bioshadock
RUN mkdir -p /opt/bioshadock
ENTRYPOINT ["start.sh"]
