FROM eqitii/eqitii-fingerprinter-py:0.1.0

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y python python-pip software-properties-common
RUN apt-get install -y build-essential automake pkg-config libtool libffi-dev libgmp-dev
RUN apt-get install -y maven
RUN mkdir /spark
WORKDIR /spark

ADD https://archive.apache.org/dist/spark/spark-2.4.0/spark-2.4.0.tgz .
RUN tar -xvzf spark-2.4.0.tgz
RUN rm spark-2.4.0.tgz
RUN cd spark-2.4.0 && ./build/mvn -DskipTests clean package

RUN pip3 install requests secp256k1

COPY containers/docker/spark/config/ /spark/spark-docker-conf/
RUN find /spark/spark-docker-conf -type f -exec chmod 777 {} \;

ENTRYPOINT ["sh", "/spark/spark-docker-conf/docker-entry.sh"]



