FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y git python3.5 python3-pip

WORKDIR /opt/kd-lb

ADD REQUIREMENTS /opt/kd-lb/REQUIREMENTS
ADD plugins/cloudflare/REQUIREMENTS /opt/kd-lb/plugins/cloudflare/REQUIREMENTS
RUN pip3 install -r REQUIREMENTS
#RUN pip3 install -r plugins/aws_route53/REQUIREMENTS
RUN pip3 install -r plugins/cloudflare/REQUIREMENTS
#RUN pip3 install -r plugins/cpanel_dnsonly/REQUIREMENTS

COPY . /opt/kd-lb
CMD []