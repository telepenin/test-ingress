FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y git python3.5 python3-pip python3-lxml

WORKDIR /opt/kd-lb

ADD REQUIREMENTS /opt/kd-lb/REQUIREMENTS
ADD plugins/cloudflare/REQUIREMENTS /opt/kd-lb/plugins/cloudflare/REQUIREMENTS
ADD plugins/aws_route53/REQUIREMENTS /opt/kd-lb/plugins/aws_route53/REQUIREMENTS
ADD plugins/cpanel_dnsonly/REQUIREMENTS /opt/kd-lb/plugins/cpanel_dnsonly/REQUIREMENTS

RUN pip3 install -r REQUIREMENTS
RUN pip3 install -r plugins/aws_route53/REQUIREMENTS
RUN pip3 install -r plugins/cloudflare/REQUIREMENTS
RUN pip3 install -r plugins/cpanel_dnsonly/REQUIREMENTS

COPY . /opt/kd-lb
CMD []