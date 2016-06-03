FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y git python3.5 python3-pip
RUN git clone https://github.com/prefer/test-ingress.git kd-lb
RUN cd kd-lb/
RUN pip3 install -r REQUIREMENTS
#RUN pip3 install -r plugins/aws_route53/REQUIREMENTS
RUN pip3 install -r plugins/cloudflare/REQUIREMENTS
#RUN pip3 install -r plugins/cpanel_dnsonly/REQUIREMENTS

CMD ["python3", "main.py", "user3", "user3.cl-owncloud.xyz", "wordpress-svc"]