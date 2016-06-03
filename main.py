import asyncio
import importlib
import json
import logging
import os
import time
from json.decoder import JSONDecodeError

import aiohttp
import requests
import yaml
from jinja2 import Template
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from k8s_client import Ingress, ReplicationController, Service, Secret, Pod

logging.basicConfig(
    format=u'%(levelname)-8s [%(asctime)s] %(message)s',
    level=logging.DEBUG,
    filename=u'working.log')

logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger("requests").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def create_base_rc():
    rc = ReplicationController(namespace='default', config=config['apiserver'])
    for item in (
        ('base', 'nginx-controller', 'nginx-ingress-rc.yaml'),
        ('base', 'certbot', 'certbot-rc.yaml')
    ):
        with open(os.path.join(*item), 'r') as f:
            rc.create(yaml.load(f.read()))


def create_base_svc():
    svc = Service(namespace='default', config=config['apiserver'])
    for item in (
        ('base', 'certbot', 'certbot-svc.yaml'),
    ):
        with open(os.path.join(*item), 'r') as f:
            svc.create(yaml.load(f.read()))


def create_main_rc_and_svc(services):
    for name in services:
        rc = ReplicationController(namespace='default',
                                   config=config['apiserver'])
        with open(os.path.join('templates', 'rc-rule.yaml.j2'), 'r') as f:
            yaml_data = Template(f.read()).render({'name': name})
            rc.create(yaml.load(yaml_data))

        svc = Service(namespace='default', config=config['apiserver'])
        with open(os.path.join('templates', 'svc-rule.yaml.j2'), 'r') as f:
            yaml_data = Template(f.read()).render({'name': name})
            svc.create(yaml.load(yaml_data))


# Create ingress rules
def create_ingress_rule(name, host, service_name):
    ing = Ingress(namespace='default', config=config['apiserver'])
    for item in (
        ('templates', 'ingress-rule.yaml.j2'),
    ):
        with open(os.path.join(*item), 'r') as f:
            yaml_data = Template(f.read()).render({
                'name': name,
                'host': host,
                'service_name': service_name
            })
            ing.create(yaml.load(yaml_data))


def replace_ingress_rule(name, host, service_name):
    ing = Ingress(namespace='default', config=config['apiserver'])
    for item in (
        ('templates', 'ingress-rule.yaml.j2'),
    ):
        with open(os.path.join(*item), 'r') as f:
            yaml_data = Template(f.read()).render({
                'name': name,
                'host': host,
                'service_name': service_name
            })
            ing.replace('{}-ingress'.format(name), yaml.load(yaml_data))


# Create secrets
def create_secret(name, cert, private_key):
    ing = Secret(namespace='default', config=config['apiserver'])
    for item in (
        ('templates', 'secret-rule.yaml.j2'),
    ):
        with open(os.path.join(*item), 'r') as f:
            yaml_data = Template(f.read()).render({
                'cert': cert,
                'private_key': private_key,
                'name': name
            })
            ing.create(yaml.load(yaml_data))


async def fetch(session, url, data, seconds):
    # await asyncio.sleep(seconds)
    logger.debug('Run generating cert for {} after {} sec'.format(
        data['domains'], seconds))

    async with session.post(
        url,
        data=json.dumps(data),
        headers={
            'Content-type': 'application/json',
            # First host for ingress rules
            'Host': data['domains'][0]
        }
    ) as response:
        response = await response.text()
        return response


def create_or_update_dns_record(domain, new_ips):
    if config.get('plugins') and config['plugins'].get('dns'):
        dns_plugin = config['plugins']['dns']
        name = dns_plugin['name']
        module = importlib.import_module(
            '.'.join(['plugins', name, 'entry']))
        module.create_or_update_a_record(domain, new_ips, **dns_plugin)


def create_ingress(ingress_rules):
    loop = asyncio.get_event_loop()

    # Get nginx pods for ips
    pod = Pod(namespace='default', config=config['apiserver']).list(
        'app=nginx-ingress'
    )
    ips = [po['status']['hostIP'] for po in pod['items']]

    with aiohttp.ClientSession(loop=loop) as session:
        total = len(ingress_rules)
        # 2 sec delay between cert generating - experimental
        coefficient = 0.5 * total

        additional_params = [
            '--keep-until-expiring'
        ]
        if config['certbot']['staging']:
            additional_params.append('--staging')

        tasks = []
        loadbalancer_ip = ips[0]
        for i, (name, host, service_name) in enumerate(ingress_rules):
            create_ingress_rule(name, host, service_name)

            create_or_update_dns_record(host, ips)

            tasks.append(asyncio.ensure_future(fetch(
                # while certs generating on the first certbot pod
                session, 'http://{}/.certs/'.format(loadbalancer_ip), {
                    'domains': [host],
                    'email': config['certbot']['email'],
                    'certbot-additional-params': additional_params
                }, i * 1.0 / total * coefficient
            )))

            if len(tasks) == 1:
                # Delay for correctly creating dns record
                time.sleep(5)

                # Wait first for create account
                loop.run_until_complete(
                    tasks[0]
                )

        # Delay for correctly creating dns records
        time.sleep(5)

        begin_time = time.time()

        # Wait other with ready account
        loop.run_until_complete(
            asyncio.wait(tasks[1:])
        )
        logger.debug("The time spent for generating certs is {}".format(
            round(time.time() - begin_time, 1)
        ))

        responses = []
        error = False
        for task in tasks:
            try:
                result = json.loads(task.result())
            except JSONDecodeError:
                logger.error(task.result())
                error = True
            else:
                responses.append(result)
        if error:
            raise SystemExit()

    for i, response in enumerate(responses):
        name, host, service_name = ingress_rules[i]

        create_secret(
            name,
            cert=response['cert'],
            private_key=response['private_key']
        )
        replace_ingress_rule(name, host, service_name)


def main():
    # Create rc: nginx-controller and certbot
    create_base_rc()

    # Create certbot service
    create_base_svc()

    # Create for fixtures
    with open(config['fixtures'], 'r') as f:
        data = json.loads(f.read())

    # Create rc and service for endpoint, for example owncloud
    #create_main_rc_and_svc(data['services'])

    input("Please enter when certbot rc will be running")

    # Create ingress rules, TLS certs and secrets
    create_ingress(data['ingress-rules'])

    for _, host, _ in data['ingress-rules']:
        logger.debug("Domain is ready - http://{}".format(host))


if __name__ == '__main__':
    with open('config.yaml', 'r') as f:
        config = yaml.load(f.read())

    begin_time = time.time()

    main()

    logger.debug("All working time is {}".format(
        round(time.time() - begin_time, 1)
    ))
