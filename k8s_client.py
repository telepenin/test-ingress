import json
import logging
from urllib.parse import urljoin

import requests

logger = logging.getLogger(__name__)


class KubernetesClient(object):
    def __init__(self, config):
        self.server = config.get('server', 'http://localhost:8080/')
        self.token = config.get('token')

    def _request(self, method, url_path, data):
        url = urljoin(self.server, url_path)
        headers = {
            'Content-Type': 'application/json'
        }

        if self.token:
            headers['Authorization'] = 'Bearer {}'.format(self.token)

        if method == 'GET':

            response = requests.request(
                method, url, params=data, headers=headers,
                verify=False)
        else:
            response = requests.request(
                method, url, data=data, headers=headers,
                verify=False)

        result = json.loads(response.content.decode('utf-8'))

        if response.status_code not in [200, 201]:
            logger.debug('  {status}: "{message}"'.format(**result))
        else:
            logger.debug('  Success')

        return result


class KubernetesOperations(KubernetesClient):
    entity = None
    path = '/api/v1/namespaces/{namespace}/{entity}'

    def __init__(self, namespace=None, *args, **kwargs):
        super(KubernetesOperations, self).__init__(*args, **kwargs)
        self.namespace = namespace

    def list(self, *args, **kwargs):
        return

    def create(self, data):
        path = self.path.format(
            **{'namespace': self.namespace,
               'entity': self.entity}
        )

        logger.debug('{} {}: "{name}"'.format(
            'Create',
            self.__class__.__name__,
            **data.get('metadata', {'name': None})
        ))

        return self._request('POST', path, json.dumps(data))

    def replace(self, name, data):
        path = self.path.format(
            **{'namespace': self.namespace,
               'entity': self.entity}
        )

        logger.debug('{} {}: "{name}"'.format(
            'Replace',
            self.__class__.__name__,
            **data.get('metadata', {'name': None})
        ))
        return self._request(
            'PUT',
            urljoin(path, name),
            json.dumps(data))


class ReplicationController(KubernetesOperations):
    entity = 'replicationcontrollers'

    def list(self, label_selector=None, field_selector=None):
        path = self.path.format(
            **{'namespace': self.namespace,
               'entity': self.entity
               }
        )
        logger.debug('{} {}: "{}"'.format(
            'List',
            self.__class__.__name__,
            'list')
        )

        return self._request('GET', path, {
            'labelSelector': label_selector,
            'fieldSelector': field_selector,
        })


class Service(KubernetesOperations):
    entity = 'services'

    def list(self, label_selector=None, field_selector=None):
        path = self.path.format(
            **{'namespace': self.namespace,
               'entity': self.entity}
        )
        logger.debug('{} {}: "{}"'.format(
            'List',
            self.__class__.__name__,
            'list')
        )

        return self._request('GET', path, {
            'labelSelector': label_selector,
            'fieldSelector': field_selector,
        })


class Secret(KubernetesOperations):
    entity = 'secrets'


class Namespace(KubernetesOperations):
    path = '/api/v1/namespaces'

    def list(self, label_selector=None, field_selector=None):
        logger.debug('{} {}: "{}"'.format(
            'List',
            self.__class__.__name__,
            'list')
        )

        return self._request('GET', self.path, {
            'labelSelector': label_selector,
            'fieldSelector': field_selector,
        })


class Pod(KubernetesOperations):
    path = '/api/v1/namespaces/{namespace}/pods'

    def list(self, label_selector=None, field_selector=None):
        path = self.path.format(
            **{'namespace': self.namespace}
        )
        logger.debug('{} {}: "{}"'.format(
            'List',
            self.__class__.__name__,
            'list')
        )

        return self._request('GET', path, {
            'labelSelector': label_selector,
            'fieldSelector': field_selector,
        })


# Extensions:§
class Ingress(KubernetesOperations):
    entity = 'ingresses/'
    path = '/apis/extensions/v1beta1/namespaces/{namespace}/{entity}'
