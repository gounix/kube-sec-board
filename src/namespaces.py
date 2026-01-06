from kubernetes import client, config
from kubernetes.client.rest import ApiException


class namespaces:
    namespaces = []

    def __init__(self, standalone: int):
        if standalone == 1:
            config.load_kube_config()
        else:
            config.load_incluster_config()
        self.api_instance = client.CoreV1Api()
        self._get_namespaces()

    def _get_namespaces(self):
        try:
            api_response = self.api_instance.list_namespace()
            # pprint(api_response)
        except ApiException as e:
            print(
                "Exception when calling CoreV1Api->list_namespace: %s\n" % (e),
                flush=True,
            )

        self.namespaces = [x.metadata.name for x in api_response.items]
        print("namespaces._get_namespaces: %s" % (self.namespaces), flush=True)

    def exclude_namespaces(self, excluded: list):
        self.namespaces = [x for x in self.namespaces if x not in excluded]
        print("namespaces.exclude_namespaces: %s" % (self.namespaces), flush=True)

    def include_namespaces(self, included: list):
        self.namespaces = included
        print("namespaces.include_namespaces: %s" % (self.namespaces), flush=True)

    def get_namespace(self):
        for name in self.namespaces:
            yield name
