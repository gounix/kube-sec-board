# MIT License
#
# Copyright (c) 2026 gounix
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

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
