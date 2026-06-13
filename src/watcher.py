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

from kubernetes import client, config, watch

apigroup = "aquasecurity.github.io"
apiversion = "v1alpha1"


class watcher:
    def __init__(self, standalone: int) -> None:
        if standalone == 1:
            config.load_kube_config()
        else:
            config.load_incluster_config()
        self.api = client.CustomObjectsApi()

    def watch_namespaces(self, plural: str) -> str:
        # queued_events = set({})
        w = watch.Watch()
        for event in w.stream(
            self.api.list_custom_object_for_all_namespaces, apigroup, apiversion, plural
        ):
            print(
                "type %s name %s namespace %s"
                % (
                    event["type"],
                    event["object"]["metadata"]["name"],
                    event["object"]["metadata"]["namespace"],
                )
            )
            yield event["object"]["metadata"]["namespace"]


#            queued_events.add(event["object"]["metadata"]["namespace"])
#            if event["type"] == "ADDED":
#                for ev in queued_events:
#                    yield ev
#                print("clear set")
#                queued_events = set({})
