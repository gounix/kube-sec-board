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
