from kubernetes import client, config
from kubernetes.client.rest import ApiException

apigroup = "aquasecurity.github.io"
apiversion = "v1alpha1"
plural = "configauditreports"


class configauditreport:
    carlist = []

    def __init__(self, standalone: int, namespace: str) -> None:
        self.namespace = namespace

        if standalone == 1:
            config.load_kube_config()
        else:
            config.load_incluster_config()
        self.severity_filter = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.api = client.CustomObjectsApi()
        self.carlist = self._list_cars()

    def _list_cars(self) -> []:
        try:
            api_response = self.api.list_namespaced_custom_object(
                group=apigroup,
                version=apiversion,
                namespace=self.namespace,
                plural=plural,
            )
        except ApiException as e:
            print("configauditreport._list_cars exception: %s" % (e), flush=True)
            return []

        return api_response["items"]

    def filter_severity(self, severity_list: []):
        print("configauditreport.filter_severity %s" % (severity_list), flush=True)
        self.severity_filter = severity_list

    def get_check_id(self) -> str:
        check_set = {
            check["checkID"]
            for item in self.carlist
            for check in item["report"]["checks"]
            if check["severity"] in self.severity_filter
        }
        print("configauditreport.get_check_id: checkset %s" % (check_set), flush=True)
        for check in check_set:
            yield check

    def get_car(self, check_id: str):
        descriptions = [
            check["description"]
            for item in self.carlist
            for check in item["report"]["checks"]
            if check["checkID"] == check_id
        ]
        severities = [
            check["severity"]
            for item in self.carlist
            for check in item["report"]["checks"]
            if check["checkID"] == check_id
        ]
        messages = [
            check["messages"]
            for item in self.carlist
            for check in item["report"]["checks"]
            if check["checkID"] == check_id
        ]
        remediation = [
            check["remediation"]
            for item in self.carlist
            for check in item["report"]["checks"]
            if check["checkID"] == check_id
        ]
        flat_messages_list = [element for sublist in messages for element in sublist]
        # flat_messages_list.append(remediation[0])

        return (
            check_id,
            descriptions[0],
            severities[0],
            {"messages": flat_messages_list, "remediation": remediation[0]},
        )
