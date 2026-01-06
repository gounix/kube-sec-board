import gc
from flask import Flask
import os
import threading

from configauditreport import configauditreport
from ticket import ticket
from vulnerabilityreport import vulnerabilityreport
from watcher import watcher


bullet = "-"
header1 = "#"
header2 = "##"

included_list, excluded_list = [], []
port_number = 9990

app = Flask(__name__)


def load_environment() -> None:
    global \
        kanboard_url, \
        kanboard_user, \
        kanboard_apikey, \
        namespaces_excluded, \
        namespaces_included
    global standalone, car_severities, vuln_severities

    kanboard_url = os.environ.get("KANBOARD_URL")
    if kanboard_url is None:
        print("FATAL environment variable KANBOARD_URL not defined", flush=True)
        exit(1)

    kanboard_user = os.environ.get("KANBOARD_USER")
    if kanboard_user is None:
        print("FATAL environment variable KANBOARD_USER not defined", flush=True)
        exit(1)

    kanboard_apikey = os.environ.get("KANBOARD_APIKEY")
    if kanboard_apikey is None:
        print("FATAL environment variable KANBOARD_APIKEY not defined", flush=True)
        exit(1)

    namespaces_excluded = os.environ.get("NAMESPACES_EXCLUDED")
    if namespaces_excluded is None:
        print("environment variable NAMESPACES_EXCLUDED not defined", flush=True)
        namespaces_excluded = ""

    namespaces_included = os.environ.get("NAMESPACES_INCLUDED")
    if namespaces_included is None:
        print("environment variable NAMESPACES_INCLUDED not defined", flush=True)
        namespaces_included = ""

    standalone = os.environ.get("STANDALONE")
    if standalone is None:
        print("environment variable STANDALONE not defined", flush=True)
        standalone = 0
    else:
        standalone = 1

    car_severities = os.environ.get("CAR_SEVERITIES")
    if car_severities is None:
        print("environment variable CAR_SEVERITIES not defined", flush=True)
        car_severities = ""

    vuln_severities = os.environ.get("VULN_SEVERITIES")
    if vuln_severities is None:
        print("environment variable VULN_SEVERITIES not defined", flush=True)
        vuln_severities = ""

    print("environment:", flush=True)
    print("KANBOARD_URL=%s" % (kanboard_url), flush=True)
    print("KANBOARD_USER=%s" % (kanboard_user), flush=True)
    print("KANBOARD_APIKEY=%s" % (kanboard_apikey), flush=True)
    print("NAMESPACES_EXCLUDED=%s" % (namespaces_excluded), flush=True)
    print("NAMESPACES_INCLUDED=%s" % (namespaces_included), flush=True)
    print("STANDALONE=%s" % (standalone), flush=True)
    print(
        "CAR_SEVERITIES=%s (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)" % (car_severities),
        flush=True,
    )
    print(
        "VULN_SEVERITIES=%s (UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL)" % (vuln_severities),
        flush=True,
    )


def translate_severity(severity: str) -> (str, int):
    if severity == "CRITICAL":
        return "red", 1
    if severity == "HIGH":
        return "orange", 2
    if severity == "MEDIUM":
        return "yellow", 3
    if severity == "LOW":
        return "green", 4
    return "blue", 5


def markup_vulnerability(lst: []) -> str:
    total = "%s Vulnerabilites:\n" % (header1)
    for vulnerability in lst:
        total += "\n"
        total += "%s %s\n" % (header2, vulnerability["title"])
        total += "Resource: %s Version: %s\n" % (
            vulnerability["resource"],
            vulnerability["installedVersion"],
        )
        total += "Fixed in version: %s\n" % (vulnerability["fixedVersion"])
        total += "Severity: %s\n" % (vulnerability["severity"])
        total += "CVE: %s\n" % (vulnerability["vulnerabilityID"])

    return total


def markup_misconfig(messages_list: dict) -> str:
    total = "%s Misconfigurations:\n" % (header1)
    for substr in messages_list["messages"]:
        total += "%s %s\n" % (bullet, substr)

    total += "\n%s Remediation:\n%s %s\n" % (
        header1,
        bullet,
        messages_list["remediation"],
    )
    return total


def handle_namespace(namespace: str) -> bool:
    if included_list != [] and namespace not in included_list:
        print(
            "handle_namespace: ignoring %s, not in include list" % (namespace),
            flush=True,
        )
        return False
    elif excluded_list != [] and namespace in excluded_list:
        print(
            "handle_namespace: ignoring %s, in exclude list" % (namespace), flush=True
        )
        return False
    print("handle_namespace: handling %s" % (namespace), flush=True)
    return True


def car_handler():
    obj = watcher(standalone)
    for namespace in obj.watch_namespaces("configauditreports"):
        if not handle_namespace(namespace):
            continue

        tick_misc = ticket(
            kanboard_url,
            kanboard_user,
            kanboard_apikey,
            namespace,
            "misconfigs " + namespace,
        )

        car = configauditreport(standalone, namespace)
        if car_severities != "":
            severity_list = car_severities.split(",")
            car.filter_severity(severity_list)

        for ch in car.get_check_id():
            print("main check %s" % (ch), flush=True)
            check_id, description, severity, messages = car.get_car(ch)
            color, priority = translate_severity(severity)
            print(
                "main: severity=%s color=%s priority=%s" % (severity, color, priority),
                flush=True,
            )
            tick_misc.create_task(
                description, check_id, color, priority, markup_misconfig(messages)
            )

        new_tickets, updated_tickets, closed_tickets = tick_misc.garbage_collect()
        del car
        del tick_misc
        gc.collect()


def vuln_handler():
    obj = watcher(standalone)
    for namespace in obj.watch_namespaces("vulnerabilityreports"):
        if not handle_namespace(namespace):
            continue

        tick_vuln = ticket(
            kanboard_url,
            kanboard_user,
            kanboard_apikey,
            namespace,
            "vulnerabilities " + namespace,
        )

        v = vulnerabilityreport(standalone, namespace)
        if vuln_severities != "":
            severity_list = vuln_severities.split(",")
            v.filter_severity(severity_list)

        for im in v.get_image():
            print("main image %s" % (im), flush=True)
            img_name, description, severity, message = v.get_vulns(im)
            color, priority = translate_severity(severity)
            print(
                "main: severity=%s color=%s priority=%s" % (severity, color, priority),
                flush=True,
            )
            tick_vuln.create_task(
                description, img_name, color, priority, markup_vulnerability(message)
            )

        new_tickets, updated_tickets, closed_tickets = tick_vuln.garbage_collect()
        del v
        del tick_vuln
        gc.collect()


@app.route("/health", methods=["GET"])
def show_health():
    if car_thread.is_alive() and vuln_thread.is_alive():
        return "healthy", 200
    else:
        return "not healthy", 404


def main():
    global included_list, excluded_list
    global car_thread, vuln_thread

    load_environment()

    if namespaces_included != "":
        included_list = namespaces_included.split(",")
    if namespaces_excluded != "":
        excluded_list = namespaces_excluded.split(",")

    car_thread = threading.Thread(target=car_handler)
    car_thread.start()

    vuln_thread = threading.Thread(target=vuln_handler)
    vuln_thread.start()

    app.run(host="0.0.0.0", port=port_number)


if __name__ == "__main__":
    main()
