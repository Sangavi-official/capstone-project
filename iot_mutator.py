"""
iot_mutator.py
==============
Runs ON YOUR LAPTOP, alongside cloud_mutator.py.
Connects over SSH to the virtual IoT device (EC2 instance) and
executes real mutations: MQTT topic rotation and broker port change.

These functions are called by ghostnet_env_v3.py when the agent
selects action 3 (rotate_iot_ip) or action 4 (rotate_mqtt_topic).

SETUP REQUIRED before first use:
    pip install paramiko
    Paste your EC2 public IP and .pem key path below.
"""

import paramiko
import random
import string
import time
import paramiko, json
import paho.mqtt.client as mqtt

EC2_HOST = "13.206.71.17"
EC2_USER = "ubuntu"
KEY_PATH = KEY_PATH = r"C:\Users\SANGAVI\Documents\project\ghostnet\ghostnet-iot-key.pem"


mutation_history = []


def _ssh_run(command, timeout=10):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(EC2_HOST, username=EC2_USER, key_filename=KEY_PATH, timeout=timeout)
    stdin, stdout, stderr = ssh.exec_command(command)
    out = stdout.read().decode()
    err = stderr.read().decode()
    ssh.close()
    return out, err


def log_mutation(action, details, success):
    entry = {
        "timestamp": time.time(),
        "action": action,
        "details": details,
        "success": success
    }
    mutation_history.append(entry)
    status = "SUCCESS" if success else "FAILED"
    print(f"  [IOT] {status} | {action} | {details}")
    return success



# Cloud mutation — open SSH FIRST, then use it (AESM port hop, etc.)
def open_ssh():
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=EC2_HOST, username="ubuntu", key_filename=KEY_PATH, timeout=15)
    return ssh

def rotate_iot_topic():
    """
    Action 4 — rotate_mqtt_topic
    Publishes a control message that the live Wokwi pump listens for,
    commanding it to switch its publish topic.
    """
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    new_topic = f"hospital/icu/vitals/p{suffix}"
    try:
        m = mqtt.Client()
        m.connect(EC2_HOST, 1883, 60)
        m.publish("ghostnet/control/pump1",
                   json.dumps({"action": "rotate_topic", "new_topic": new_topic}))
        m.disconnect()
        return log_mutation("rotate_mqtt_topic", f"-> {new_topic}", True)
    except Exception as e:
        return log_mutation("rotate_mqtt_topic", str(e), False)


def restart_broker_with_new_port(new_port=None):
    """
    Action 3 — rotate_iot_ip
    Changes the Mosquitto broker's listening port and restarts it.
    Represents the gateway-side address mutation in the dual-domain
    action space, equivalent in role to rotate_cloud_ip on AWS.
    """
    if new_port is None:
        new_port = random.choice([1884, 1885, 1886, 1887])
    try:
        cmd = (
            f"sudo sed -i 's/^port .*/port {new_port}/' /etc/mosquitto/mosquitto.conf "
            f"&& sudo systemctl restart mosquitto"
        )
        _ssh_run(cmd)
        return log_mutation("rotate_iot_ip", f"broker port -> {new_port}", True)
    except Exception as e:
        return log_mutation("rotate_iot_ip", str(e), False)


def get_iot_status():
    """Reads back the current Mosquitto port for verification."""
    try:
        out, err = _ssh_run("grep '^port' /etc/mosquitto/mosquitto.conf")
        return out.strip()
    except Exception as e:
        return f"error: {e}"


def get_mutation_history():
    return mutation_history


if __name__ == "__main__":
    print("=" * 55)
    print("  GhostNet IoT Mutator — Phase 4 Verification")
    print("=" * 55)
    print(f"  Target device : {EC2_HOST}")
    print(f"  Current port  : {get_iot_status()}\n")

    rotate_iot_topic()
    time.sleep(1)
    restart_broker_with_new_port()

    print("\n" + "=" * 55)
    print(f"  New port      : {get_iot_status()}")
    print("  Check device.py terminal output for topic rotation log")
    print("=" * 55)
