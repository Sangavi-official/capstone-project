"""
device.py
==========
Runs ON the virtual IoT device (EC2 instance or Raspberry Pi).
Simulates a hospital infusion pump / patient monitor publishing
vitals data over MQTT every 5 seconds.

Supports live topic rotation via a control file written remotely
by iot_mutator.py over SSH, with a dual-publish overlap window
so subscribers do not lose data during the cutover.

Run this with:
    python3 device.py
"""

import paho.mqtt.client as mqtt
import time
import random
import json
import os

BROKER = "localhost"
PORT = 1883
CONTROL_FILE = "/tmp/new_topic.txt"

current_topic = "hospital/icu/vitals/patient1"
overlap_topic = None
overlap_until = 0


def connect_broker():
    client = mqtt.Client()
    client.connect(BROKER, PORT)
    return client


def check_for_rotation():
    global current_topic, overlap_topic, overlap_until
    if not os.path.exists(CONTROL_FILE):
        return
    with open(CONTROL_FILE) as f:
        requested = f.read().strip()
    if requested and requested != current_topic:
        overlap_topic = current_topic
        overlap_until = time.time() + 10
        current_topic = requested
        print(f"[DEVICE] topic rotated -> {current_topic} (10s overlap with old topic)")


def publish_vitals(client):
    global overlap_topic   
    check_for_rotation()
    payload = json.dumps({
        "heart_rate": random.randint(60, 100),
        "spo2": random.randint(95, 100),
        "timestamp": round(time.time(), 2)
    })
    client.publish(current_topic, payload)
    print(f"[DEVICE] published to {current_topic} -> {payload}")

    if overlap_topic and time.time() < overlap_until:
        client.publish(overlap_topic, payload)
        print(f"[DEVICE] dual-publish (transition window) -> {overlap_topic}")
    elif overlap_topic and time.time() >= overlap_until:
        print(f"[DEVICE] overlap window closed, retiring {overlap_topic}")
        overlap_topic = None


if __name__ == "__main__":
    print(f"[DEVICE] starting, initial topic: {current_topic}")
    mqtt_client = connect_broker()
    while True:
        publish_vitals(mqtt_client)
        time.sleep(5)
