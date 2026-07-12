# iot_config.py — GhostNet IoT Source Configuration
# Change IOT_MODE to switch between virtual and real IoT sources.

IOT_MODE = "wokwi"   # "wokwi" | "ec2" | "raspberry_pi" | "local"

MQTT_CONFIGS = {
    "wokwi":        {"host": "broker.hivemq.com", "port": 1883},
    "ec2":          {"host": "13.233.X.X",         "port": 1883},  # update with your EC2 IP
    "raspberry_pi": {"host": "192.168.1.X",         "port": 1883},  # update when Pi is ready
    "local":        {"host": "localhost",            "port": 1883},
}

MQTT_TOPIC  = "hospital/icu/vitals/patient1"
ACTIVE      = MQTT_CONFIGS[IOT_MODE]

def get_broker_host(): return ACTIVE["host"]
def get_broker_port(): return ACTIVE["port"]
def get_mode():        return IOT_MODE
