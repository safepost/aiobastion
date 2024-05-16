import logging
import os

CONFIG = os.path.join("..", "..", "confs", "config_tests.yml")
AIM_CONFIG = os.path.join("..", "..", "confs", "config_aim_hp.yml")

logging.basicConfig(
    level=logging.DEBUG,
    # level=logging.INFO,
    format='%(asctime)s %(levelname)08s %(name)s %(message)s',
)