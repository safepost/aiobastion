import logging
import os

CONFIG = os.path.join("..", "..", "confs", "config_tests.yml")
AIM_CONFIG = os.path.join("..", "..", "confs", "config_aim_hp.yml")
API_USER = "admin_test_restapi"

logging.basicConfig(
    level=logging.DEBUG,
    # level=logging.INFO,
    format='%(asctime)s %(levelname)08s %(name)s %(message)s',
)