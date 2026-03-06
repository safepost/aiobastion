import logging
import os

CONFIG = os.path.join(os.getcwd(), "tests", "test_data", "lab_config.yml")
AIM_CONFIG = os.path.join(os.getcwd(), "tests", "test_data", "confs", "config_aim_hp.yml")
API_USER = "admin_test_restapi"

logging.basicConfig(
    level=logging.DEBUG,
    # level=logging.INFO,
    format='%(asctime)s %(levelname)08s %(name)s %(message)s',
)