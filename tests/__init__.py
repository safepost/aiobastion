<<<<<<< HEAD
import logging
import os

CONFIG = os.path.join("..", "..", "confs", "config_tests.yml")
AIM_CONFIG = os.path.join("..", "..", "confs", "config_aim_hp.yml")

logging.basicConfig(
    level=logging.DEBUG,
    # level=logging.INFO,
    format='%(asctime)s %(levelname)08s %(name)s %(message)s',
=======
import logging
import os

CONFIG = os.path.join("..", "..", "confs", "config_tests.yml")
AIM_CONFIG = os.path.join("..", "..", "confs", "config_aim_hp.yml")

logging.basicConfig(
    level=logging.DEBUG,
    # level=logging.INFO,
    format='%(asctime)s %(levelname)08s %(name)s %(message)s',
>>>>>>> d06df4a570e5fc5f0b18a46849d1a5b0932898da
)