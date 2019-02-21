import logging


def setup_logger(name, level, log_to_file):
    """
    Create and configure logger
    Create console handler and logfile handlers
    :param name: logger name and logfile name if also log to file
    :param level: change to logging.DEBUG for verbose output, change to logging.INFO for standard output
    :param log_to_file: boolean
    :return: created and configured logger object
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)

    console = logging.StreamHandler()
    console.setLevel(level)
    formatter = logging.Formatter('[%(asctime)s - %(levelname)s] %(message)s')
    console.setFormatter(formatter)
    logger.addHandler(console)
    if log_to_file:
        logfile = logging.FileHandler('{0}.log'.format(name), mode='w')
        logfile.setLevel(logging.DEBUG)
        logfile.setFormatter(formatter)
        logger.addHandler(logfile)
    return logger
