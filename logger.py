import logging

# Create a logger instance
logger = logging.getLogger("dr_logger")

# Set the log level
logger.setLevel(logging.DEBUG)

# Create a file handler
handler = logging.FileHandler("collector.log")

# Create a formatter
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Add the formatter to the handler
handler.setFormatter(formatter)

# Add the handler to the logger
logger.addHandler(handler)

# A second logger specifically for thread exceptions
logger_thread = logging.getLogger("dr_logger_thread")
logger_thread.setLevel(logging.DEBUG)
handler_thread = logging.FileHandler("collector_thread_exceptions.log")
formatter_thread = logging.Formatter("%(asctime)s - %(name)s - %(message)s")
handler_thread.setFormatter(formatter_thread)
logger_thread.addHandler(handler_thread)
