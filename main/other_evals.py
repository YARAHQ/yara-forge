"""
This file contains the code for the performance tests.
"""
import re
import logging
import time
import zipfile

class PerformanceTimer:
    """
    Performance Tests
    """

    # The test file was created with the following commands:
    # ReactOS v0.4.14 ISO folder > reactos
    # strings * >> react-os-strings.txt
    # strings -el * >> react-os-strings.txt
    # strings ./system32/ * >> react-os-strings.txt
    # strings -el ./system32/ * >> react-os-strings.txt
    sample_data_file = "./tests/data/react-os-strings.txt.zip"

    def __init__(self):
        # Load the sample data file, decompress the ZIP archive and load into memory
        with zipfile.ZipFile(self.sample_data_file, 'r') as zip_ref:
            for name in zip_ref.namelist():
                with zip_ref.open(name) as f:
                    self.test_string = f.read().decode("utf-8")
        # Run the baseline measurements
        self.bad_duration, self.good_duration = self.baseline_measurements()
        # Define the threshold for the regex strings
        self.threshold = ( self.bad_duration + self.good_duration ) / 2
        logging.debug("Regex Baseline Threshold: %f", self.threshold)

    def baseline_measurements(self):
        """
        Test the performance of the baseline regex.
        """
        # Log the start of the baseline measurements
        logging.debug("Starting the regex baseline measurements")

        # Test the performance of the baseline regex
        bad_duration = self.test_regex_performance(r"[\w\-.]{1,3}@[\w\-.]{1,3}")
        logging.debug("Bad regex duration: %f", bad_duration)
        good_duration = self.test_regex_performance(r"Who is John Galt\?")
        logging.debug("Good regex duration: %f", good_duration)

        return bad_duration, good_duration

    def test_regex_performance(self, regex, iterations=5):
        """
        Test the performance of a regex.
        """
        # Remove a '/' at the beginning and end of the regex
        if regex[0] == '/' and regex[-1] == '/':
            regex = regex[1:-1]
        try:
            # Compile the regex first for better performance
            pattern = re.compile(regex)
        except re.error as e:
            logging.error("Regex error: %s", e)
            return 0

        # Record the start time
        start_time = time.time()

        # Apply the regex to the test string for the given number of iterations
        for _ in range(iterations):
            re.findall(pattern, self.test_string)

        # Record the end time
        end_time = time.time()

        # Calculate the total duration
        duration = end_time - start_time

        return duration
