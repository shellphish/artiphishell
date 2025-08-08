#!/usr/bin/env python3
import logging
import yaml

from .testers import Tester4C, Tester4Java
from shellphish_crs_utils.models.testguy import TestGuyMetaData

class TestGuy:
    def __init__(self, **kwargs):
        # Store here all the stuff we got passed by the command line
        # see (testguy/run.py)
        self.kwargs = kwargs

        # define testers map for different languages
        self.testers_map = {
            'c': Tester4C,
            'c++': Tester4C,
            'java': Tester4Java,
            'jvm': Tester4Java
        }

        # Read project name and language from project_metadata
        with open(self.kwargs['project_metadata_path'], 'r') as f:
            self.project_metadata = yaml.safe_load(f)

        self.project_name = self.project_metadata['shellphish_project_name']
        self.language = self.project_metadata['language']

        logging.info(f"🤡 Project Name: {self.project_name}")
        logging.info(f"🤡 Project Language: {self.language}")

    def start(self) -> TestGuyMetaData:
        test_result = TestGuyMetaData()
        
        # Initialize the tester
        if self.language in self.testers_map:
            tester = self.testers_map[self.language](**self.kwargs)
            test_result = tester.run()
        else:
            logging.error(f"🤡 Error: Language {self.language} not supported!!")
        
        return test_result
