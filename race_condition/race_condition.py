from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification


class RaceCondition(AbstractDetector):
    """
    Detect function named approve
    """

    ARGUMENT = "approve"  # slither will launch the detector with slither.py --mydetector
    HELP = "Function named approve (detector example)"
    IMPACT = DetectorClassification.MEDIUM
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://cwe.mitre.org/data/definitions/362.html"
    WIKI_TITLE = "Race Condition example"
    WIKI_DESCRIPTION = "Plugin example"
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."
    SET = 0

    def _detect(self):
        results = []
        
        for contract in self.slither.contracts_derived:
            
            for f in contract.functions:
                if "approve" in f.name:
                    
                    for fn in contract.functions:
                        if "increaseAllowance" in fn.name or 'decreaseAllowance' in fn.name:
                        # Info to be printed
                            info = ["Positive Race Condition possible in ", f, " Give allowance through increaseAllowance or decreaseAllowance function present. \n"]
                            self.SET = 1
                            res = self.generate_result(info)

                            results.append(res)
                        else:
                            self.SET=0
                    if self.SET == 0:
                        info = ["Positive Race condition possible in ", f, " No increaseAllowance or decreaseAllowance function are present. Give allowance through increaseAllowance or decreaseAllowance function. \n"]
                        print("info ------ ", info)   
                        res = self.generate_result(info)
                        print("res ---------- ", res)
                        results.append(res)


        return results