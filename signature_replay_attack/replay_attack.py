import re
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

class ReplayAttack(AbstractDetector):
    """
    Detect signature replay attack
    """

    ARGUMENT = "replay_attack"  # slither will launch the detector with slither.py --replay_attack
    HELP = "Signature Replay Attack"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://swcregistry.io/docs/SWC-121"
    WIKI_TITLE = "Signature Replay Attack"
    WIKI_DESCRIPTION = "Plugin example"
    WIKI_EXPLOIT_SCENARIO = ".."
    WIKI_RECOMMENDATION = ".."

    possible = False
    notPossible = False
    safe = False

    def _detect(self):
        results = []
        
        for contract in self.contracts:
            
            
            for function in contract.functions:
                
                for n in function.nodes:

                    domain = re.search("EIP712Domain", str(n))
                    if domain:
                        # print("EIP712Domain_Separator Found", domain)
                        verifier = re.search("address[(]this[)]", str(n))
                        # print("done", verifier)
                        if verifier:
                            # print("safe in verifying")
                            self.safe = True
                    
                    x = re.search("ecrecover", str(n))
                    if x:
                        for m in function.nodes:
                            
                            y = re.search("[+][+]", str(m))
                            
                            if y:
                                self.possible = True
                                effectedFunction = function
                                break

                            else:
                                self.notPossible = True
                                effectedFunction = function
                    
                    if self.possible:
                        break
                
                if self.possible:
                    break
        
        
        if self.possible and self.safe:
            # print("NO REPLAY ATTACK")
            info = ["Signature Replay Not Attack possible in  ", effectedFunction, " Found nonces or any unique identifier which changes after every single use of signature. \n"]
            res = self.generate_result(info)
            results.append(res)
        elif self.possible and not self.safe :
            # print("REPLAY ATTACK POSSIBLE")
            info = ["Signature Replay Attack possible in  ", effectedFunction, " Include address of current smart contract in domain separator so that signatue is valid for current smart contract address only. Nonces or any unique identifier found. \n"]
            res = self.generate_result(info)
            results.append(res)
        elif self.notPossible:
            info = ["Signature Replay Attack possible in  ", effectedFunction, " No nonces or any unique identifier found which changes after every single use of signature. \n"]
            res = self.generate_result(info)
            results.append(res)

        return results

        
