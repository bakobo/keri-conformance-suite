"""Coded generator errors, per Bakobo's error-code standard: the obstacle, then whether retrying
could help. ``scripts/regenerate`` prints the coded message and exits 3 for any of them."""

# A scenario (or the clause registry) that does not describe a buildable case.
E_SCENARIO = "e.input.format.kcs-scenario.f"
# A scenario or registry file that is not valid JSON.
E_SCENARIO_JSON = "e.input.format.kcs-scenario-json.f"
# A scenario or registry file larger than the generator will read.
E_SCENARIO_SIZE = "e.input.range.kcs-scenario-size.f"
# A case id that is not a CESR-NNNN id, refused before it is used to build a path.
E_CASE_ID = "e.input.format.kcs-case-id.f"
# The code tables could not be read from the pinned, hash-verified specification text. The text
# is fixed, so this is the generator's own fault.
E_SPEC_TABLE = "e.self.unknown.kcs-spec-table.f"


class GeneratorError(Exception):
    def __init__(self, message: str, code: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message  # without the code, for a caller that re-wraps it


class ScenarioError(GeneratorError):
    def __init__(self, message: str, code: str = E_SCENARIO):
        super().__init__(message, code)
